// Hardened Gin API — production-quality security controls.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	stripe "github.com/stripe/stripe-go/v78"
	"github.com/stripe/stripe-go/v78/webhook"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// ─── Models ─────────────────────────────────────────────────────────

type User struct {
	ID             string `gorm:"primaryKey;type:uuid;default:gen_random_uuid()"`
	Email          string `gorm:"uniqueIndex;not null"`
	HashedPassword string `gorm:"not null"`
	Role           string `gorm:"default:user;not null"`
	CreatedAt      time.Time
}

type UsageRecord struct {
	ID        uint   `gorm:"primaryKey;autoIncrement"`
	UserID    string `gorm:"index;not null"`
	Type      string `gorm:"not null"`
	Tokens    int
	CreatedAt time.Time
}

type WebhookEvent struct {
	EventID     string `gorm:"primaryKey"`
	Type        string `gorm:"not null"`
	ProcessedAt time.Time
}

// ─── Globals initialized outside handlers (connection reuse) ────────

var (
	db            *gorm.DB
	jwtSecret     []byte
	whSecret      string
	processedMu   sync.Mutex
	processedEvts = make(map[string]struct{}) // in-memory idempotency cache
)

// ─── Auth middleware (JWT verification) ─────────────────────────────

type Claims struct {
	UserID string `json:"sub"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func requireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
			return
		}
		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenStr, claims, func(t *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})
		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		c.Set("userID", claims.UserID)
		c.Set("role", claims.Role)
		c.Next()
	}
}

func requireAdmin() gin.HandlerFunc {
	return func(c *gin.Context) {
		role, _ := c.Get("role")
		if role != "admin" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Admin access required"})
			return
		}
		c.Next()
	}
}

// ─── Input validation structs ───────────────────────────────────────

type ChatRequest struct {
	Message string `json:"message" binding:"required,min=1,max=4000"`
}

type DeleteUserRequest struct {
	UserID string `json:"userId" binding:"required,uuid"`
}

// ─── CORS middleware (restricted origins) ───────────────────────────

func corsMiddleware() gin.HandlerFunc {
	allowed := map[string]bool{
		"https://app.example.com":   true,
		"https://admin.example.com": true,
	}
	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if allowed[origin] {
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
			c.Header("Access-Control-Allow-Credentials", "true")
		}
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

// ─── Rate limiter (sliding window, per-IP) ─────────────────────────

func rateLimiter(maxRequests int, window time.Duration) gin.HandlerFunc {
	type entry struct {
		count    int
		resetAt  time.Time
	}
	var (
		mu      sync.Mutex
		clients = make(map[string]*entry)
	)
	go func() {
		for {
			time.Sleep(window)
			mu.Lock()
			for k, v := range clients {
				if time.Now().After(v.resetAt) {
					delete(clients, k)
				}
			}
			mu.Unlock()
		}
	}()
	return func(c *gin.Context) {
		ip := c.ClientIP()
		mu.Lock()
		e, ok := clients[ip]
		now := time.Now()
		if !ok || now.After(e.resetAt) {
			clients[ip] = &entry{count: 1, resetAt: now.Add(window)}
			mu.Unlock()
			c.Next()
			return
		}
		e.count++
		if e.count > maxRequests {
			mu.Unlock()
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{"error": "Too many requests"})
			return
		}
		mu.Unlock()
		c.Next()
	}
}

// ─── Handlers ───────────────────────────────────────────────────────

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().UTC().Format(time.RFC3339)})
}

func chatHandler(c *gin.Context) {
	var req ChatRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input", "details": err.Error()})
		return
	}

	userID, _ := c.Get("userID")

	// Quota check via parameterized GORM query
	var count int64
	cutoff := time.Now().AddDate(0, 0, -30)
	db.Model(&UsageRecord{}).
		Where("user_id = ? AND created_at >= ?", userID, cutoff).
		Count(&count)

	if count >= 1000 {
		c.JSON(http.StatusTooManyRequests, gin.H{"error": "Monthly quota exceeded"})
		return
	}

	// In production this calls OpenAI; stub for fixture
	responseText := "Hardened response for: " + req.Message

	// Record usage via parameterized GORM
	db.Create(&UsageRecord{
		UserID: userID.(string),
		Type:   "chat",
		Tokens: len(responseText),
	})

	c.JSON(http.StatusOK, gin.H{"text": responseText})
}

func deleteUserHandler(c *gin.Context) {
	var req DeleteUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input", "details": err.Error()})
		return
	}

	adminID, _ := c.Get("userID")
	log.Printf("audit: admin=%s action=delete_user target=%s", adminID, req.UserID)

	// Parameterized GORM delete (no string concatenation)
	result := db.Where("id = ?", req.UserID).Delete(&User{})
	if result.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func stripeWebhookHandler(c *gin.Context) {
	payload, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Cannot read payload"})
		return
	}

	sigHeader := c.GetHeader("Stripe-Signature")
	if sigHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Missing stripe-signature header"})
		return
	}

	event, err := webhook.ConstructEvent(payload, sigHeader, whSecret)
	if err != nil {
		log.Printf("webhook signature verification failed: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid signature"})
		return
	}

	// Idempotency: in-memory + DB check (parameterized)
	processedMu.Lock()
	if _, seen := processedEvts[event.ID]; seen {
		processedMu.Unlock()
		c.JSON(http.StatusOK, gin.H{"received": true, "duplicate": true})
		return
	}
	processedMu.Unlock()

	var existing WebhookEvent
	if db.Where("event_id = ?", event.ID).First(&existing).RowsAffected > 0 {
		c.JSON(http.StatusOK, gin.H{"received": true, "duplicate": true})
		return
	}

	if event.Type == "checkout.session.completed" {
		db.Create(&WebhookEvent{EventID: event.ID, Type: string(event.Type)})
		processedMu.Lock()
		processedEvts[event.ID] = struct{}{}
		processedMu.Unlock()
		log.Printf("webhook processed: id=%s type=%s", event.ID, event.Type)
	}

	c.JSON(http.StatusOK, gin.H{"received": true})
}

// ─── HTTPS enforcement middleware ───────────────────────────────────

func httpsEnforcement() gin.HandlerFunc {
	return func(c *gin.Context) {
		if os.Getenv("GIN_MODE") == "release" {
			if c.GetHeader("X-Forwarded-Proto") != "https" {
				target := "https://" + c.Request.Host + c.Request.URL.RequestURI()
				c.Redirect(http.StatusMovedPermanently, target)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}

// ─── Error handler (no stack traces to client) ─────────────────────

func errorHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
		if len(c.Errors) > 0 {
			log.Printf("error: %v", c.Errors.Last())
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Internal server error"})
		}
	}
}

// ─── Main ───────────────────────────────────────────────────────────

func main() {
	var err error
	jwtSecret = []byte(os.Getenv("JWT_SECRET"))
	whSecret = os.Getenv("STRIPE_WEBHOOK_SECRET")

	dsn := os.Getenv("DATABASE_URL")
	if dsn == "" {
		dsn = "postgres://localhost:5432/hardened?sslmode=require"
	}
	db, err = gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}
	db.AutoMigrate(&User{}, &UsageRecord{}, &WebhookEvent{})

	r := gin.New()
	r.Use(gin.Logger())
	r.Use(errorHandler())
	r.Use(httpsEnforcement())
	r.Use(corsMiddleware())
	r.Use(rateLimiter(100, 15*time.Minute))

	r.GET("/health", healthHandler)

	api := r.Group("/api")
	{
		ai := api.Group("")
		ai.Use(rateLimiter(10, time.Minute))
		ai.Use(requireAuth())
		ai.POST("/chat", chatHandler)

		admin := api.Group("/admin")
		admin.Use(requireAuth(), requireAdmin())
		admin.DELETE("/users", deleteUserHandler)
	}

	r.POST("/api/stripe/webhook", stripeWebhookHandler)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      r,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("server starting on %s", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server error: %v", err)
	}
}
