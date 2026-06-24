package main

import (
	"fmt"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/openai/openai-go"
	"github.com/stripe/stripe-go"
	"gorm.io/gorm"
)

func main() {
	r := gin.Default()

	r.POST("/api/chat", func(c *gin.Context) {
		var body struct {
			Message string `json:"message"`
		}
		c.ShouldBindJSON(&body)

		client := openai.NewClient(os.Getenv("OPENAI_API_KEY"))
		completion, _ := client.ChatCompletion(openai.ChatRequest{
			Model:    "gpt-4o-mini",
			Messages: []openai.Message{{Role: "user", Content: body.Message}},
		})

		c.JSON(http.StatusOK, gin.H{"text": completion.Choices[0].Message.Content})
	})

	r.DELETE("/api/admin/users", func(c *gin.Context) {
		var body struct {
			UserID string `json:"userId"`
		}
		c.ShouldBindJSON(&body)

		db.Delete(&User{}, body.UserID)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	r.POST("/api/stripe/webhook", func(c *gin.Context) {
		var event map[string]interface{}
		c.ShouldBindJSON(&event)

		if event["type"] == "checkout.session.completed" {
			fmt.Println("paid", event["data"].(map[string]interface{})["object"].(map[string]interface{})["id"])
		}

		c.JSON(http.StatusOK, gin.H{"received": true})
	})

	r.Run(":8080")
}
