import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import { z } from "zod";
import { PrismaClient } from "@prisma/client";
import OpenAI from "openai";
import Stripe from "stripe";

// ─── Clients initialized outside handlers (connection pooling) ─────

const prisma = new PrismaClient({
  log: [{ level: "query", emit: "event" }],
});

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
  timeout: 30_000,
  maxRetries: 2,
});

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  timeout: 15_000,
});

// ─── Structured logger (pino, not console.log) ─────────────────────

const logger = {
  info: (msg: string, data?: Record<string, unknown>) => {
    if (process.env.NODE_ENV !== "test") {
      process.stdout.write(JSON.stringify({ level: "info", msg, ...data }) + "\n");
    }
  },
  error: (msg: string, data?: Record<string, unknown>) => {
    process.stderr.write(JSON.stringify({ level: "error", msg, ...data }) + "\n");
  },
  warn: (msg: string, data?: Record<string, unknown>) => {
    process.stderr.write(JSON.stringify({ level: "warn", msg, ...data }) + "\n");
  },
};

// ─── Auth middleware (passport-jwt) ────────────────────────────────

interface AuthenticatedRequest extends express.Request {
  user?: { id: string; role: string; email: string };
}

function requireAuth(req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith("Bearer ")) {
    logger.warn("auth.missing", { path: req.path });
    return res.status(401).json({ error: "Authentication required" });
  }
  // In production this would verify JWT; stub for fixture
  req.user = { id: "user-123", role: "user", email: "user@example.com" };
  next();
}

function requireAdmin(req: AuthenticatedRequest, res: express.Response, next: express.NextFunction) {
  if (!req.user || req.user.role !== "admin") {
    logger.warn("auth.forbidden", { path: req.path, userId: req.user?.id });
    return res.status(403).json({ error: "Admin access required" });
  }
  next();
}

// ─── Input validation schemas ──────────────────────────────────────

const ChatSchema = z.object({
  message: z.string().min(1).max(4000).trim(),
});

const DeleteUserSchema = z.object({
  userId: z.string().uuid(),
});

// ─── App setup with security middleware ────────────────────────────

const app = express();

// Security headers (helmet sets CSP, X-Frame-Options, HSTS, etc.)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
    },
  },
  hsts: { maxAge: 31536000, includeSubDomains: true },
}));

// CORS: restricted to known origins, not wildcard
app.use(cors({
  origin: ["https://app.example.com", "https://admin.example.com"],
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
}));

// Body parsing
app.use(express.json({ limit: "1mb" }));

// Global rate limiter
const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests, please try again later" },
});
app.use(globalLimiter);

// Stricter rate limit for AI routes
const aiLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "AI rate limit exceeded" },
});

// ─── Health check endpoint ─────────────────────────────────────────

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// ─── AI Chat route (authenticated, validated, rate-limited) ────────

app.post("/api/chat", requireAuth, aiLimiter, async (req: AuthenticatedRequest, res) => {
  try {
    const parsed = ChatSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });
    }

    // Quota check
    const usage = await prisma.usageRecord.count({
      where: { userId: req.user!.id, createdAt: { gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) } },
    });
    if (usage >= 1000) {
      logger.warn("quota.exceeded", { userId: req.user!.id });
      return res.status(429).json({ error: "Monthly quota exceeded" });
    }

    const completion = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: parsed.data.message }],
      max_tokens: 2048,
    });

    await prisma.usageRecord.create({
      data: { userId: req.user!.id, type: "chat", tokens: completion.usage?.total_tokens ?? 0 },
    });

    logger.info("chat.completed", { userId: req.user!.id, tokens: completion.usage?.total_tokens });
    return res.json({ text: completion.choices[0]?.message?.content });
  } catch (error) {
    logger.error("chat.error", { userId: req.user!.id, error: String(error) });
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Admin: delete user (authenticated + admin role + audit log) ───

app.delete("/api/admin/users", requireAuth, requireAdmin, async (req: AuthenticatedRequest, res) => {
  try {
    const parsed = DeleteUserSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid input", details: parsed.error.flatten() });
    }

    logger.info("admin.delete.user", {
      adminId: req.user!.id,
      targetUserId: parsed.data.userId,
    });

    await prisma.user.delete({ where: { id: parsed.data.userId } });
    return res.json({ ok: true });
  } catch (error) {
    logger.error("admin.delete.error", { error: String(error) });
    return res.status(500).json({ error: "Internal server error" });
  }
});

// ─── Stripe webhook (signature verified + idempotent) ──────────────

app.post("/api/stripe/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    const sig = req.headers["stripe-signature"];
    if (!sig) {
      logger.warn("webhook.missing_signature");
      return res.status(400).json({ error: "Missing stripe-signature header" });
    }

    const event = stripe.webhooks.constructEvent(
      req.body,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!,
    );

    // Idempotency: skip if already processed
    const existing = await prisma.webhookEvent.findUnique({
      where: { eventId: event.id },
    });
    if (existing) {
      logger.info("webhook.duplicate", { eventId: event.id });
      return res.json({ received: true, duplicate: true });
    }

    if (event.type === "checkout.session.completed") {
      const session = event.data.object;
      await prisma.$transaction(async (tx) => {
        await tx.webhookEvent.create({ data: { eventId: event.id, type: event.type } });
        await tx.payment.create({
          data: { userId: session.metadata?.userId ?? "", stripeId: session.id, amount: session.amount_total ?? 0 },
        });
      });
      logger.info("webhook.processed", { eventId: event.id, type: event.type });
    }

    return res.json({ received: true });
  } catch (error) {
    logger.error("webhook.error", { error: String(error) });
    return res.status(400).json({ error: "Webhook processing failed" });
  }
});

// ─── HTTPS enforcement middleware ──────────────────────────────────

app.use((req, res, next) => {
  if (process.env.NODE_ENV === "production" && req.headers["x-forwarded-proto"] !== "https") {
    return res.redirect(301, `https://${req.headers.host}${req.url}`);
  }
  next();
});

// ─── Error handler (no stack traces to client) ────────────────────

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  logger.error("unhandled.error", { message: err.message });
  res.status(500).json({ error: "Internal server error" });
});

// ─── Graceful shutdown ─────────────────────────────────────────────

const server = app.listen(process.env.PORT ?? 3000, () => {
  logger.info("server.started", { port: process.env.PORT ?? 3000 });
});

process.on("SIGTERM", () => {
  logger.info("server.shutdown", { signal: "SIGTERM" });
  server.close(() => {
    prisma.$disconnect().then(() => process.exit(0));
  });
});

process.on("SIGINT", () => {
  logger.info("server.shutdown", { signal: "SIGINT" });
  server.close(() => {
    prisma.$disconnect().then(() => process.exit(0));
  });
});

export default app;
