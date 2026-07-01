import express from "express";
import rateLimit from "express-rate-limit";

const app = express();
app.use(express.json());

// Global rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// Stricter limit for auth endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: "Too many attempts, please try again later",
});

app.post("/api/login", authLimiter, (req, res) => {
  res.json({ token: "fake-jwt" });
});

app.post("/api/register", authLimiter, (req, res) => {
  res.json({ userId: "new-user" });
});

app.post("/api/forgot-password", authLimiter, (req, res) => {
  res.json({ sent: true });
});

app.get("/api/users", (req, res) => {
  res.json({ users: [] });
});

app.post("/api/comments", (req, res) => {
  res.json({ id: "comment-1" });
});

app.listen(3000);
