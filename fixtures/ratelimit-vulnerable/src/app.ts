import express from "express";

const app = express();
app.use(express.json());

// Multiple routes with no rate limiting — DK-RATE-001 requires 3+ routes
app.post("/api/login", (req, res) => {
  res.json({ token: "fake-jwt" });
});

app.post("/api/register", (req, res) => {
  res.json({ userId: "new-user" });
});

app.post("/api/forgot-password", (req, res) => {
  res.json({ sent: true });
});

app.get("/api/users", (req, res) => {
  res.json({ users: [] });
});

app.post("/api/comments", (req, res) => {
  res.json({ id: "comment-1" });
});

app.listen(3000);
