import express from "express";
import csurf from "csurf";

const app = express();
app.use(express.json());

// CSRF protection middleware applied globally
const csrfProtection = csurf({ cookie: true });
app.use(csrfProtection);

app.post("/api/transfer", (req, res) => {
  const { amount, toAccount } = req.body;
  // CSRF token validated by middleware
  res.json({ transferred: amount, to: toAccount });
});

app.put("/api/settings", (req, res) => {
  const { email, password } = req.body;
  res.json({ updated: true });
});

app.delete("/api/account", (req, res) => {
  res.json({ deleted: true });
});

// Endpoint to get CSRF token
app.get("/api/csrf-token", (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

app.listen(3000);
