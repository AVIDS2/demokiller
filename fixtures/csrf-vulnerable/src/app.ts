import express from "express";

const app = express();
app.use(express.json());

// State-changing POST with no token validation
app.post("/api/transfer", (req, res) => {
  const { amount, toAccount } = req.body;
  res.json({ transferred: amount, to: toAccount });
});

// State-changing PUT with no token validation
app.put("/api/settings", (req, res) => {
  const { email, password } = req.body;
  res.json({ updated: true });
});

// State-changing DELETE with no token validation
app.delete("/api/account", (req, res) => {
  res.json({ deleted: true });
});

app.listen(3000);
