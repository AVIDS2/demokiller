import express from "express";

const app = express();

// Open redirect: user-controlled URL passed directly to res.redirect
app.get("/login", (req, res) => {
  const next = req.query.next;
  // Vulnerable: no validation on redirect target
  res.redirect(req.query.next as string);
});

app.get("/logout", (req, res) => {
  // Another open redirect via req.body
  res.redirect(req.query.returnTo as string);
});

app.listen(3000);
