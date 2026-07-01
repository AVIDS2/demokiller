import express from "express";

const app = express();
app.use(express.json());

// XSS: user input rendered unescaped via res.send with req.body directly
app.post("/api/comment", (req, res) => {
  // DK-XSS-001 trigger: res.send(req.body...) without escaping
  res.send(req.body.comment);
});

// XSS: res.send with req.query directly
app.get("/api/search", (req, res) => {
  // DK-XSS-001 trigger: res.send(req.query...) without escaping
  res.send(req.query.q);
});

// XSS: res.write with req.params
app.get("/api/profile/:id", (req, res) => {
  // DK-XSS-001 trigger: res.write(req.params...) without escaping
  res.write(req.params.id);
  res.end();
});

app.listen(3000);
