import express from "express";
import createDOMPurify from "dompurify";
import { JSDOM } from "jsdom";

const app = express();
app.use(express.json());

const window = new JSDOM("").window;
const DOMPurify = createDOMPurify(window);

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

app.post("/api/comment", (req, res) => {
  const { comment } = req.body;
  const sanitized = DOMPurify.sanitize(comment);
  res.send(`<div class="comment">${sanitized}</div>`);
});

app.get("/api/search", (req, res) => {
  const query = escapeHtml(String(req.query.q ?? ""));
  res.send(`<h1>Search results for: ${query}</h1>`);
});

app.get("/api/profile", (req, res) => {
  const bio = escapeHtml(String(req.query.bio ?? ""));
  res.write(`<div>${bio}</div>`);
  res.end();
});

app.listen(3000);
