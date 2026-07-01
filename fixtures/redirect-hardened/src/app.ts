import express from "express";

const app = express();

// redirect_whitelist: allowed redirect targets
const redirect_whitelist = new Set(["/", "/dashboard", "/profile", "/settings"]);

function validateRedirect(url: string): boolean {
  if (redirect_whitelist.has(url)) return true;
  if (url.startsWith("/") && !url.startsWith("//")) return true;
  return false;
}

app.get("/login", (req, res) => {
  const next = String(req.query.next ?? "/");
  if (!validateRedirect(next)) {
    return res.status(400).json({ error: "Invalid redirect URL" });
  }
  res.redirect(next);
});

app.get("/logout", (req, res) => {
  const returnTo = String(req.query.returnTo ?? "/");
  if (!validateRedirect(returnTo)) {
    return res.status(400).json({ error: "Invalid redirect URL" });
  }
  res.redirect(returnTo);
});

app.listen(3000);
