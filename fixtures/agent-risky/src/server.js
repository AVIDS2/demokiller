const express = require("express");
const { Server } = require("@modelcontextprotocol/sdk/server/index.js");
const OpenAI = require("openai");

const app = express();
app.use(express.json());

// DK-AGENT-011: MCP server without auth
const mcpServer = new Server({ name: "risky-agent", version: "1.0.0" });

// DK-AGENT-006: No tool allowlist — any tool can be invoked
mcpServer.tool("execute", async (args) => {
  return { result: eval(args.code) };
});

// DK-AGENT-007: Prompt injection via tool inputs
app.post("/chat", async (req, res) => {
  const userInput = req.body.message;
  const client = new OpenAI();

  const response = await client.chat.completions.create({
    model: "gpt-4",
    messages: [
      { role: "system", content: `You are a helpful assistant. User said: ${userInput}` },
      { role: "user", content: userInput },
    ],
  });

  // DK-AGENT-008: Secret leak in response
  res.json({
    reply: response.choices[0].message.content,
    config: {
      apiKey: process.env.OPENAI_API_KEY,
      dbUrl: process.env.DATABASE_URL,
      secret: process.env.JWT_SECRET,
    },
  });
});

// DK-AGENT-009: Unbounded agent loop
async function runAgentLoop(task) {
  while (true) {
    const result = await processTask(task);
    if (result.done) break;
    task = result.next;
    // No iteration limit, no timeout
  }
}

// DK-AGENT-010: Unsafe filesystem tool
app.post("/read-file", (req, res) => {
  const filePath = req.body.path;
  const fs = require("fs");
  const content = fs.readFileSync(filePath, "utf8");
  res.json({ content });
});

app.post("/write-file", (req, res) => {
  const { path: filePath, content } = req.body;
  const fs = require("fs");
  fs.writeFileSync(filePath, content);
  res.json({ success: true });
});

app.listen(3000);
mcpServer.connect({ transport: "stdio" });
