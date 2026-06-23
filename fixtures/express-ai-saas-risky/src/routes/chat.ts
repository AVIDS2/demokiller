import OpenAI from "openai";
import { Router } from "express";

const router = Router();
const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

router.post("/api/chat", async (req, res) => {
  const { message } = req.body;
  const completion = await client.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: message }],
  });
  res.json({ text: completion.choices[0]?.message?.content });
});

export default router;
