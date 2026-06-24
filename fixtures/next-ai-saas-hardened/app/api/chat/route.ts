import OpenAI from "openai";
import { z } from "zod";
import { auth } from "@/auth";
import { rateLimit } from "@/lib/rate-limit";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

const ChatSchema = z.object({
  message: z.string().min(1).max(4000),
});

const logger = {
  info: (msg: string, data?: unknown) => {
    if (process.env.NODE_ENV !== "production") {
      // structured logger placeholder
    }
  },
  error: (msg: string, data?: unknown) => {
    if (process.env.NODE_ENV !== "production") {
      // structured logger placeholder
    }
  },
};

const MONTHLY_QUOTA = 1000;

async function checkQuota(userId: string): Promise<boolean> {
  // quota check placeholder
  return true;
}

const securityHeaders = {
  "Content-Security-Policy": "default-src 'self'",
  "X-Frame-Options": "DENY",
  "X-Content-Type-Options": "nosniff",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};

export async function POST(request: Request) {
  try {
    if (process.env.NODE_ENV === "production" && request.headers.get("x-forwarded-proto") !== "https") {
      return Response.redirect(`https://${request.headers.get("host")}${request.url}`, 301);
    }

    const session = await auth();
    if (!session?.user?.id) return new Response("Unauthorized", { status: 401 });
    await rateLimit(session.user.id, "chat");

    const withinQuota = await checkQuota(session.user.id);
    if (!withinQuota) return new Response("Quota exceeded", { status: 429 });

    const raw = await request.json();
    const body = ChatSchema.parse(raw);

    const completion = await client.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: body.message }],
    });

    logger.info("chat completion", { userId: session.user.id });
    return Response.json({ text: completion.choices[0]?.message?.content });
  } catch (error) {
    logger.error("chat route error", { error: String(error) });
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
