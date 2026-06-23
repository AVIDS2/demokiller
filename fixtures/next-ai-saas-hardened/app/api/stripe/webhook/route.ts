import Stripe from "stripe";

const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(request: Request) {
  try {
    const sig = request.headers.get("stripe-signature");
    if (!sig) return new Response("Missing signature", { status: 400 });

    const rawBody = await request.text();
    const event = stripe.webhooks.constructEvent(
      rawBody,
      sig,
      process.env.STRIPE_WEBHOOK_SECRET!,
    );

    if (event.type === "checkout.session.completed") {
      // idempotent: check if already processed
      const existing = await (globalThis as any).prisma?.webhookEvent?.findUnique({
        where: { eventId: event.id },
      });
      if (existing) return Response.json({ received: true, duplicate: true });
    }

    return Response.json({ received: true });
  } catch (error) {
    return Response.json({ error: "Webhook processing failed" }, { status: 400 });
  }
}
