import Stripe from "stripe";
import { Router } from "express";

const router = Router();
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

router.post("/api/stripe/webhook", async (req, res) => {
  const event = req.body;
  if (event.type === "checkout.session.completed") {
    console.log("paid", event.data.object.id);
  }
  res.json({ received: true });
});

export default router;
