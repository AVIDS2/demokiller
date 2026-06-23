import { Router } from "express";
import { prisma } from "../lib/db";

const router = Router();

router.delete("/api/admin/users", async (req, res) => {
  const { userId } = req.body;
  await prisma.user.delete({ where: { id: userId } });
  res.json({ ok: true });
});

export default router;
