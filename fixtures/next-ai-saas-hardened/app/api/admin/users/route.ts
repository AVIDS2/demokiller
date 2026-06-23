import { z } from "zod";
import { auth } from "@/auth";
import { prisma } from "../../../../lib/db";

const DeleteSchema = z.object({
  userId: z.string().uuid(),
});

function auditLog(action: string, data: Record<string, unknown>) {
  // structured audit logger — not console.log
}

export async function DELETE(request: Request) {
  try {
    const session = await auth();
    if (!session?.user?.role || session.user.role !== "admin") {
      return new Response("Forbidden", { status: 403 });
    }

    const raw = await request.json();
    const { userId } = DeleteSchema.parse(raw);
    auditLog("admin.delete.user", { userId, adminId: session.user.id });
    await prisma.user.delete({ where: { id: userId } });
    return Response.json({ ok: true });
  } catch (error) {
    return Response.json({ error: "Internal server error" }, { status: 500 });
  }
}
