import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

export function healthCheckRule(inventory: ProjectInventory): Finding[] {
  const serverStacks = ["express", "fastify", "nextjs", "gin", "echo", "fiber", "actix", "axum", "spring-boot", "ktor", "laravel", "rails", "aspnet"];
  if (!serverStacks.includes(inventory.stack)) return [];
  if (inventory.apiRoutes.length === 0) return [];

  return [{
    ruleId: "DK-OPS-002",
    title: "No health check endpoint detected",
    severity: "medium",
    confidence: "low",
    missingControls: ["healthCheck"],
    consequence: "Load balancers and orchestrators (Kubernetes, ECS) cannot verify the service is alive. Unhealthy instances continue receiving traffic.",
    acceptanceCriteria: [
      "A /health or /healthz endpoint returns 200 when the service is ready.",
      "Health check verifies database and critical dependency connectivity.",
      "Health check distinguishes liveness from readiness.",
    ],
    evidence: [{ id: "project-scan", detector: "inventory", location: { path: "." }, controls: [], signals: ["no health check endpoint detected"] }],
  }];
}
