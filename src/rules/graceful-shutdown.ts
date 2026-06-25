import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

export function gracefulShutdownRule(inventory: ProjectInventory): Finding[] {
  const serverStacks = ["express", "fastify", "nextjs", "gin", "echo", "fiber", "actix", "axum", "spring-boot", "ktor", "laravel", "rails", "aspnet"];
  if (!serverStacks.includes(inventory.stack)) return [];
  if (inventory.apiRoutes.length === 0) return [];

  return [{
    ruleId: "DK-OPS-001",
    title: "No graceful shutdown handling detected",
    severity: "medium",
    confidence: "low",
    missingControls: ["gracefulShutdown"],
    consequence: "In-flight requests are dropped on deployment or restart. Users see connection errors. Background jobs are interrupted mid-execution.",
    acceptanceCriteria: [
      "SIGTERM/SIGINT handlers are registered to drain connections.",
      "In-flight requests complete before process exits.",
      "Background jobs are checkpointed or retried.",
    ],
    evidence: [{ id: "project-scan", detector: "inventory", location: { path: "." }, controls: [], signals: ["no graceful shutdown pattern detected"] }],
  }];
}
