import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

export function healthCheckRule(inventory: ProjectInventory): Finding[] {
  if (inventory.apiRoutes.length === 0) return [];
  if (inventory.stack === "unknown") return [];
  return [{
    ruleId: "DK-OPS-002", title: "No health check endpoint detected", severity: "medium", confidence: "low",
    missingControls: ["healthCheck"],
    consequence: "Without a health check endpoint (/health, /healthz), load balancers and orchestrators cannot determine if the service is alive.",
    acceptanceCriteria: ["A /health or /healthz endpoint returns 200 when healthy.", "Health check verifies critical dependencies (database, APIs).", "Kubernetes/Docker healthcheck probes are configured."],
    evidence: [{ id: "project-scan", detector: "inventory", location: { path: "." }, controls: [], signals: ["no health check found"] }],
  }];
}
