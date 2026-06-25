import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

export function gracefulShutdownRule(inventory: ProjectInventory): Finding[] {
  if (inventory.apiRoutes.length === 0) return [];
  if (inventory.stack === "unknown") return [];
  return [{
    ruleId: "DK-OPS-001", title: "No graceful shutdown handler detected", severity: "medium", confidence: "low",
    missingControls: ["gracefulShutdown"],
    consequence: "Without a graceful shutdown handler (SIGTERM/SIGINT), in-flight requests are dropped during deployment, causing partial writes and failed responses.",
    acceptanceCriteria: ["Server listens for SIGTERM/SIGINT and drains connections before exiting.", "Health check returns unhealthy during shutdown.", "Connection pools are closed after serving in-flight requests."],
    evidence: [{ id: "project-scan", detector: "inventory", location: { path: "." }, controls: [], signals: ["no graceful shutdown handler found"] }],
  }];
}
