import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function nPlusOneRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("nPlusOneRisk")) return [];
  // Function-scoped detection (nPlusOneQuery) gives higher confidence
  const hasFunctionScoped = route.capabilities.includes("nPlusOneQuery");
  return [{
    ruleId: "DK-PERF-001", title: "Database query inside a loop — potential N+1 problem", severity: "high", confidence: hasFunctionScoped ? "high" : "medium", entryPoint: route.path,
    capability: "Iterates and queries database in each iteration", asset: "database performance", missingControls: ["batchedQueries"],
    consequence: "Each loop iteration executes a separate database query. With N items, this produces N+1 queries, causing significant latency.",
    acceptanceCriteria: ["Database queries are batched or use JOIN/IN clauses instead of per-item queries.", "ORM eager loading is configured for related data."],
    evidence: [{ id: "route-source", detector: "source-inspector", location: { path: route.path, line: route.line }, entryPoint: route.path, capability: "nPlusOneRisk", asset: "database performance", controls: route.controls, signals: route.capabilities }],
  }];
}
