import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function nPlusOneRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("nPlusOneQuery")) return [];

  return [{
    ruleId: "DK-PERF-001",
    title: "Potential N+1 query: database call inside a loop",
    severity: "high",
    confidence: "medium",
    entryPoint: route.path,
    capability: "Database query executed inside iteration",
    asset: "API latency and database load",
    missingControls: ["batchQuery"],
    consequence: "Each iteration triggers a separate database query. With 100 items, this creates 100 queries instead of 1, causing API latency to scale linearly with data size.",
    acceptanceCriteria: [
      "Use batch queries (findMany, IN clause, DataLoader) instead of per-item queries.",
      "Eager loading or join queries are used for related data.",
      "Query count is bounded regardless of input size.",
    ],
    evidence: [{ id: "perf-scan", detector: "source-inspector", location: { path: route.path, line: route.line }, entryPoint: route.path, capability: "nPlusOneQuery", asset: "API latency", controls: route.controls, signals: route.capabilities }],
  }];
}
