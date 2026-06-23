import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function debugLeakRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("debugStatements")) return [];

  return [
    {
      ruleId: "DK-DEBUG-001",
      title: "Production route contains debug or development-only statements",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Emits debug output in production code path",
      asset: "operational hygiene",
      missingControls: ["debugGuard"],
      consequence:
        "Console statements in production routes can leak internal state to logs, degrade performance, and signal unfinished development to consumers.",
      acceptanceCriteria: [
        "Remove console.log / console.debug / console.warn from production routes.",
        "Use a structured logger with configurable log levels instead.",
        "If debug output is needed, guard it behind a NODE_ENV or DEBUG flag.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "debugStatements",
          asset: "operational hygiene",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
