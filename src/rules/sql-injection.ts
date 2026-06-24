import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function sqlInjectionRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("sqlInjectionRisk")) return [];

  return [
    {
      ruleId: "DK-SQLI-001",
      title: "SQL query constructed with string interpolation or concatenation",
      severity: "blocker",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Builds SQL queries from dynamic strings",
      asset: "database integrity",
      missingControls: ["parameterizedQueries"],
      consequence:
        "User-controlled input in SQL queries allows attackers to read, modify, or delete arbitrary data, bypass authentication, or execute system commands.",
      acceptanceCriteria: [
        "All SQL queries use parameterized statements or prepared queries.",
        "User input is never interpolated into SQL strings.",
        "ORM methods are used instead of raw SQL where possible.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "sqlInjectionRisk",
          asset: "database integrity",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
