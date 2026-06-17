import type { RouteSourceEvidence } from "../source-inspector.js";
import type { Finding } from "../types.js";

export function observabilityRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("mutatesDatabase")) return [];
  if (route.controls.includes("logging")) return [];

  return [
    {
      ruleId: "DK-OBS-001",
      title: "Critical mutation path lacks diagnostic logging",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Mutates production data",
      asset: "incident diagnosis",
      missingControls: ["logging"],
      consequence:
        "When this path fails in production, the team may not know what happened or how to recover quickly.",
      acceptanceCriteria: [
        "The mutation path emits structured logs or a traceable audit event.",
        "Failure cases preserve enough context for diagnosis.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "mutatesDatabase",
          asset: "incident diagnosis",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
