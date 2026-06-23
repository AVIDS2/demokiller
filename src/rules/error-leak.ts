import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function errorLeakRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("consumesRequestBody")) return [];
  if (route.controls.includes("errorHandling")) return [];

  return [
    {
      ruleId: "DK-ERR-001",
      title: "API route lacks error handling and may leak internals to clients",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Consumes request input without error boundary",
      asset: "application security",
      missingControls: ["errorHandling"],
      consequence:
        "An unhandled exception can expose stack traces, database errors, or internal paths to the client, aiding attackers.",
      acceptanceCriteria: [
        "Route handler is wrapped in try-catch or uses a framework-level error boundary.",
        "Caught errors return a generic error response (e.g. 500 with safe message).",
        "Internal details are logged server-side, not returned to the client.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "consumesRequestBody",
          asset: "application security",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
