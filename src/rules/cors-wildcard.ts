import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function corsWildcardRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("corsWildcard")) return [];

  return [
    {
      ruleId: "DK-CORS-001",
      title: "API route allows requests from any origin",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Accepts cross-origin requests from any domain",
      asset: "API surface",
      missingControls: ["corsRestriction"],
      consequence:
        "Any website or script can make authenticated or unauthenticated requests to this route, expanding the attack surface for CSRF, data exfiltration, and abuse.",
      acceptanceCriteria: [
        "Access-Control-Allow-Origin is restricted to known trusted domains.",
        "Credentials are not combined with wildcard origin.",
        "Preflight responses reflect the actual allowed origin.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "corsWildcard",
          asset: "API surface",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
