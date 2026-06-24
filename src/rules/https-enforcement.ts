import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function httpsEnforcementRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("consumesRequestBody")) return [];
  if (route.controls.includes("httpsEnforcement")) return [];

  return [
    {
      ruleId: "DK-HTTPS-001",
      title: "Route does not enforce HTTPS or HSTS",
      severity: "high",
      confidence: "low",
      entryPoint: route.path,
      capability: "Accepts HTTP requests without HTTPS redirect or HSTS",
      asset: "transport security",
      missingControls: ["httpsEnforcement"],
      consequence:
        "Data transmitted over HTTP can be intercepted, modified, or replayed by network attackers. Session tokens and credentials are exposed in transit.",
      acceptanceCriteria: [
        "HTTP requests are redirected to HTTPS (301/302).",
        "Strict-Transport-Security header is set with appropriate max-age.",
        "All cookies use the Secure flag.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "noHttpsEnforcement",
          asset: "transport security",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
