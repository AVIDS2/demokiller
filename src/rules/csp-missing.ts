import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

const WEB_FACING = new Set(["web-app", "api-gateway", "static-site", "cms", "browser-extension"]);

export function cspMissingRule(route: RouteSourceEvidence): Finding[] {
  if (!WEB_FACING.has(route.projectKind || "unknown")) return [];
  if (!route.capabilities.includes("consumesRequestBody")) return [];
  if (route.controls.includes("securityHeaders")) return [];

  return [
    {
      ruleId: "DK-CSP-001",
      title: "API responses lack security headers (CSP, X-Frame-Options, X-Content-Type-Options)",
      severity: "medium",
      confidence: "low",
      entryPoint: route.path,
      capability: "Returns API responses without security headers",
      asset: "client-side security",
      missingControls: ["securityHeaders"],
      consequence:
        "Without security headers, the API responses can be embedded in iframes, have MIME types sniffed, or allow inline script injection.",
      acceptanceCriteria: [
        "Content-Security-Policy header is set with appropriate directives.",
        "X-Frame-Options is set to DENY or SAMEORIGIN.",
        "X-Content-Type-Options is set to nosniff.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "missingSecurityHeaders",
          asset: "client-side security",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
