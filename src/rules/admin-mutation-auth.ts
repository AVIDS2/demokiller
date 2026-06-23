import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function adminMutationAuthRule(route: RouteSourceEvidence): Finding[] {
  if (!route.path.toLowerCase().includes("admin")) return [];
  if (!route.capabilities.includes("mutatesDatabase")) return [];

  const missingControls = ["auth", "authorization"].filter(
    (control) => !route.controls.includes(control),
  );

  if (missingControls.length === 0) return [];

  return [
    {
      ruleId: "DK-AUTH-001",
      title: "Admin data mutation route lacks a verified access boundary",
      severity: "blocker",
      confidence: "high",
      entryPoint: route.path,
      capability: "Mutates user data",
      asset: "user data",
      missingControls,
      consequence:
        "A user or script may trigger privileged data changes without a verified admin boundary.",
      acceptanceCriteria: [
        "Route requires a valid authenticated session.",
        "Route verifies an admin role or explicit permission.",
        "Unauthorized requests return 401 or 403 before data mutation.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "mutatesDatabase",
          asset: "user data",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
