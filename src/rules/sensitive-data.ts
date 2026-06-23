import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function sensitiveDataRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("readsDatabase")) return [];
  if (!route.capabilities.includes("consumesRequestBody")) return [];
  if (route.controls.includes("auth")) return [];

  return [
    {
      ruleId: "DK-DATA-001",
      title: "Database read result may be returned without field filtering",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Reads database and returns results to unauthenticated caller",
      asset: "user data",
      missingControls: ["auth"],
      consequence:
        "Database records (including password hashes, tokens, or internal fields) may be returned directly to unauthenticated callers.",
      acceptanceCriteria: [
        "Route requires authentication before returning database results.",
        "Prisma queries use `select` or `omit` to exclude sensitive fields.",
        "Returned objects are mapped to a safe response shape.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "readsDatabase",
          asset: "user data",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
