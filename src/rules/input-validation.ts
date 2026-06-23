import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function inputValidationRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("consumesRequestBody")) return [];
  if (route.controls.includes("inputValidation")) return [];

  return [
    {
      ruleId: "DK-INPUT-001",
      title: "API route consumes request body without input validation",
      severity: "blocker",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Consumes unvalidated request body",
      asset: "application integrity",
      missingControls: ["inputValidation"],
      consequence:
        "Unexpected, malformed, or malicious input can reach business logic, causing crashes, data corruption, or injection.",
      acceptanceCriteria: [
        "Request body is validated against a schema (e.g. zod, yup, joi) before use.",
        "Validation errors return a clear 400 response instead of reaching business logic.",
        "Only expected fields are accepted; extra fields are stripped or rejected.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "consumesRequestBody",
          asset: "application integrity",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
