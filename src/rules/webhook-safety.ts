import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function webhookSafetyRule(route: RouteSourceEvidence): Finding[] {
  if (!route.path.includes("webhook")) return [];
  if (!route.capabilities.includes("handlesPaymentProvider")) return [];

  const missingControls = ["signatureVerification", "idempotency"].filter(
    (control) => !route.controls.includes(control),
  );

  if (missingControls.length === 0) return [];

  return [
    {
      ruleId: "DK-WEBHOOK-001",
      title: "Payment webhook lacks production safety controls",
      severity: "blocker",
      confidence: "high",
      entryPoint: route.path,
      capability: "Handles payment provider webhook",
      asset: "payment state",
      missingControls,
      consequence:
        "Forged or repeated webhook requests can corrupt payment state or grant access incorrectly.",
      acceptanceCriteria: [
        "Provider signature is verified against a webhook secret.",
        "Processed event ids are stored or checked for idempotency.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "handlesPaymentProvider",
          asset: "payment state",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
