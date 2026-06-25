import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function piiExposureRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("piiExposure")) return [];
  return [{
    ruleId: "DK-DATA-002", title: "API response may expose personally identifiable information (PII)", severity: "blocker", confidence: "medium", entryPoint: route.path,
    capability: "Returns unredacted PII in API response", asset: "user data privacy", missingControls: ["piiRedaction"],
    consequence: "Exposing PII (email, phone, SSN, credit card, address) in API responses violates GDPR/CCPA and enables identity theft.",
    acceptanceCriteria: ["PII fields are excluded or redacted from API responses.", "Response DTO/ViewModel strips sensitive fields before serialization.", "PII is only returned with explicit access control."],
    evidence: [{ id: "route-source", detector: "source-inspector", location: { path: route.path, line: route.line }, entryPoint: route.path, capability: "piiExposure", asset: "user data privacy", controls: route.controls, signals: route.capabilities }],
  }];
}
