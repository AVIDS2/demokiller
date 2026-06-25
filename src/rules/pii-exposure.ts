import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function piiExposureRule(route: RouteSourceEvidence): Finding[] {
  if (!route.capabilities.includes("piiExposure")) return [];

  return [{
    ruleId: "DK-DATA-002",
    title: "Route may expose PII fields (email, phone, address) without filtering",
    severity: "high",
    confidence: "low",
    entryPoint: route.path,
    capability: "Database result with PII fields returned to client",
    asset: "user privacy and compliance",
    missingControls: ["piiFiltering"],
    consequence: "Personal data (email, phone, address, SSN) is returned in API responses without field-level filtering. This violates GDPR/CCPA and increases breach impact.",
    acceptanceCriteria: [
      "API responses use a DTO/serializer that excludes sensitive fields.",
      "PII fields are masked or omitted in list endpoints.",
      "Access to PII requires explicit authorization.",
    ],
    evidence: [{ id: "route-source", detector: "source-inspector", location: { path: route.path, line: route.line }, entryPoint: route.path, capability: "piiExposure", asset: "user privacy", controls: route.controls, signals: route.capabilities }],
  }];
}
