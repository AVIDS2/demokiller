import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function insecureDeserializationRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("insecureDeserialization")) return [];

  return [
    {
      ruleId: "DK-INSEC-001",
      title: "Route uses unsafe deserialization or evaluates user-controlled code",
      severity: "blocker",
      confidence: "high",
      entryPoint: route.path,
      capability: "Deserializes untrusted data or evaluates user input as code",
      asset: "host system and application integrity",
      missingControls: ["safeSerialization"],
      consequence:
        "Unsafe deserialization (pickle, yaml.load) or code evaluation (eval, exec) with user input allows remote code execution on the server.",
      acceptanceCriteria: [
        "Use safe deserialization libraries (e.g. yaml.safe_load, JSON.parse).",
        "Never evaluate user input with eval/exec/Function constructors.",
        "Input is deserialized using type-safe, schema-validated methods.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "insecureDeserialization",
          asset: "host system and application integrity",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
