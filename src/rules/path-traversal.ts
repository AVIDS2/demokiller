import type { Finding } from "../types.js";
import type { RouteSourceEvidence } from "../source-inspector.js";

export function pathTraversalRule(route: RouteSourceEvidence): Finding[] {
  if (!route.controls.includes("pathTraversalRisk")) return [];

  return [
    {
      ruleId: "DK-PATH-001",
      title: "File system access uses user-controlled path without sanitization",
      severity: "high",
      confidence: "medium",
      entryPoint: route.path,
      capability: "Reads files using user-supplied path",
      asset: "file system and application data",
      missingControls: ["pathSanitization"],
      consequence:
        "An attacker can use path traversal sequences (../) to read arbitrary files on the server including source code, configuration, and credentials.",
      acceptanceCriteria: [
        "User-supplied paths are resolved and checked against an allowed directory.",
        "Path traversal sequences (../) are stripped or rejected.",
        "File access is restricted to a designated public directory.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: route.path, line: route.line },
          entryPoint: route.path,
          capability: "pathTraversalRisk",
          asset: "file system and application data",
          controls: route.controls,
          signals: route.capabilities,
        },
      ],
    },
  ];
}
