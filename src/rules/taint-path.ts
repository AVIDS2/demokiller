import type { Finding } from "../types.js";
import type { TaintPath } from "../taint-analysis.js";

export function taintPathFindings(taintPaths: TaintPath[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const tp of taintPaths) {
    // Only report paths to dangerous sinks (code-exec, sql, command)
    if (tp.sink.kind !== "code-exec" && tp.sink.kind !== "sql" && tp.sink.kind !== "command") continue;

    const key = `${tp.source.file}:${tp.source.line}:${tp.sink.file}:${tp.sink.line}`;
    if (seen.has(key)) continue;
    seen.add(key);

    // Downgrade severity if sanitizer detected between source and sink
    const severity = tp.sanitized ? "medium" : (tp.sink.severity as "blocker" | "high" | "medium");
    const confidence = tp.sanitized ? "low" : "high";

    findings.push({
      ruleId: "DK-TAINT-001",
      title: tp.sanitized
        ? `User input flows to ${tp.sink.kind} operation (sanitizer detected — verify effectiveness)`
        : `User input flows to ${tp.sink.kind} operation without sanitization`,
      severity,
      confidence,
      entryPoint: tp.source.file,
      capability: `Taint path: ${tp.risk}`,
      asset: "system integrity",
      missingControls: ["taintSanitization"],
      consequence: tp.sanitized
        ? `User-controlled data reaches ${tp.sink.kind} through the call chain. A sanitizer was detected between source and sink — verify it actually prevents the attack.`
        : `User-controlled data reaches ${tp.sink.kind} through the call chain. This enables injection attacks that pattern matching alone cannot detect.`,
      acceptanceCriteria: [
        "User input is validated before reaching dangerous operations.",
        "Dangerous operations use parameterized/safe APIs.",
        "Input is sanitized at the boundary, not at each sink.",
      ],
      evidence: [{
        id: "taint-path",
        detector: "call-graph-analysis",
        location: { path: tp.source.file, line: tp.source.line },
        entryPoint: tp.source.file,
        capability: tp.risk,
        asset: "system integrity",
        controls: tp.sanitized ? ["sanitizer-detected"] : [],
        signals: tp.path,
      }],
    });
  }

  return findings;
}
