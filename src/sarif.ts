import type { AnalysisReport, Finding, Severity } from "./types.js";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const __here = path.dirname(fileURLToPath(import.meta.url));
// Works for both src/sarif.ts (tests) and dist/src/sarif.js (CLI/npm)
const pkgPath = ["../package.json", "../../package.json"]
  .map(rel => path.resolve(__here, rel))
  .find(p => { try { readFileSync(p); return true; } catch { return false; } });
const pkg = JSON.parse(readFileSync(pkgPath!, "utf8"));

function mapSeverity(severity: Severity): string {
  switch (severity) {
    case "blocker":
      return "error";
    case "high":
      return "warning";
    case "medium":
      return "note";
    case "advisory":
      return "none";
    default:
      return "none";
  }
}

export function toSarif(report: AnalysisReport): object {
  const seenRules = new Map<string, Finding>();

  for (const finding of report.findings) {
    if (!seenRules.has(finding.ruleId)) {
      seenRules.set(finding.ruleId, finding);
    }
  }

  const rules = Array.from(seenRules.values()).map((finding) => ({
    id: finding.ruleId,
    shortDescription: { text: finding.title },
    fullDescription: { text: finding.consequence },
    defaultConfiguration: { level: mapSeverity(finding.severity) },
    help: { text: finding.acceptanceCriteria.join("\n") },
    properties: { confidence: finding.confidence },
  }));

  const results = report.findings.map((finding) => {
    const firstEvidence = finding.evidence[0];
    const locationPath = firstEvidence?.location.path ?? "unknown";
    const startLine = firstEvidence?.location.line ?? 1;

    return {
      ruleId: finding.ruleId,
      level: mapSeverity(finding.severity),
      message: { text: finding.title },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: locationPath },
            region: { startLine },
          },
        },
      ],
    };
  });

  return {
    $schema:
      "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "demo-killer",
            version: pkg.version,
            informationUri: "https://github.com/AVIDS2/demokiller",
            rules,
          },
        },
        results,
      },
    ],
  };
}
