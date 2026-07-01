import { describe, it } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { analyzeFindings } from "../src/rules/index.js";

const SELF_ROOT = path.resolve(import.meta.dirname, "..");

describe("self-scan audit", () => {
  it("outputs all findings", { timeout: 60000 }, async () => {
    const { findings } = await analyzeFindings(SELF_ROOT);
    const summary: Record<string, { ruleId: string; title: string; severity: string; files: string[] }[]> = {
      blocker: [], high: [], medium: [], advisory: []
    };
    for (const f of findings) {
      // Filter out test file evidence — only count findings on source code
      const srcFiles = [...new Set(f.evidence.map(e => e.location?.path || "unknown"))].filter(p => !p.startsWith("tests/") && !p.includes("/tests/"));
      if (srcFiles.length === 0) continue;
      const sev = f.severity as keyof typeof summary;
      if (!summary[sev]) summary[sev] = [];
      summary[sev].push({
        ruleId: f.ruleId,
        title: f.title,
        severity: f.severity,
        files: srcFiles
      });
    }
    const outPath = path.join(SELF_ROOT, "demokiller", "self-scan-audit.json");
    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    fs.writeFileSync(outPath, JSON.stringify(summary, null, 2));
    console.log(`Findings written to ${outPath}`);
    console.log(`Blockers: ${summary.blocker.length}, Highs: ${summary.high.length}, Mediums: ${summary.medium.length}, Advisory: ${summary.advisory.length}`);
  });
});
