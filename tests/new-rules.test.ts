import { describe, expect, it } from "vitest";
import path from "node:path";
import { analyzeFindings } from "../src/rules/index.js";

const SELF_ROOT = path.resolve(import.meta.dirname, "..");

describe("round 2 rules integration", () => {
  it("runs full analysis without throwing", { timeout: 30000 }, async () => {
    const { findings, inventory } = await analyzeFindings(SELF_ROOT);
    expect(inventory).toBeDefined();
    expect(Array.isArray(findings)).toBe(true);
  });

  it("has no blocker-level false positives from self-scan", { timeout: 30000 }, async () => {
    const { findings } = await analyzeFindings(SELF_ROOT);
    const blockers = findings.filter(f => f.severity === "blocker").filter(f => {
      const srcFiles = [...new Set(f.evidence.map(e => e.location?.path || "unknown"))]
        .filter(p => !p.startsWith("tests/") && !p.includes("/tests/"));
      return srcFiles.length > 0;
    });
    expect(blockers.length).toBe(0);
  });

  it("produces findings with valid structure", { timeout: 60000 }, async () => {
    const { findings } = await analyzeFindings(SELF_ROOT);
    for (const f of findings) {
      expect(f.ruleId).toBeTruthy();
      expect(f.title).toBeTruthy();
      expect(["blocker", "high", "medium", "advisory"]).toContain(f.severity);
      expect(["high", "medium", "low"]).toContain(f.confidence);
      expect(Array.isArray(f.missingControls)).toBe(true);
      expect(f.consequence).toBeTruthy();
      expect(Array.isArray(f.acceptanceCriteria)).toBe(true);
      expect(Array.isArray(f.evidence)).toBe(true);
    }
  });

  it("categorizes findings by rule prefix", { timeout: 30000 }, async () => {
    const { findings } = await analyzeFindings(SELF_ROOT);
    const prefixes = new Set(findings.map(f => f.ruleId.split("-").slice(0, 2).join("-")));
    expect(prefixes.size).toBeGreaterThan(1);
  });
});
