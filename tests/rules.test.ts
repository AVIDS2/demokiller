import { readFile } from "node:fs/promises";
import { describe, expect, it } from "vitest";
import { analyzeFindings } from "../src/rules/index.js";

function stableFindingShape(finding: {
  ruleId: string;
  severity: string;
  entryPoint?: string;
  missingControls: string[];
  asset?: string;
}) {
  return {
    ruleId: finding.ruleId,
    severity: finding.severity,
    entryPoint: finding.entryPoint,
    missingControls: finding.missingControls,
    asset: finding.asset,
  };
}

describe("analyzeFindings", () => {
  it("matches golden findings for risky fixture", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-risky");
    const expected = JSON.parse(
      await readFile("fixtures/expected/next-ai-saas-risky.findings.json", "utf8"),
    );

    expect(findings.map(stableFindingShape)).toEqual(expected);
  });

  it("matches golden findings after partial fixes", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-partial-fix");
    const expected = JSON.parse(
      await readFile("fixtures/expected/next-ai-saas-partial-fix.findings.json", "utf8"),
    );

    expect(findings.map(stableFindingShape)).toEqual(expected);
  });

  it("returns no findings for the hardened fixture", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-hardened");

    expect(findings).toEqual([]);
  });

  it("returns inventory alongside findings", async () => {
    const result = await analyzeFindings("fixtures/next-ai-saas-risky");

    expect(result.inventory).toBeDefined();
    expect(result.inventory.stack).toBe("nextjs");
    expect(result.inventory.apiRoutes.length).toBeGreaterThan(0);
  });
});
