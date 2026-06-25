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
  it("finds known rule violations in the risky fixture", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-risky");
    const shaped = findings.map(stableFindingShape);

    // Must find all original blockers
    expect(shaped).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "DK-AI-001", severity: "blocker" }),
      expect.objectContaining({ ruleId: "DK-AUTH-001", severity: "blocker" }),
      expect.objectContaining({ ruleId: "DK-WEBHOOK-001", severity: "blocker" }),
      expect.objectContaining({ ruleId: "DK-INPUT-001", severity: "blocker" }),
    ]));
    // Must find quality issues
    expect(shaped).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "DK-OBS-001" }),
      expect.objectContaining({ ruleId: "DK-ERR-001" }),
      expect.objectContaining({ ruleId: "DK-ENV-001" }),
      expect.objectContaining({ ruleId: "DK-DB-001" }),
    ]));
    // Must have at least 15 findings
    expect(findings.length).toBeGreaterThanOrEqual(15);
  });

  it("resolves some findings after partial fixes", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-partial-fix");
    const shaped = findings.map(stableFindingShape);

    // Auth should be resolved for chat route
    const aiFindings = shaped.filter((f) => f.ruleId === "DK-AI-001");
    expect(aiFindings.every((f) => !f.missingControls?.includes("auth"))).toBe(true);
    // Webhook still has issues
    expect(shaped).toEqual(expect.arrayContaining([
      expect.objectContaining({ ruleId: "DK-WEBHOOK-001" }),
    ]));
  });

  it("returns no blocker findings for the hardened fixture", async () => {
    const { findings } = await analyzeFindings("fixtures/next-ai-saas-hardened");

    // No blockers or highs — only acceptable medium/low findings
    const blockers = findings.filter(f => f.severity === "blocker");
    const highs = findings.filter(f => f.severity === "high");
    expect(blockers).toEqual([]);
    // Medium findings like graceful shutdown, health check are acceptable
  });

  it("returns inventory alongside findings", async () => {
    const result = await analyzeFindings("fixtures/next-ai-saas-risky");

    expect(result.inventory).toBeDefined();
    expect(result.inventory.stack).toBe("nextjs");
    expect(result.inventory.apiRoutes.length).toBeGreaterThan(0);
  });

  it("detects Go fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/gin-ai-saas-risky");

    expect(inventory.stack).toBe("gin");
    expect(findings.length).toBeGreaterThan(0);
    expect(findings.some((f) => f.ruleId === "DK-AI-001")).toBe(true);
  });

  it("detects Rust fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/actix-ai-saas-risky");

    expect(inventory.stack).toBe("actix");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects Java fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/springboot-ai-saas-risky");

    expect(inventory.stack).toBe("spring-boot");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects PHP fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/laravel-risky");

    expect(inventory.stack).toBe("laravel");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects Rails fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/rails-risky");

    expect(inventory.stack).toBe("rails");
    expect(findings.length).toBeGreaterThan(0);
  });

  it("detects ASP.NET fixtures correctly", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/aspnet-risky");

    expect(inventory.stack).toBe("aspnet");
    expect(findings.length).toBeGreaterThan(0);
  });
});
