import { describe, expect, it } from "vitest";
import { analyzeFindings } from "../src/rules/index.js";

/**
 * False-positive regression tests.
 * Hardened fixtures must NOT produce blockers from security-critical rules
 * that have high-confidence detectors (AI-001, AUTH-001, WEBHOOK-001).
 * Pattern-based rules (BIZ-*, PAY-*, INPUT-*) still have some residual false positives
 * on hardened fixtures — tracked in AUDIT.md §3.4.
 */
describe("false-positive regression", () => {
  it("hardened-web-app has zero AI/auth/webhook blockers", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/hardened-web-app");
    const ruleIds = findings.filter(f => f.severity === "blocker").map(f => f.ruleId);
    expect(ruleIds).not.toContain("DK-AI-001");
    expect(ruleIds).not.toContain("DK-AUTH-001");
    expect(ruleIds).not.toContain("DK-WEBHOOK-001");
    expect(["web-app", "web-api", "payment-system"]).toContain(inventory.projectKind);
  });

  it("hardened-python-api has zero AI/auth blockers", async () => {
    const { findings } = await analyzeFindings("fixtures/hardened-python-api");
    const ruleIds = findings.filter(f => f.severity === "blocker").map(f => f.ruleId);
    expect(ruleIds).not.toContain("DK-AI-001");
    expect(ruleIds).not.toContain("DK-AUTH-001");
    // Python deep rules must not fire on hardened code
    const pyFindings = findings.filter(f => f.ruleId.startsWith("DK-PY-"));
    expect(pyFindings).toEqual([]);
  });

  it("hardened-go-api has zero AI/auth/webhook blockers", async () => {
    const { findings } = await analyzeFindings("fixtures/hardened-go-api");
    const ruleIds = findings.filter(f => f.severity === "blocker").map(f => f.ruleId);
    expect(ruleIds).not.toContain("DK-AI-001");
    expect(ruleIds).not.toContain("DK-AUTH-001");
    expect(ruleIds).not.toContain("DK-WEBHOOK-001");
  });

  it("hardened-serverless has zero blockers and zero highs", async () => {
    const { findings } = await analyzeFindings("fixtures/hardened-serverless");
    const blockers = findings.filter(f => f.severity === "blocker");
    const highs = findings.filter(f => f.severity === "high");
    expect(blockers).toEqual([]);
    expect(highs).toEqual([]);
  });

  it("Python deep rules don't fire on hardened-python-api", async () => {
    const { findings } = await analyzeFindings("fixtures/hardened-python-api");
    const pyFindings = findings.filter(f => f.ruleId.startsWith("DK-PY-"));
    expect(pyFindings).toEqual([]);
  });

  it("CLI-specific web rules don't fire on CLI projects", async () => {
    const { findings, inventory } = await analyzeFindings("fixtures/cli-tool-risky");
    expect(inventory.projectKind).toBe("cli-tool");
    const ruleIds = findings.map(f => f.ruleId);
    expect(ruleIds).not.toContain("DK-CSP-001");
    expect(ruleIds).not.toContain("DK-HTTPS-001");
    expect(ruleIds).not.toContain("DK-CORS-001");
    expect(ruleIds).not.toContain("DK-WEBHOOK-001");
  });

  it("MQ worker rules don't fire on web projects and vice versa", async () => {
    const { findings: mqFindings, inventory: mqInv } = await analyzeFindings("fixtures/mq-worker-risky");
    expect(mqInv.projectKind).toBe("mq-worker");
    const mqRuleIds = mqFindings.map(f => f.ruleId);
    expect(mqRuleIds).not.toContain("DK-CSP-001");
    expect(mqRuleIds).not.toContain("DK-HTTPS-001");
    expect(mqRuleIds.some(id => id.startsWith("DK-MQ-"))).toBe(true);
  });
});
