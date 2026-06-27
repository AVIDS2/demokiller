import { describe, expect, it, tmpDir } from "vitest";
import {
  loadBaseline,
  saveBaseline,
  diffFindings,
  buildFingerprint,
} from "../src/baseline.js";
import type { Finding } from "../src/types.js";
import fs from "node:fs/promises";
import path from "node:path";
import os from "node:os";

function makeFinding(ruleId: string, title: string, filePath = "src/app.ts"): Finding {
  return {
    ruleId,
    severity: "high",
    title,
    description: "test",
    evidence: [{ message: "test", location: { path: filePath, startLine: 1 } }],
    missingControls: [],
    entryPoint: "test",
  };
}

describe("baseline", () => {
  it("buildFingerprint is deterministic for the same input", () => {
    const fp1 = buildFingerprint("DK-AI-001", "src/app.ts", "AI gateway missing auth");
    const fp2 = buildFingerprint("DK-AI-001", "src/app.ts", "AI gateway missing auth");
    expect(fp1).toBe(fp2);
    expect(fp1).toHaveLength(16);
  });

  it("buildFingerprint differs for different inputs", () => {
    const fp1 = buildFingerprint("DK-AI-001", "src/app.ts", "title A");
    const fp2 = buildFingerprint("DK-AI-001", "src/app.ts", "title B");
    expect(fp1).not.toBe(fp2);
  });

  it("saveBaseline writes a valid JSON file", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dk-baseline-"));
    const filePath = path.join(dir, "baseline.json");
    const findings = [
      makeFinding("DK-AI-001", "AI gateway auth"),
      makeFinding("DK-AUTH-001", "Auth middleware"),
    ];
    await saveBaseline(findings, filePath);
    const content = await fs.readFile(filePath, "utf8");
    const parsed = JSON.parse(content);
    expect(parsed).toHaveLength(2);
    expect(parsed[0].ruleId).toBe("DK-AI-001");
    expect(parsed[0].fingerprint).toBeDefined();
    await fs.rm(dir, { recursive: true });
  });

  it("loadBaseline reads a previously saved baseline", async () => {
    const dir = await fs.mkdtemp(path.join(os.tmpdir(), "dk-baseline-"));
    const filePath = path.join(dir, "baseline.json");
    const findings = [makeFinding("DK-AI-001", "AI gateway auth")];
    await saveBaseline(findings, filePath);
    const loaded = await loadBaseline(filePath);
    expect(loaded).toHaveLength(1);
    expect(loaded[0].fingerprint).toBe(buildFingerprint("DK-AI-001", "src/app.ts", "AI gateway auth"));
    await fs.rm(dir, { recursive: true });
  });

  it("diffFindings identifies new, existing, and fixed findings", () => {
    const baseline = [
      { fingerprint: buildFingerprint("DK-AI-001", "src/app.ts", "finding A"), ruleId: "DK-AI-001" },
      { fingerprint: buildFingerprint("DK-AUTH-001", "src/app.ts", "finding B"), ruleId: "DK-AUTH-001" },
    ];
    const current = [
      makeFinding("DK-AI-001", "finding A"),       // exists in baseline
      makeFinding("DK-WEBHOOK-001", "finding C"),  // new
    ];
    const diff = diffFindings(current, baseline);
    expect(diff.existingFindings).toHaveLength(1);
    expect(diff.existingFindings[0].ruleId).toBe("DK-AI-001");
    expect(diff.newFindings).toHaveLength(1);
    expect(diff.newFindings[0].ruleId).toBe("DK-WEBHOOK-001");
    expect(diff.fixedFindings).toHaveLength(1);
    expect(diff.fixedFindings[0].ruleId).toBe("DK-AUTH-001");
  });

  it("diffFindings returns all as new when baseline is empty", () => {
    const current = [
      makeFinding("DK-AI-001", "finding A"),
      makeFinding("DK-AUTH-001", "finding B"),
    ];
    const diff = diffFindings(current, []);
    expect(diff.newFindings).toHaveLength(2);
    expect(diff.existingFindings).toHaveLength(0);
    expect(diff.fixedFindings).toHaveLength(0);
  });
});
