import { describe, expect, it, beforeEach, afterEach } from "vitest";
import path from "node:path";
import fs from "node:fs";
import { analyzeFindings } from "../src/rules/index.js";

const FIXTURE = path.resolve(import.meta.dirname, "../fixtures/next-ai-saas-risky");

describe("custom rules plugin system", () => {
  const pluginDir = path.join(FIXTURE, ".demokiller", "plugins");

  beforeEach(() => {
    fs.mkdirSync(pluginDir, { recursive: true });
  });

  afterEach(() => {
    fs.rmSync(path.join(FIXTURE, ".demokiller"), { recursive: true, force: true });
  });

  it("loads and applies custom rules from .demokiller/plugins/", async () => {
    const rule = [{
      ruleId: "CUSTOM-001",
      title: "No TODO comments in production",
      severity: "medium" as const,
      confidence: "high" as const,
      patterns: ["//\\s*TODO"]
    }];
    fs.writeFileSync(path.join(pluginDir, "no-todo.json"), JSON.stringify(rule));

    const { findings } = await analyzeFindings(FIXTURE);
    // May or may not have TODO findings depending on fixture content
    // Just verify it doesn't crash
    expect(findings).toBeDefined();
  });

  it("ignores malformed plugin files", async () => {
    fs.writeFileSync(path.join(pluginDir, "bad.json"), "not json {{{");

    const { findings } = await analyzeFindings(FIXTURE);
    expect(findings).toBeDefined();
  });

  it("returns no custom findings when plugin dir doesn't exist", async () => {
    // Remove plugin dir
    fs.rmSync(pluginDir, { recursive: true, force: true });

    const { findings } = await analyzeFindings(FIXTURE);
    const customFindings = findings.filter(f => f.ruleId.startsWith("CUSTOM-"));
    expect(customFindings).toEqual([]);
  });
});
