import { describe, expect, it } from "vitest";
import { toSarif } from "../src/sarif.js";
import type { AnalysisReport } from "../src/types.js";

const singleFindingReport: AnalysisReport = {
  verdict: "Launch Blocked",
  supportedScope: ["nextjs"],
  findings: [
    {
      ruleId: "DK-SEC-001",
      title: "Paid AI capability is exposed without production abuse controls",
      severity: "blocker",
      confidence: "high",
      entryPoint: "app/api/chat/route.ts",
      capability: "Calls OpenAI chat completion",
      asset: "paid AI API quota",
      missingControls: ["auth", "quota", "rateLimit"],
      consequence: "A public script can repeatedly trigger paid AI calls.",
      acceptanceCriteria: [
        "Requests require authentication.",
        "Rate limiting is enforced.",
      ],
      evidence: [
        {
          id: "route-source",
          detector: "source-inspector",
          location: { path: "app/api/chat/route.ts", line: 5 },
          controls: [],
          signals: ["callsOpenAI"],
        },
      ],
    },
  ],
  hardeningPlan: {
    summary: "Harden before launch.",
    phases: [],
    recheckCommand: "demokiller inspect . --markdown",
  },
  generatedAt: "2026-06-26T00:00:00.000Z",
};

const multiFindingReport: AnalysisReport = {
  verdict: "Launch Blocked",
  supportedScope: ["nextjs"],
  findings: [
    singleFindingReport.findings[0],
    {
      ruleId: "DK-SEC-002",
      title: "No rate limiting on public API",
      severity: "high",
      confidence: "medium",
      missingControls: ["rateLimit"],
      consequence: "API can be abused at scale.",
      acceptanceCriteria: ["Rate limiting is enforced."],
      evidence: [
        {
          id: "api-route",
          detector: "source-inspector",
          location: { path: "app/api/data/route.ts", line: 10 },
          controls: [],
          signals: ["noRateLimit"],
        },
      ],
    },
    {
      ruleId: "DK-SEC-001",
      title: "Paid AI capability is exposed without production abuse controls",
      severity: "blocker",
      confidence: "high",
      entryPoint: "app/api/chat/route.ts",
      capability: "Calls OpenAI chat completion",
      asset: "paid AI API quota",
      missingControls: ["auth", "quota", "rateLimit"],
      consequence: "A public script can repeatedly trigger paid AI calls.",
      acceptanceCriteria: [
        "Requests require authentication.",
        "Rate limiting is enforced.",
      ],
      evidence: [
        {
          id: "route-source-2",
          detector: "source-inspector",
          location: { path: "app/api/chat/route.ts", line: 12 },
          controls: [],
          signals: ["callsOpenAI"],
        },
      ],
    },
  ],
  hardeningPlan: {
    summary: "Harden before launch.",
    phases: [],
    recheckCommand: "demokiller inspect . --markdown",
  },
  generatedAt: "2026-06-26T00:00:00.000Z",
};

describe("SARIF output", () => {
  it("produces valid SARIF 2.1.0 structure", () => {
    const sarif = toSarif(singleFindingReport) as any;

    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toContain("sarif-schema-2.1.0.json");
    expect(sarif.runs).toHaveLength(1);

    const run = sarif.runs[0];
    expect(run.tool.driver.name).toBe("demo-killer");
    expect(typeof run.tool.driver.version).toBe("string");
    expect(run.tool.driver.informationUri).toBeTruthy();
  });

  it("maps blocker severity to error level", () => {
    const sarif = toSarif(singleFindingReport) as any;
    const rule = sarif.runs[0].tool.driver.rules[0];
    const result = sarif.runs[0].results[0];

    expect(rule.defaultConfiguration.level).toBe("error");
    expect(result.level).toBe("error");
  });

  it("maps all severity levels correctly", () => {
    const sevReport: AnalysisReport = {
      ...singleFindingReport,
      findings: ["blocker", "high", "medium", "advisory"].map(
        (sev, i) => ({
          ...singleFindingReport.findings[0],
          ruleId: `DK-TEST-${i}`,
          severity: sev as any,
        }),
      ),
    };
    const sarif = toSarif(sevReport) as any;
    const levels = sarif.runs[0].results.map((r: any) => r.level);

    expect(levels).toEqual(["error", "warning", "note", "none"]);
  });

  it("includes all findings as results", () => {
    const sarif = toSarif(multiFindingReport) as any;
    const results = sarif.runs[0].results;

    expect(results).toHaveLength(multiFindingReport.findings.length);
  });

  it("each result references a rule in the driver", () => {
    const sarif = toSarif(multiFindingReport) as any;
    const ruleIds = new Set(
      sarif.runs[0].tool.driver.rules.map((r: any) => r.id),
    );

    for (const result of sarif.runs[0].results) {
      expect(ruleIds.has(result.ruleId)).toBe(true);
    }
  });

  it("deduplicates rules even when findings share a ruleId", () => {
    const sarif = toSarif(multiFindingReport) as any;
    const ruleIds = sarif.runs[0].tool.driver.rules.map((r: any) => r.id);
    const unique = new Set(ruleIds);

    expect(ruleIds.length).toBe(unique.size);
    expect(ruleIds).toContain("DK-SEC-001");
    expect(ruleIds).toContain("DK-SEC-002");
  });

  it("SARIF output is valid JSON", () => {
    const sarif = toSarif(singleFindingReport);
    const json = JSON.stringify(sarif);
    const parsed = JSON.parse(json);

    expect(parsed).toEqual(sarif);
  });

  it("result locations reference evidence path and line", () => {
    const sarif = toSarif(singleFindingReport) as any;
    const result = sarif.runs[0].results[0];
    const physical = result.locations[0].physicalLocation;

    expect(physical.artifactLocation.uri).toBe("app/api/chat/route.ts");
    expect(physical.region.startLine).toBe(5);
  });

  it("rules include acceptance criteria in help text", () => {
    const sarif = toSarif(singleFindingReport) as any;
    const rule = sarif.runs[0].tool.driver.rules[0];

    expect(rule.help.text).toContain("Requests require authentication.");
    expect(rule.help.text).toContain("Rate limiting is enforced.");
  });

  it("rules include confidence as a property", () => {
    const sarif = toSarif(singleFindingReport) as any;
    const rule = sarif.runs[0].tool.driver.rules[0];

    expect(rule.properties.confidence).toBe("high");
  });
});
