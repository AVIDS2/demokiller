import { describe, expect, it } from "vitest";
import { analyzeFindings } from "../src/rules/index.js";

describe("golden rule validation", () => {
  const RULES = [
    { ruleId: "DK-XSS-001", vulnerable: "fixtures/xss-vulnerable", hardened: "fixtures/xss-hardened" },
    { ruleId: "DK-CSRF-001", vulnerable: "fixtures/csrf-vulnerable", hardened: "fixtures/csrf-hardened" },
    { ruleId: "DK-REDIRECT-001", vulnerable: "fixtures/redirect-vulnerable", hardened: "fixtures/redirect-hardened" },
    { ruleId: "DK-RATE-001", vulnerable: "fixtures/ratelimit-vulnerable", hardened: "fixtures/ratelimit-hardened" },
    { ruleId: "DK-GO-001", vulnerable: "fixtures/go-vulnerable", hardened: "fixtures/go-hardened" },
    { ruleId: "DK-GO-002", vulnerable: "fixtures/go-vulnerable", hardened: "fixtures/go-hardened" },
    { ruleId: "DK-RS-001", vulnerable: "fixtures/rust-vulnerable", hardened: "fixtures/rust-hardened" },
    { ruleId: "DK-JAVA-001", vulnerable: "fixtures/java-vulnerable", hardened: "fixtures/java-hardened" },
    { ruleId: "DK-JAVA-003", vulnerable: "fixtures/java-vulnerable", hardened: "fixtures/java-hardened" },
  ];

  for (const { ruleId, vulnerable, hardened } of RULES) {
    it(`${ruleId} fires on vulnerable fixture`, { timeout: 30000 }, async () => {
      const { findings } = await analyzeFindings(vulnerable);
      const ruleFindings = findings.filter(f => f.ruleId === ruleId);
      expect(ruleFindings.length).toBeGreaterThan(0);
    });

    it(`${ruleId} does NOT fire on hardened fixture`, { timeout: 30000 }, async () => {
      const { findings } = await analyzeFindings(hardened);
      const ruleFindings = findings.filter(f => f.ruleId === ruleId);
      expect(ruleFindings).toEqual([]);
    });
  }
});
