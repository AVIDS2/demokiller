import type { Finding, Severity } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";
import * as fs from "node:fs";
import * as path from "node:path";

export type CustomSeverity = Severity | "low";

// Custom rule definition that users write
export interface CustomRuleDef {
  ruleId: string;
  title: string;
  severity: CustomSeverity;
  confidence: "high" | "medium" | "low";
  description?: string;
  consequence?: string;
  acceptanceCriteria?: string[];
  // Either provide regex patterns...
  patterns?: string[]; // regex strings to match against file contents
  fileGlobs?: string[]; // file extensions to scan (default: all source files)
  // ...or provide a JS function (advanced)
  detect?: string; // "(content, file) => string[]" — eval'd safely
}

export async function loadCustomRules(root: string): Promise<CustomRuleDef[]> {
  const pluginDir = path.join(root, ".demokiller", "plugins");
  if (!fs.existsSync(pluginDir)) return [];

  const rules: CustomRuleDef[] = [];
  const entries = fs.readdirSync(pluginDir).filter(f => f.endsWith(".json"));

  for (const entry of entries) {
    try {
      const content = fs.readFileSync(path.join(pluginDir, entry), "utf-8");
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed)) {
        rules.push(...parsed.filter(isValidRule));
      } else if (isValidRule(parsed)) {
        rules.push(parsed);
      }
    } catch { /* skip malformed files */ }
  }

  return rules;
}

function isValidRule(r: any): r is CustomRuleDef {
  return r && typeof r.ruleId === "string" && typeof r.title === "string"
    && ["blocker","high","medium","low","advisory"].includes(r.severity)
    && (Array.isArray(r.patterns) || typeof r.detect === "string");
}

export async function customFindings(root: string, _inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const rules = await loadCustomRules(root);
  if (rules.length === 0) return [];

  const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;

  for (const rule of rules) {
    const exts = rule.fileGlobs || [".ts",".tsx",".js",".jsx",".mjs",".cjs",".py",".go",".rs",".java",".kt",".cs",".rb",".php"];
    const files = await walkSourceFiles(root, exts);
    const hits = new Map<string, string[]>();

    // Compile patterns
    const regexes: RegExp[] = [];
    if (rule.patterns) {
      for (const p of rule.patterns) {
        try { regexes.push(new RegExp(p, "gi")); } catch { /* skip bad regex */ }
      }
    }

    // Optional detect function
    let detectFn: ((content: string, file: string) => string[]) | null = null;
    if (rule.detect) {
      try {
        // Safe eval: only allow simple function expressions
        detectFn = new Function("content", "file", `return (${rule.detect})(content, file)`) as any;
      } catch { /* skip bad detect function */ }
    }

    for (const file of files) {
      if (EXCLUDE_RE.test(file)) continue;
      const content = await readFileContent(root, file);
      const fileHits: string[] = [];

      for (const re of regexes) {
        re.lastIndex = 0;
        for (const m of content.matchAll(new RegExp(re.source, re.flags))) {
          fileHits.push(m[0].slice(0, 120));
        }
      }

      if (detectFn) {
        try {
          const customHits = detectFn(content, file);
          if (Array.isArray(customHits)) fileHits.push(...customHits);
        } catch { /* skip errors in user code */ }
      }

      if (fileHits.length > 0) hits.set(file, fileHits.slice(0, 10));
    }

    if (hits.size > 0) {
      findings.push({
        ruleId: rule.ruleId,
        title: rule.title,
        severity: rule.severity === "low" ? "advisory" : rule.severity as Severity,
        confidence: rule.confidence || "medium",
        missingControls: [],
        consequence: rule.consequence || "Custom rule violation detected.",
        acceptanceCriteria: rule.acceptanceCriteria || ["Fix the issues flagged by this custom rule."],
        evidence: [...hits.entries()].map(([file, signals]) => ({
          id: `${rule.ruleId}-${file}`,
          detector: "custom-rule",
          location: { path: file },
          controls: [],
          signals
        }))
      });
    }
  }

  return findings;
}
