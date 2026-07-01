import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;
const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;
const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe|agent-mcp|security-hardening|error-handling|performance-rules|observability|deployment-rules|python-rules|environment-rules)/;
const ANALYSIS_INDICATORS_RE = /walkSourceFiles|walkPythonFiles|FUNC_PATTERNS|ROUTE_PATTERNS|extractFunctions|CallGraph|buildCallGraph|detectMcp|detectUnsafe|walkSourceFiles|codegraph/i;
const INFRA_RE = /src[/\\](?:rules|call-graph|python-call-graph|source-inspector|cli|inventory)[/\\.]|(?:vscode-extension)/;

function evidence(hits: Map<string, string[]>, ruleId: string) {
  return [...hits.entries()].map(([file, signals]) => ({
    id: `${ruleId}-${file}`,
    detector: "pattern-match",
    location: { path: file },
    controls: [],
    signals
  }));
}

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export async function scalaFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".scala", ".sc"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-SCALA-001: SQL injection with string interpolation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // sql"" with $ interpolation
      const sqlInterp = content.match(/sql\s*"[^"]*\$\{?[^}"]*\}?[^"]*"/g) ?? [];
      for (const m of sqlInterp) {
        matches.push(`SQL with string interpolation: ${m.trim().slice(0, 60)}`);
      }
      // s"SELECT ... $var" or s"INSERT ... ${var}"
      const sInterpSQL = content.match(/s\s*"(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s[^"]*\$\{?/gi) ?? [];
      for (const m of sInterpSQL) {
        matches.push(`SQL in s-interpolator: ${m.trim().slice(0, 60)}`);
      }
      // String concatenation with SQL keywords
      const sqlConcat = content.match(/(?:Query|execute|executeQuery|executeUpdate)\s*\([^)]*\+\s*/g) ?? [];
      for (const m of sqlConcat) {
        matches.push(`SQL with string concatenation: ${m.trim().slice(0, 60)}`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SCALA-001",
        title: "SQL injection via string interpolation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string interpolation (sql\"\" with $ or s\"\") allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data.",
        acceptanceCriteria: [
          "Use parameterized queries with ? placeholders and PreparedStatement.",
          "Use Slick, Doobie, or Quill for type-safe query construction.",
          "Never interpolate user input directly into SQL strings.",
        ],
        evidence: evidence(hits, "scala-001"),
      });
    }
  }

  // DK-SCALA-002: Missing timeout on Future
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/Future\s*\{/.test(content)) continue;
      // Check for timeout patterns
      if (/withTimeout|\.timeout|duration\.Duration|Await\.result|Await\.ready|after\s*\(/.test(content)) continue;
      hits.set(file, ["Future { ... } without timeout — may block indefinitely"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SCALA-002",
        title: "Missing timeout on Future execution",
        severity: "high",
        confidence: "medium",
        missingControls: ["futureTimeout"],
        consequence: "Futures without timeouts can block indefinitely on slow downstream services, exhausting thread pools and causing cascading failures across the application.",
        acceptanceCriteria: [
          "Use Akka pattern.after or Scala Futures timeout to bound Future execution.",
          "Configure timeouts at the dispatcher level for all async operations.",
          "Use Await.result with a finite Duration for blocking waits.",
        ],
        evidence: evidence(hits, "scala-002"),
      });
    }
  }

  // DK-SCALA-003: Hardcoded secrets
  {
    const hits = new Map<string, string[]>();
    const secretVarRe = /(?:val|var|lazy\s+val)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*(?::\s*\w+\s*)?=\s*"([^"]{16,})"/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretVarRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret in variable (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check for generic secret assignments
      const assignRe = /\w*(?:token|secret|password|apikey|api_key|credential)\w*\s*=\s*"([A-Za-z0-9+/=_\-]{20,})"/gi;
      for (const m of content.matchAll(assignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`hardcoded secret assigned (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SCALA-003",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code are trivially extracted from repositories or compiled artifacts. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables: sys.env.getOrElse(\"API_TOKEN\", \"\").",
          "Use a secret manager (Vault, AWS SSM, GCP Secret Manager).",
          "Never commit secrets to source control — use .env and .gitignore.",
        ],
        evidence: evidence(hits, "scala-003"),
      });
    }
  }

  // DK-SCALA-004: Unsafe deserialization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      if (/ObjectInputStream\b/.test(content)) {
        matches.push("ObjectInputStream used — Java native deserialization is unsafe");
      }
      if (/\.readObject\s*\(/.test(content)) {
        matches.push("readObject() called — vulnerable to deserialization attacks");
      }
      if (/pickle\.load|pickle\.loads/.test(content)) {
        matches.push("Scala pickle used — deserialization of untrusted data");
      }
      if (/fromJSON|fromJson.*\.as\[/.test(content) && /untrusted|input|request|body/i.test(content)) {
        matches.push("JSON deserialization from potentially untrusted input without validation");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SCALA-004",
        title: "Unsafe deserialization of untrusted data",
        severity: "high",
        confidence: "medium",
        missingControls: ["safeDeserialization"],
        consequence: "Java native deserialization (ObjectInputStream, readObject) is inherently unsafe and allows remote code execution via crafted payloads. An attacker can execute arbitrary code by sending a malicious serialized object.",
        acceptanceCriteria: [
          "Replace ObjectInputStream with safe alternatives (JSON, Protobuf, Avro).",
          "If deserialization is required, use look-ahead deserialization (ValidatingObjectInputStream).",
          "Use Play JSON or Circe with explicit type-safe reads instead of raw deserialization.",
        ],
        evidence: evidence(hits, "scala-004"),
      });
    }
  }

  // DK-SCALA-005: Missing input validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Check for controller/action patterns
      if (!/(?:Action|def\s+\w+.*Request|def\s+(?:get|post|put|delete|patch))\b/.test(content)) continue;
      // Check for validation
      if (/(?:validate|constraint|require|maxLen|minLen|pattern|nonEmpty|isDefined|isValid)/i.test(content)) continue;
      // Check if it's a route/handler file
      if (!/(?:controller|route|handler|endpoint)/i.test(file)) continue;
      hits.set(file, ["Controller action without input validation"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SCALA-005",
        title: "Missing input validation in controller actions",
        severity: "high",
        confidence: "low",
        missingControls: ["inputValidation"],
        consequence: "Controller actions that accept request data without validation are vulnerable to injection attacks, data corruption, and unexpected behavior from malformed input.",
        acceptanceCriteria: [
          "Validate all user input at the controller boundary.",
          "Use Play Framework form validation or custom constraints.",
          "Return 400 Bad Request for invalid input with descriptive error messages.",
        ],
        evidence: evidence(hits, "scala-005"),
      });
    }
  }

  return findings;
}
