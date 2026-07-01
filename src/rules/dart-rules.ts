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

export async function dartFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".dart"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-DART-001: Force unwrap with ! on nullable types
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line)) continue;
        // Match variable! patterns — identifier followed by ! but not != or !! (bang bang is different)
        const forceUnwrap = line.match(/\b([a-zA-Z_]\w*)\s*!(?!=)/g);
        if (forceUnwrap) {
          // Filter out keywords and non-nullable patterns
          const filtered = forceUnwrap.filter(m => {
            const name = m.replace(/\s*!$/, "").trim();
            return !/^(if|while|for|assert|return|await|yield|throw|new|const|final|var|late|is|as|in)$/.test(name);
          });
          if (filtered.length > 0) {
            matches.push(`line ${i + 1}: ${filtered.length} force unwrap(s) — ${filtered.map(f => f.trim()).join(", ").slice(0, 60)}`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-DART-001",
        title: "Force unwrap on nullable type: runtime crash risk",
        severity: "high",
        confidence: "medium",
        missingControls: ["nullSafety"],
        consequence: "Using the ! operator on a nullable type throws a runtime exception if the value is null. In production, this causes unhandled exceptions and crashes.",
        acceptanceCriteria: [
          "Use null-aware operators: ?. , ?? , ??= to handle null safely.",
          "Add explicit null checks before using ! on nullable values.",
          "Consider using type promotion with if (x != null) to avoid force unwrap.",
        ],
        evidence: evidence(hits, "dart-001"),
      });
    }
  }

  // DK-DART-002: Insecure HTTP usage
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      const httpUrls = content.match(/["']http:\/\/[^"'\s]+["']/g) ?? [];
      for (const url of httpUrls) {
        if (/localhost|127\.0\.0\.1|0\.0\.0\.0|::1/.test(url)) continue;
        matches.push(`insecure HTTP URL: ${url.slice(0, 60)}`);
      }
      // Check for HttpClient without HTTPS enforcement
      if (/HttpClient\b/.test(content) && !/https|certificate|ssl|tls|SecurityContext/i.test(content)) {
        matches.push("HttpClient configured without HTTPS/TLS enforcement");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-DART-002",
        title: "Insecure HTTP usage: plaintext communication",
        severity: "high",
        confidence: "high",
        missingControls: ["httpsEnforcement"],
        consequence: "Using HTTP instead of HTTPS transmits all data in plaintext, including credentials and tokens. This allows man-in-the-middle attacks to intercept and modify traffic.",
        acceptanceCriteria: [
          "Use HTTPS for all API endpoints and URLs.",
          "Configure HttpClient with certificate pinning for sensitive operations.",
          "Add an HTTP-to-HTTPS redirect policy for all network requests.",
        ],
        evidence: evidence(hits, "dart-002"),
      });
    }
  }

  // DK-DART-003: Missing input validation on form fields
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/TextFormField|TextEditingController|TextField\b/.test(content)) continue;
      // Check if any TextFormField lacks a validator
      const textFormFields = content.match(/TextFormField\s*\(/g) ?? [];
      const validators = content.match(/validator\s*:/g) ?? [];
      if (textFormFields.length > 0 && validators.length < textFormFields.length) {
        hits.set(file, [`${textFormFields.length - validators.length} TextFormField(s) without validator`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-DART-003",
        title: "Missing input validation on form fields",
        severity: "high",
        confidence: "medium",
        missingControls: ["formValidation"],
        consequence: "TextFormField widgets without validators accept any input, including empty strings, excessively long text, or malformed data. This leads to data integrity issues and potential injection attacks.",
        acceptanceCriteria: [
          "Add a validator callback to every TextFormField.",
          "Validate input format, length, and allowed characters.",
          "Show clear error messages for invalid input using the validator return value.",
        ],
        evidence: evidence(hits, "dart-003"),
      });
    }
  }

  // DK-DART-004: Hardcoded secrets/API keys
  {
    const hits = new Map<string, string[]>();
    const secretVarRe = /(?:const|final|var|static\s+(?:const|final)?)\s+\w*(?:key|secret|token|password|apikey|api_key|apiKey|credential|auth)\w*\s*=\s*['"]([^'"]{16,})['"]/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretVarRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme|YOUR_|REPLACE/i.test(val)) {
          matches.push(`high-entropy secret in variable (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check for generic high-entropy string literals assigned to secret-looking names
      const assignRe = /\w*(?:key|secret|token|password|apikey|api_key|credential)\w*\s*=\s*['"]([A-Za-z0-9+/=_\-]{20,})['"]/gi;
      for (const m of content.matchAll(assignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme|YOUR_|REPLACE/i.test(val)) {
          matches.push(`hardcoded secret assigned (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-DART-004",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code are trivially extracted from repositories, APKs, or IPA files. This leads to credential compromise and unauthorized access to APIs and services.",
        acceptanceCriteria: [
          "Load secrets from environment variables using --dart-define or flutter_dotenv.",
          "Use a secret manager or secure storage (flutter_secure_storage) for runtime secrets.",
          "Never commit secrets to source control — use .env and .gitignore.",
        ],
        evidence: evidence(hits, "dart-004"),
      });
    }
  }

  // DK-DART-005: Missing error handling in async/await
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line)) continue;
        if (!/\bawait\b/.test(line)) continue;
        // Check if inside a try block — look backwards for try {
        let inTry = false;
        for (let j = i - 1; j >= Math.max(0, i - 30); j--) {
          if (/\btry\s*\{/.test(lines[j])) { inTry = true; break; }
          if (/\bcatch\s*\(/.test(lines[j])) break;
        }
        // Also check if the enclosing function has try-catch
        if (!inTry) {
          // Check surrounding 15 lines for try-catch
          const ctx = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 15)).join("\n");
          if (/try\s*\{[\s\S]*?catch\s*\(/.test(ctx)) continue;
          matches.push(`line ${i + 1}: await without try-catch — ${line.trim().slice(0, 60)}`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size >  0) {
      findings.push({
        ruleId: "DK-DART-005",
        title: "Missing error handling in async/await code",
        severity: "high",
        confidence: "low",
        missingControls: ["asyncErrorHandling"],
        consequence: "Async/await calls without try-catch propagate unhandled exceptions that crash the app or leave it in an inconsistent state. Network errors, timeouts, and parse failures will go unhandled.",
        acceptanceCriteria: [
          "Wrap await calls in try-catch blocks to handle exceptions gracefully.",
          "Add specific catch clauses for network errors, timeouts, and format exceptions.",
          "Use .catchError() on Futures for non-await error handling.",
        ],
        evidence: evidence(hits, "dart-005"),
      });
    }
  }

  return findings;
}
