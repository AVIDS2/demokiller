import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;

const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;

const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe)/;

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

export async function rubyFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".rb"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-RB-001: SQL injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // where("...#{user_input}") or find_by_sql("...")
      const sqlInterp = /(?:where|find_by_sql|select|order|group|having|joins)\s*\(\s*"[^"]*#\{/g;
      for (const m of content.matchAll(sqlInterp)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string interpolation in query`);
      }
      // ActiveRecord raw SQL with interpolation
      const rawSQL = /(?:execute|exec_query)\s*\(\s*"[^"]*#\{/g;
      for (const m of content.matchAll(rawSQL)) {
        matches.push(`${m[0].trim().slice(0, 60)} — raw SQL with string interpolation`);
      }
      // where("col = ?", value) is safe, but where("col = " + value) is not
      const sqlConcat = /(?:where|find_by_sql)\s*\([^)]*\+\s*\w+/g;
      for (const m of content.matchAll(sqlConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string concatenation`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-001",
        title: "SQL injection: query built via string interpolation or concatenation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string interpolation (#{...}) or concatenation allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data from the database.",
        acceptanceCriteria: [
          "Use parameterized queries: User.where('id = ?', params[:id]).",
          "Use ActiveRecord's built-in query methods instead of raw SQL.",
          "Never interpolate or concatenate user input into SQL strings.",
        ],
        evidence: evidence(hits, "rb-001"),
      });
    }
  }

  // DK-RB-002: XSS — raw output without sanitization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // raw() helper in Rails views
      if (/\braw\s*\(/.test(content)) {
        matches.push("raw() used — bypasses HTML escaping");
      }
      // .html_safe on strings
      if (/\.html_safe\b/.test(content)) {
        matches.push(".html_safe called — bypasses HTML escaping");
      }
      // <%== %> in ERB (unescaped output)
      if (/<%==/.test(content)) {
        matches.push("<%== %> used — unescaped ERB output");
      }
      if (matches.length > 0) {
        // Check if sanitize is used as a mitigation
        if (!/sanitize\s*\(|Sanitize\.|html_escape|h\(\)/.test(content)) {
          hits.set(file, matches.slice(0, 5));
        }
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-002",
        title: "XSS: raw output or html_safe bypasses HTML escaping",
        severity: "high",
        confidence: "medium",
        missingControls: ["outputEncoding"],
        consequence: "Using raw(), html_safe, or <%== %> bypasses Rails' automatic HTML escaping, allowing cross-site scripting (XSS) attacks when user input is included in the output.",
        acceptanceCriteria: [
          "Use sanitize() helper to whitelist allowed HTML tags.",
          "Avoid raw() and html_safe — rely on Rails' automatic escaping.",
          "If raw HTML is necessary, use the Loofah sanitizer with an explicit allowed-tags list.",
        ],
        evidence: evidence(hits, "rb-002"),
      });
    }
  }

  // DK-RB-003: Mass assignment
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // User.new(params[:user]) or Model.create(params[:model]) without strong params
      const massAssign = /(?:new|create|update_attributes?|assign_attributes)\s*\(\s*params\s*\[/g;
      for (const m of content.matchAll(massAssign)) {
        // Check if strong parameters (permit/require) are used in the file
        if (/permit\s*\(|require\s*\(|\.to_h|\.to_hash/.test(content)) continue;
        matches.push(`${m[0].trim().slice(0, 60)} — mass assignment without strong parameters`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-003",
        title: "Mass assignment: model initialized from params without strong parameters",
        severity: "high",
        confidence: "medium",
        missingControls: ["massAssignmentProtection"],
        consequence: "Passing raw params hash to model constructors allows mass assignment attacks. An attacker can set any attribute (including admin flags, account balances, or role fields) via extra form fields.",
        acceptanceCriteria: [
          "Use strong parameters: params.require(:user).permit(:name, :email).",
          "Never pass raw params hash to new(), create(), or update().",
          "Explicitly whitelist allowed attributes with permit().",
        ],
        evidence: evidence(hits, "rb-003"),
      });
    }
  }

  // DK-RB-004: Command injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // system(), exec(), ``, %x{}, Open3 without proper escaping
      const cmdPatterns = [
        { re: /\bsystem\s*\([^)]*\#\{/g, name: "system() with interpolation" },
        { re: /\bexec\s*\([^)]*\#\{/g, name: "exec() with interpolation" },
        { re: /`[^`]*#\{/g, name: "backtick with interpolation" },
        { re: /%x\{[^}]*#\{/g, name: "%x{} with interpolation" },
        { re: /\bOpen3\.\w+\s*\([^)]*\#\{/g, name: "Open3 with interpolation" },
        { re: /\bIO\.popen\s*\([^)]*\#\{/g, name: "IO.popen with interpolation" },
      ];
      for (const { re, name } of cmdPatterns) {
        for (const m of content.matchAll(re)) {
          // Check for Shellwords.escape
          if (/Shellwords\.escape|shellescape/.test(content)) continue;
          matches.push(`${name} — command injection risk`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-004",
        title: "Command injection: shell command with unsanitized interpolation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["commandInjectionPrevention"],
        consequence: "Passing unsanitized input to shell commands via interpolation allows command injection. An attacker can execute arbitrary commands on the server, leading to full system compromise.",
        acceptanceCriteria: [
          "Use Shellwords.escape() to escape all user-supplied arguments.",
          "Pass arguments as array to system()/exec() to bypass shell interpretation.",
          "Avoid shell execution entirely — use Ruby built-in methods instead.",
        ],
        evidence: evidence(hits, "rb-004"),
      });
    }
  }

  // DK-RB-005: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*=\s*["']([^"']{16,})["']/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check ENV['...'] hardcoded defaults
      const envDefault = /ENV\s*\[\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD|API)[^'"]*['"]\s*\]\s*\|\|\s*['"]([^'"]{16,})['"]/gi;
      for (const m of content.matchAll(envDefault)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`hardcoded secret as ENV fallback (entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-005",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in Ruby source code are trivially extracted from repositories, Docker images, or server file systems. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables: ENV['API_TOKEN'].",
          "Use Rails credentials (rails credentials:edit) for encrypted secret storage.",
          "Never commit secrets to source control — use .gitignore and secret scanning.",
        ],
        evidence: evidence(hits, "rb-005"),
      });
    }
  }

  // DK-RB-006: Missing CSRF protection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Only check controller files
      if (!/class\s+\w+Controller\s*</.test(content)) continue;
      if (!/(?:POST|PUT|PATCH|DELETE|create|update|destroy)/i.test(content)) continue;
      const matches: string[] = [];
      if (!/protect_from_forgery|csrf|forgery_protection/.test(content)) {
        matches.push("Controller without protect_from_forgery — CSRF protection may be disabled");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-006",
        title: "Missing CSRF protection: controller without protect_from_forgery",
        severity: "high",
        confidence: "medium",
        missingControls: ["csrfProtection"],
        consequence: "Without protect_from_forgery, an attacker can trick an authenticated user into performing state-changing operations (create, update, delete) via a malicious website.",
        acceptanceCriteria: [
          "Add protect_from_forgery with: :exception strategy in ApplicationController.",
          "Include CSRF token in all forms with <%= csrf_meta_tags %>.",
          "Use null_session strategy only for API-only controllers with token-based auth.",
        ],
        evidence: evidence(hits, "rb-006"),
      });
    }
  }

  // DK-RB-007: Unsafe deserialization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // Marshal.load with user input
      if (/Marshal\.load\s*\(/.test(content)) {
        if (!/Marshal\.dump/.test(content)) {
          matches.push("Marshal.load() used — can instantiate arbitrary objects from untrusted data");
        }
      }
      // YAML.load without safe_load
      if (/YAML\.load\s*\(/.test(content) && !/YAML\.safe_load|YAML\.load\s*\([^,]*,\s*permitted_classes/.test(content)) {
        matches.push("YAML.load() without safe_load — can instantiate arbitrary Ruby objects");
      }
      // Psych.load without safe mode
      if (/Psych\.load\s*\(/.test(content) && !/Psych\.safe_load/.test(content)) {
        matches.push("Psych.load() without safe_load — can instantiate arbitrary Ruby objects");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-007",
        title: "Unsafe deserialization: Marshal.load or YAML.load without safe mode",
        severity: "blocker",
        confidence: "high",
        missingControls: ["safeDeserialization"],
        consequence: "Marshal.load and YAML.load can instantiate arbitrary Ruby objects from untrusted input, enabling remote code execution via crafted payloads (gem dependency injection, ERB template instantiation).",
        acceptanceCriteria: [
          "Use YAML.safe_load with permitted_classes instead of YAML.load.",
          "Never use Marshal.load with untrusted input — use JSON instead.",
          "If Marshal is required, implement a whitelist of permitted classes.",
        ],
        evidence: evidence(hits, "rb-007"),
      });
    }
  }

  // DK-RB-008: Missing input validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/params\s*\[/.test(content)) continue;
      const matches: string[] = [];
      // params[:something] used without permit/require or validation
      const paramUses = content.match(/params\s*\[\s*:\w+\s*\]/g) ?? [];
      if (paramUses.length > 0) {
        // Check for strong parameters (permit/require)
        if (!/\.permit\s*\(|\.require\s*\(|strong_params|params\.require/.test(content)) {
          matches.push(`${paramUses.length} params[] access(es) without strong parameters (permit/require)`);
        }
        // Check for any validation
        if (!/validates?\s|validate\s|presence:\s*true|numericality|format:\s*\{|inclusion:\s*\{/.test(content)) {
          if (!/\.permit\s*\(|\.require\s*\(/.test(content)) {
            matches.push("params used without model validation or strong parameters");
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RB-008",
        title: "Missing input validation: params used without validation or strong parameters",
        severity: "high",
        confidence: "low",
        missingControls: ["inputValidation"],
        consequence: "Using params hash without validation or strong parameters allows malformed or malicious data to reach business logic. This can cause mass assignment, SQL injection, and other injection attacks.",
        acceptanceCriteria: [
          "Use strong parameters: params.require(:model).permit(:attr1, :attr2).",
          "Add model validations: validates :name, presence: true, length: { maximum: 255 }.",
          "Sanitize and validate all external input before use.",
        ],
        evidence: evidence(hits, "rb-008"),
      });
    }
  }

  return findings;
}
