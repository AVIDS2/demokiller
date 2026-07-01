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

export async function phpFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".php"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-PHP-001: SQL injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // mysqli_query with string interpolation
      const mysqliQuery = /mysqli_query\s*\([^,]*,\s*"[^"]*\$/g;
      for (const m of content.matchAll(mysqliQuery)) {
        matches.push(`${m[0].trim().slice(0, 60)} — mysqli_query with variable interpolation`);
      }
      // mysql_query (deprecated but still used)
      if (/mysql_query\s*\(/.test(content)) {
        matches.push("mysql_query() used — deprecated and insecure");
      }
      // PDO query without prepared statement
      const pdoQuery = /->query\s*\(\s*"[^"]*\$/g;
      for (const m of content.matchAll(pdoQuery)) {
        matches.push(`${m[0].trim().slice(0, 60)} — PDO::query with variable interpolation`);
      }
      // Direct string concat in query context
      const sqlConcat = /(?:query|exec|execute)\s*\([^)]*\.\s*\$/g;
      for (const m of content.matchAll(sqlConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string concatenation`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-001",
        title: "SQL injection: query built via string interpolation or concatenation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string interpolation or concatenation allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data from the database.",
        acceptanceCriteria: [
          "Use PDO prepared statements with bound parameters: $pdo->prepare('SELECT * FROM users WHERE id = ?').",
          "Use mysqli prepared statements with bind_param().",
          "Never concatenate or interpolate user input into SQL strings.",
        ],
        evidence: evidence(hits, "php-001"),
      });
    }
  }

  // DK-PHP-002: XSS via direct output of user input
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // echo $_GET / $_POST / $_REQUEST without htmlspecialchars
      const superGlobalEcho = /echo\s+\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\s*\[/g;
      for (const m of content.matchAll(superGlobalEcho)) {
        // Check if htmlspecialchars is used nearby
        if (/htmlspecialchars\s*\(/.test(content)) continue;
        matches.push(`${m[0].trim().slice(0, 60)} — direct output of superglobal without htmlspecialchars`);
      }
      // echo $var without htmlspecialchars in template context
      if (/\<\?=?\s*\$/.test(content) || /echo\s+\$\w+/.test(content)) {
        if (!/htmlspecialchars|htmlentities|e\(|strip_tags/.test(content)) {
          // Only flag if the file looks like a template
          if (/\<html|\<div|\<form|\<body|\<head/i.test(content) || /\.blade\.php|\.twig/.test(content)) {
            matches.push("Template output without htmlspecialchars/htmlentities encoding");
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-002",
        title: "XSS: user input output without encoding",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["outputEncoding"],
        consequence: "Echoing user input without htmlspecialchars allows cross-site scripting (XSS) attacks. An attacker can inject malicious scripts that steal session tokens, deface pages, or redirect users.",
        acceptanceCriteria: [
          "Always use htmlspecialchars($var, ENT_QUOTES, 'UTF-8') before outputting user input.",
          "Use a templating engine (Blade, Twig) with auto-escaping enabled.",
          "Never output raw user input in HTML context.",
        ],
        evidence: evidence(hits, "php-002"),
      });
    }
  }

  // DK-PHP-003: File inclusion vulnerability
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // include/require with user input
      const includeInput = /(?:include|require|include_once|require_once)\s*\(?\s*\$_(?:GET|POST|REQUEST|COOKIE)/g;
      for (const m of content.matchAll(includeInput)) {
        matches.push(`${m[0].trim().slice(0, 60)} — file inclusion with user-controlled path`);
      }
      // include/require with variable without whitelist
      const includeVar = /(?:include|require|include_once|require_once)\s*\(?\s*\$(?!_)/g;
      for (const m of content.matchAll(includeVar)) {
        // Check for whitelist / basename / realpath
        if (/basename|realpath|allowed|whitelist|in_array/.test(content)) continue;
        matches.push(`${m[0].trim().slice(0, 60)} — file inclusion with variable (no whitelist)`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-003",
        title: "File inclusion vulnerability: user-controlled include/require path",
        severity: "blocker",
        confidence: "high",
        missingControls: ["fileInclusionControl"],
        consequence: "Allowing user input in include/require paths enables Local File Inclusion (LFI) and Remote File Inclusion (RFI) attacks, potentially leading to arbitrary code execution and full server compromise.",
        acceptanceCriteria: [
          "Never pass user input directly to include/require statements.",
          "Use a whitelist of allowed files: if (!in_array($page, $allowed)) die().",
          "Use basename() and realpath() to sanitize file paths and prevent directory traversal.",
        ],
        evidence: evidence(hits, "php-003"),
      });
    }
  }

  // DK-PHP-004: Unsafe deserialization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // unserialize with user input
      if (/unserialize\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE|SESSION)/.test(content)) {
        matches.push("unserialize() with superglobal — arbitrary object instantiation");
      }
      // unserialize with variable (potentially from user)
      if (/unserialize\s*\(\s*\$/.test(content)) {
        if (!/allowed_classes\s*[:,]\s*(?:false|null)/.test(content)) {
          matches.push("unserialize() without allowed_classes restriction — potential RCE");
        }
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-004",
        title: "Unsafe deserialization: unserialize() with potentially untrusted input",
        severity: "blocker",
        confidence: "high",
        missingControls: ["safeDeserialization"],
        consequence: "PHP unserialize() with untrusted input allows arbitrary object instantiation, leading to remote code execution via magic methods (__wakeup, __destruct, __toString) in loaded classes.",
        acceptanceCriteria: [
          "Never pass user input to unserialize().",
          "If deserialization is required, use ['allowed_classes' => false] to prevent object instantiation.",
          "Prefer JSON (json_decode) for data exchange instead of PHP serialization.",
        ],
        evidence: evidence(hits, "php-004"),
      });
    }
  }

  // DK-PHP-005: Missing CSRF protection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/\$_POST|_POST\(|method\s*===?\s*['"]POST/i.test(content)) continue;
      const matches: string[] = [];
      if (!/csrf|token|_token|nonce|anti.?forgery/i.test(content)) {
        matches.push("POST handler without CSRF token verification");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-005",
        title: "Missing CSRF protection: POST handler without token verification",
        severity: "high",
        confidence: "low",
        missingControls: ["csrfProtection"],
        consequence: "Without CSRF protection, an attacker can trick an authenticated user into performing state-changing operations via a malicious website.",
        acceptanceCriteria: [
          "Generate a CSRF token per session and include it in all forms.",
          "Verify the token on every POST/PUT/DELETE request before processing.",
          "Use a framework middleware (Laravel VerifyCsrfToken) for automatic CSRF protection.",
        ],
        evidence: evidence(hits, "php-005"),
      });
    }
  }

  // DK-PHP-006: Command injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // exec, system, shell_exec, passthru, proc_open, popen with variable
      const cmdFuncs = [
        { re: /\bexec\s*\(\s*\$/g, name: "exec()" },
        { re: /\bsystem\s*\(\s*\$/g, name: "system()" },
        { re: /\bshell_exec\s*\(\s*\$/g, name: "shell_exec()" },
        { re: /\bpassthru\s*\(\s*\$/g, name: "passthru()" },
        { re: /\bproc_open\s*\(\s*\$/g, name: "proc_open()" },
        { re: /\bpopen\s*\(\s*\$/g, name: "popen()" },
        { re: /\bpcntl_exec\s*\(\s*\$/g, name: "pcntl_exec()" },
      ];
      for (const { re, name } of cmdFuncs) {
        for (const m of content.matchAll(re)) {
          // Check for escapeshellarg/escapeshellcmd
          if (/escapeshellarg|escapeshellcmd/.test(content)) continue;
          matches.push(`${name} with variable input — command injection risk`);
        }
      }
      // Backtick execution
      if (/`[^`]*\$\w+/.test(content) && !/escapeshellarg|escapeshellcmd/.test(content)) {
        matches.push("Backtick execution with variable — command injection risk");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-006",
        title: "Command injection: shell command with unsanitized input",
        severity: "blocker",
        confidence: "high",
        missingControls: ["commandInjectionPrevention"],
        consequence: "Passing unsanitized input to shell commands (exec, system, shell_exec) allows command injection. An attacker can execute arbitrary commands on the server, leading to full system compromise.",
        acceptanceCriteria: [
          "Use escapeshellarg() to escape all user-supplied arguments.",
          "Avoid shell execution entirely — use PHP built-in functions instead.",
          "If shell commands are unavoidable, use an allowlist of permitted commands.",
        ],
        evidence: evidence(hits, "php-006"),
      });
    }
  }

  // DK-PHP-007: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /\$\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*=\s*['"]([^'"]{16,})['"]/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check .env-style assignments in PHP files
      const envAssign = /(?:define|putenv)\s*\(\s*['"][^'"]*(?:KEY|SECRET|TOKEN|PASSWORD|API_KEY)[^'"]*['"]\s*,\s*['"]([^'"]{16,})['"]/gi;
      for (const m of content.matchAll(envAssign)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`hardcoded secret in define/putenv (entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-007",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in PHP source code are trivially extracted from repositories, Docker images, or server file systems. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables using getenv() or $_ENV.",
          "Use .env files (via vlucas/phpdotenv) for local development.",
          "Never commit secrets to source control — use .gitignore and secret scanning.",
        ],
        evidence: evidence(hits, "php-007"),
      });
    }
  }

  // DK-PHP-008: Missing input validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // $_GET/$_POST/$_REQUEST used without filter_var or validation
      const superGlobalUses = content.match(/\$_(?:GET|POST|REQUEST)\s*\[/g) ?? [];
      if (superGlobalUses.length > 0) {
        if (!/filter_var|filter_input|ctype_|is_numeric|is_int|is_string|preg_match|intval|floatval|strval|(?:int)|(?:float)|(?:string)\)\s*\$/.test(content)) {
          matches.push(`${superGlobalUses.length} superglobal access(es) without input validation (filter_var, ctype_*, preg_match)`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-PHP-008",
        title: "Missing input validation: superglobal access without validation",
        severity: "high",
        confidence: "low",
        missingControls: ["inputValidation"],
        consequence: "Using $_GET, $_POST, or $_REQUEST without validation allows malformed or malicious data to reach business logic. This can cause SQL injection, XSS, path traversal, and other injection attacks.",
        acceptanceCriteria: [
          "Validate all input with filter_var() or filter_input() before use.",
          "Use type casting (int)$var or ctype_* functions for type validation.",
          "Use a request validation library or framework middleware for centralized validation.",
        ],
        evidence: evidence(hits, "php-008"),
      });
    }
  }

  return findings;
}
