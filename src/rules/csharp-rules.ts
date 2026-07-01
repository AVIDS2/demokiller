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

export async function csharpFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".cs"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-CS-001: SQL string concatenation / interpolation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // $"SELECT {var}" or string interpolation in SQL context
      const interpSQL = /"\$(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\s+[^"]*\{[^}]*\}[^"]*"/gi;
      for (const m of content.matchAll(interpSQL)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string interpolation`);
      }
      // SqlCommand with string concatenation
      const sqlConcat = /(?:SqlCommand|DbCommand)\s*\([^)]*\+/g;
      for (const m of content.matchAll(sqlConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SqlCommand with string concatenation`);
      }
      // ExecuteRawSql with interpolation
      const execRawSql = /(?:FromSqlRaw|ExecuteSqlRaw)\s*\(\s*"\$\{?/gi;
      for (const m of content.matchAll(execRawSql)) {
        matches.push(`${m[0].trim().slice(0, 60)} — FromSqlRaw/ExecuteSqlRaw with interpolation`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-001",
        title: "SQL injection: query built via string concatenation or interpolation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string interpolation or concatenation allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data from the database.",
        acceptanceCriteria: [
          "Use SqlParameter for parameterized queries: new SqlParameter(\"@id\", id).",
          "Use EF Core LINQ queries or FromSqlInterpolated for safe parameterized SQL.",
          "Never use string concatenation or interpolation to build SQL queries.",
        ],
        evidence: evidence(hits, "cs-001"),
      });
    }
  }

  // DK-CS-002: Unsafe deserialization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      if (/BinaryFormatter/.test(content)) {
        matches.push("BinaryFormatter used — trivially exploitable deserialization");
      }
      if (/ObjectStateFormatter/.test(content)) {
        matches.push("ObjectStateFormatter used — vulnerable to deserialization attacks");
      }
      if (/LosFormatter/.test(content)) {
        matches.push("LosFormatter used — vulnerable to deserialization attacks");
      }
      // Newtonsoft TypeNameHandling.All or Auto without custom SerializationBinder
      if (/TypeNameHandling\s*\.\s*(?:All|Auto)/.test(content) && !/SerializationBinder|ISerializationBinder/.test(content)) {
        matches.push("TypeNameHandling.All/Auto without custom SerializationBinder — RCE risk");
      }
      // System.Text.Json with type info
      if (/JsonTypeInfoResolver|PolymorphicTypeResolver/.test(content)) {
        // Generally safer, only flag if TypeDiscriminator is too loose
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-002",
        title: "Unsafe deserialization: BinaryFormatter or TypeNameHandling without type constraint",
        severity: "blocker",
        confidence: "high",
        missingControls: ["safeDeserialization"],
        consequence: "BinaryFormatter and unconstrained TypeNameHandling allow arbitrary code execution when processing untrusted input. This is one of the most exploited vulnerability classes in .NET applications.",
        acceptanceCriteria: [
          "Never use BinaryFormatter — use System.Text.Json or Newtonsoft with TypeNameHandling.None.",
          "If TypeNameHandling is required, use a custom ISerializationBinder with an explicit allowlist.",
          "Use JsonTypeInfoResolver with specific derived types for polymorphic deserialization.",
        ],
        evidence: evidence(hits, "cs-002"),
      });
    }
  }

  // DK-CS-003: Missing authentication
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/\[(?:ApiController|Route|HttpGet|HttpPost|HttpPut|HttpDelete)\]/.test(content)) continue;
      const matches: string[] = [];
      // [AllowAnonymous] on sensitive endpoints
      if (/\[AllowAnonymous\]/.test(content)) {
        // Check if it's on a sensitive action
        if (/\[(?:HttpPost|HttpPut|HttpDelete)\]/.test(content)) {
          matches.push("[AllowAnonymous] on state-changing endpoint (POST/PUT/DELETE)");
        }
        if (/(?:password|reset|admin|transfer|payment|delete|account)/i.test(content)) {
          matches.push("[AllowAnonymous] on sensitive endpoint (password/admin/payment)");
        }
      }
      // Controller with actions but no [Authorize] at class or method level
      if (/\[(?:HttpGet|HttpPost|HttpPut|HttpDelete)\]/.test(content)) {
        if (!/\[Authorize\]/.test(content) && !/\[AllowAnonymous\]/.test(content)) {
          matches.push("API controller without [Authorize] or [AllowAnonymous] — security depends on global default");
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-003",
        title: "Missing authentication: API endpoints without authorization",
        severity: "high",
        confidence: "low",
        missingControls: ["authentication"],
        consequence: "API endpoints without explicit authorization attributes may be accessible to unauthenticated users, especially if the default policy is not set globally. This allows unauthorized access to sensitive operations.",
        acceptanceCriteria: [
          "Add [Authorize] attribute to all controllers or use a global authorization filter.",
          "Never use [AllowAnonymous] on state-changing or sensitive endpoints.",
          "Configure a default authorization policy in Program.cs: builder.Services.AddAuthorization().",
        ],
        evidence: evidence(hits, "cs-003"),
      });
    }
  }

  // DK-CS-004: Missing CSRF protection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/\[(?:HttpPost|HttpPut|HttpDelete|HttpPatch)\]/.test(content)) continue;
      const matches: string[] = [];
      if (!/ValidateAntiForgeryToken|AutoValidateAntiforgeryToken/.test(content)) {
        matches.push("POST/PUT/DELETE action without [ValidateAntiForgeryToken]");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-004",
        title: "Missing CSRF protection: POST/PUT/DELETE without anti-forgery token",
        severity: "high",
        confidence: "medium",
        missingControls: ["csrfProtection"],
        consequence: "Without anti-forgery tokens, an attacker can trick an authenticated user into performing state-changing operations via a malicious website.",
        acceptanceCriteria: [
          "Add [ValidateAntiForgeryToken] to all state-changing actions.",
          "Use [AutoValidateAntiforgeryToken] filter globally for automatic CSRF validation.",
          "Include anti-forgery token in all forms and AJAX requests.",
        ],
        evidence: evidence(hits, "cs-004"),
      });
    }
  }

  // DK-CS-005: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /(?:var|const|string)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*=\s*"([^"]{16,})"/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check appsettings.json for hardcoded values
      if (/(?:Password|Secret|Token|ApiKey|ConnectionString)\s*[:=]\s*"[^"]{20,}"/i.test(content)) {
        const cfgMatches = content.match(/(?:Password|Secret|Token|ApiKey|ConnectionString)\s*[:=]\s*"([^"]{20,})"/gi) ?? [];
        for (const cm of cfgMatches) {
          const valMatch = cm.match(/"([^"]{20,})"$/);
          if (valMatch && shannonEntropy(valMatch[1]) > 4.5) {
            matches.push(`hardcoded secret in config (entropy=${shannonEntropy(valMatch[1]).toFixed(1)})`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-005",
        title: "Hardcoded secret: high-entropy string in secret-named variable or config",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code or configuration files are trivially extracted from repositories, Docker images, or CI artifacts. This leads to credential compromise.",
        acceptanceCriteria: [
          "Load secrets from environment variables or Azure Key Vault / AWS Secrets Manager.",
          "Use dotnet user-secrets for local development secrets.",
          "Never commit secrets to source control — use .gitignore and secret scanning.",
        ],
        evidence: evidence(hits, "cs-005"),
      });
    }
  }

  // DK-CS-006: Missing input validation — [FromBody] without model validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/\[(?:HttpPost|HttpPut|HttpPatch)\]/.test(content)) continue;
      const matches: string[] = [];
      // [FromBody] without [ApiController] (which auto-validates) or without model validation
      if (/\[FromBody\]/.test(content) && !/\[ApiController\]/.test(content)) {
        if (!/ModelState\.IsValid|FluentValidation|IValidator/.test(content)) {
          matches.push("[FromBody] without [ApiController] or ModelState.IsValid check");
        }
      }
      // DTOs without DataAnnotation validation attributes
      const dtoClasses = content.match(/public\s+class\s+\w*(?:Dto|Request|Model|Input)\w*\s*\{[^}]*\}/gs) ?? [];
      for (const cls of dtoClasses) {
        if (!/\[(?:Required|StringLength|Range|MinLength|MaxLength|RegularExpression|EmailAddress)\]/.test(cls)) {
          const className = cls.match(/class\s+(\w+)/)?.[1] ?? "DTO";
          matches.push(`${className} has no validation attributes (Required, StringLength, Range, etc.)`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-006",
        title: "Missing input validation: request body without model validation",
        severity: "high",
        confidence: "medium",
        missingControls: ["inputValidation"],
        consequence: "Without model validation, malformed or malicious data reaches business logic unchecked. This can cause null reference exceptions, data corruption, or security vulnerabilities.",
        acceptanceCriteria: [
          "Add [ApiController] attribute for automatic model validation.",
          "Add [Required], [StringLength], [Range] attributes to DTO properties.",
          "Use FluentValidation for complex validation rules.",
        ],
        evidence: evidence(hits, "cs-006"),
      });
    }
  }

  // DK-CS-007: Exception swallowing
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // catch (Exception) { } or catch { }
      const emptyCatch = /catch\s*(?:\(\s*(?:Exception\s+)?\w*\s*\))?\s*\{\s*\}/g;
      for (const m of content.matchAll(emptyCatch)) {
        matches.push(`${m[0].trim().slice(0, 60)} — exception silently swallowed`);
      }
      // catch with only a comment
      const catchComment = /catch\s*(?:\([^)]*\))?\s*\{\s*\/\/[^}]*\}/g;
      for (const m of content.matchAll(catchComment)) {
        matches.push(`${m[0].trim().slice(0, 60)} — catch with only a comment, no handling`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-007",
        title: "Exception swallowing: catch block with empty or comment-only body",
        severity: "high",
        confidence: "high",
        missingControls: ["exceptionHandling"],
        consequence: "Empty catch blocks silently swallow exceptions, hiding bugs and security issues. Failed operations appear to succeed when their errors are ignored.",
        acceptanceCriteria: [
          "Log the exception with sufficient context for debugging.",
          "Rethrow or wrap in a more specific exception if the caller should handle it.",
          "At minimum, add a comment explaining why the exception is intentionally ignored.",
        ],
        evidence: evidence(hits, "cs-007"),
      });
    }
  }

  // DK-CS-008: Missing HTTPS redirection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/app\.(?:Map|Use)|WebApplication\.Create/.test(content)) continue;
      if (!/app\.(?:MapGet|MapPost|MapPut|MapDelete|Run|UseRouting|UseEndpoints|UseMvc)/.test(content)) continue;
      const matches: string[] = [];
      if (!/UseHttpsRedirection|RequireHttps/.test(content)) {
        matches.push("Application does not call app.UseHttpsRedirection() or RequireHttpsAttribute");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-CS-008",
        title: "Missing HTTPS redirection: HTTP traffic not redirected to HTTPS",
        severity: "high",
        confidence: "medium",
        missingControls: ["httpsEnforcement"],
        consequence: "Without HTTPS redirection, users can access the application over plain HTTP, allowing man-in-the-middle attacks to intercept credentials, session tokens, and sensitive data.",
        acceptanceCriteria: [
          "Add app.UseHttpsRedirection() in Program.cs before routing middleware.",
          "Configure HSTS with app.UseHsts() for production environments.",
          "Use RequireHttpsAttribute on API controllers to enforce HTTPS at the action level.",
        ],
        evidence: evidence(hits, "cs-008"),
      });
    }
  }

  return findings;
}
