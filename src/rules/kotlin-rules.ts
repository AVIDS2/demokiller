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

export async function kotlinFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".kt"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-KT-001: Unsafe null assertion (!! operator) in production code
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line)) continue;
        // Match !! operator on non-null-safe chains
        const nullAsserts = line.match(/\w+!!/g) ?? [];
        for (const m of nullAsserts) {
          matches.push(`line ${i + 1}: unsafe null assertion '${m}'`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-001",
        title: "Unsafe null assertion: !! operator can throw NullPointerException",
        severity: "high",
        confidence: "medium",
        missingControls: ["nullSafety"],
        consequence: "The !! operator throws a NullPointerException at runtime if the value is null. This defeats Kotlin's null safety guarantees and causes crashes in production.",
        acceptanceCriteria: [
          "Use safe calls (?.) with null checks instead of !! operator.",
          "Use the elvis operator (?:) with a meaningful default value.",
          "Only use !! when you can prove the value is non-null by construction.",
        ],
        evidence: evidence(hits, "kt-001"),
      });
    }
  }

  // DK-KT-002: Coroutine launch without SupervisorJob
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // GlobalScope.launch is generally discouraged
      if (/GlobalScope\.launch/.test(content)) {
        matches.push("GlobalScope.launch used — coroutine not tied to lifecycle and unstructured");
      }
      // launch {} without supervisorScope or SupervisorJob
      if (/\blaunch\s*\{/.test(content) || /\blaunch\s*\(/.test(content)) {
        if (!/supervisorScope|SupervisorJob|SupervisorCoroutine/.test(content)) {
          if (!/GlobalScope\.launch/.test(content)) {
            matches.push("launch without SupervisorJob — child failure cancels parent scope");
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-002",
        title: "Coroutine launch without SupervisorJob: unstructured concurrency",
        severity: "high",
        confidence: "medium",
        missingControls: ["structuredConcurrency"],
        consequence: "Launching coroutines without SupervisorJob or supervisorScope means any exception in a child coroutine cancels the entire scope, potentially crashing the application or losing other in-flight work.",
        acceptanceCriteria: [
          "Use supervisorScope { } when launching child coroutines that should not cancel siblings on failure.",
          "Tie coroutine scope to lifecycle (viewModelScope, lifecycleScope) instead of GlobalScope.",
          "Use CoroutineExceptionHandler for uncaught exceptions in coroutine scopes.",
        ],
        evidence: evidence(hits, "kt-002"),
      });
    }
  }

  // DK-KT-003: SQL string interpolation in queries
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // String interpolation in SQL: "SELECT $userInput" or "WHERE ${var}"
      const sqlInterp = /"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\s+[^"]*\$\{?\w+\}?[^"]*"/gi;
      for (const m of content.matchAll(sqlInterp)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string interpolation`);
      }
      // rawQuery with string interpolation
      const rawQuery = /\.rawQuery\s*\(\s*"[^"]*\$\{?\w+/gi;
      for (const m of content.matchAll(rawQuery)) {
        matches.push(`${m[0].trim().slice(0, 60)} — rawQuery with string interpolation`);
      }
      // execSQL with interpolation
      const execSQL = /\.execSQL\s*\(\s*"[^"]*\$\{?\w+/gi;
      for (const m of content.matchAll(execSQL)) {
        matches.push(`${m[0].trim().slice(0, 60)} — execSQL with string interpolation`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-003",
        title: "SQL injection: query built via string interpolation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string interpolation ($var or \${var}) allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data.",
        acceptanceCriteria: [
          "Use parameterized queries with ? placeholders and bindArgs.",
          "Use Room @Query annotations with :paramName for safe parameter binding.",
          "Never concatenate or interpolate user input into SQL strings.",
        ],
        evidence: evidence(hits, "kt-003"),
      });
    }
  }

  // DK-KT-004: Missing input validation — @RequestBody without @Valid
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/@(?:PostMapping|PutMapping|PatchMapping)/.test(content)) continue;
      const matches: string[] = [];
      const requestBodyRe = /@RequestBody\s+(?!.*@Valid)(\w+(?:<[^>]*>)?)\s+(\w+)/g;
      for (const m of content.matchAll(requestBodyRe)) {
        const paramStart = m.index!;
        const lineStart = content.lastIndexOf("\n", paramStart) + 1;
        const paramLine = content.slice(lineStart, paramStart + m[0].length + 20);
        if (/@Valid\s/.test(paramLine)) continue;
        matches.push(`@RequestBody ${m[1]} ${m[2]} without @Valid annotation`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-004",
        title: "Missing input validation: @RequestBody without @Valid",
        severity: "high",
        confidence: "medium",
        missingControls: ["inputValidation"],
        consequence: "Without @Valid, Spring does not run Bean Validation constraints on the request body. This allows malformed or malicious data to reach business logic unchecked.",
        acceptanceCriteria: [
          "Add @Valid annotation to @RequestBody parameters.",
          "Define validation constraints on DTO fields (@NotNull, @Size, @Email, etc.).",
          "Add @ControllerAdvice to handle MethodArgumentNotValidException with 400 response.",
        ],
        evidence: evidence(hits, "kt-004"),
      });
    }
  }

  // DK-KT-005: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretVarRe = /\b\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*=\s*"([A-Za-z0-9+/=_\-]{16,})"/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretVarRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check val/token/secret named vars with string assignment
      const valAssign = /\b(?:val|var)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential)\w*\s*=\s*"([^"]{16,})"/gi;
      for (const m of content.matchAll(valAssign)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`hardcoded secret in val/var (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-005",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code are trivially extracted from repositories, CI logs, or compiled binaries. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables or BuildConfig fields.",
          "Use Android Keystore or a secret manager for sensitive credentials.",
          "Never commit secrets to source control — use local.properties and .gitignore.",
        ],
        evidence: evidence(hits, "kt-005"),
      });
    }
  }

  // DK-KT-006: Empty catch block
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // catch (e: Exception) { } or catch (_: Exception) { }
      const emptyCatch = /catch\s*\([^)]*\)\s*\{\s*\}/g;
      for (const m of content.matchAll(emptyCatch)) {
        matches.push(`${m[0].trim().slice(0, 60)} — exception silently swallowed`);
      }
      // Also catch with only a comment
      const catchComment = /catch\s*\([^)]*\)\s*\{\s*\/\/[^}]*\}/g;
      for (const m of content.matchAll(catchComment)) {
        matches.push(`${m[0].trim().slice(0, 60)} — catch with only a comment, no handling`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-006",
        title: "Empty catch block: exception silently swallowed",
        severity: "high",
        confidence: "high",
        missingControls: ["exceptionHandling"],
        consequence: "Empty catch blocks silently swallow exceptions, hiding bugs and security issues. Failed operations appear to succeed when their errors are ignored.",
        acceptanceCriteria: [
          "Log the exception with sufficient context for debugging.",
          "Rethrow as a more specific exception if the caller should handle it.",
          "At minimum, add a comment explaining why the exception is intentionally ignored.",
        ],
        evidence: evidence(hits, "kt-006"),
      });
    }
  }

  // DK-KT-007: Missing HTTP timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // OkHttpClient() or OkHttpClient.Builder() without timeout
      if (/OkHttpClient\s*\(\s*\)/.test(content) && !/connectTimeout|readTimeout|writeTimeout|callTimeout/.test(content)) {
        matches.push("OkHttpClient() without timeout configuration");
      }
      // HttpClient() in Ktor without timeout plugin
      if (/HttpClient\s*\(\s*\)/.test(content) && !/install\s*\(\s*HttpTimeout/.test(content)) {
        matches.push("HttpClient() without HttpTimeout plugin");
      }
      // Retrofit.Builder without OkHttp timeout
      if (/Retrofit\.Builder\(\)/.test(content) && !/OkHttpClient/.test(content)) {
        matches.push("Retrofit.Builder() without custom OkHttpClient (uses default with no timeout)");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-007",
        title: "Missing HTTP client timeout",
        severity: "high",
        confidence: "medium",
        missingControls: ["httpClientTimeout"],
        consequence: "An HTTP client without a timeout can hang indefinitely on slow or unresponsive servers, tying up coroutines and eventually causing ANR or memory exhaustion.",
        acceptanceCriteria: [
          "Configure connectTimeout, readTimeout, and writeTimeout on OkHttpClient.",
          "Install HttpTimeout plugin with requestTimeoutMillis on Ktor HttpClient.",
          "Always provide a configured OkHttpClient to Retrofit.Builder().client(okHttpClient).",
        ],
        evidence: evidence(hits, "kt-007"),
      });
    }
  }

  // DK-KT-008: Thread safety — mutable state in companion object
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/companion\s+object/.test(content)) continue;
      const matches: string[] = [];
      // var mutable state in companion object without synchronization
      const companionBlock = content.match(/companion\s+object\s*\{[^}]*\}/gs) ?? [];
      for (const block of companionBlock) {
        const mutableVars = block.match(/\bvar\s+\w+/g) ?? [];
        for (const mv of mutableVars) {
          // Check for synchronization in the broader file
          if (/synchronized|Mutex|AtomicReference|AtomicBoolean|AtomicInteger|@Volatile|volatile/.test(content)) continue;
          matches.push(`${mv} in companion object without synchronization`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-KT-008",
        title: "Thread safety: mutable state in companion object without synchronization",
        severity: "medium",
        confidence: "medium",
        missingControls: ["threadSafety"],
        consequence: "Companion objects are singletons. Mutable var fields are shared across all threads, leading to data races, corrupted state, and intermittent bugs under concurrent access.",
        acceptanceCriteria: [
          "Use @Volatile for visibility guarantees on shared mutable fields.",
          "Use synchronized blocks or Mutex for compound read-modify-write operations.",
          "Prefer immutable data structures (val with immutable types) in companion objects.",
        ],
        evidence: evidence(hits, "kt-008"),
      });
    }
  }

  return findings;
}
