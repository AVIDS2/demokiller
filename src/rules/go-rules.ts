import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;

const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;

function evidence(hits: Map<string, string[]>, ruleId: string) {
  return [...hits.entries()].map(([file, signals]) => ({
    id: `${ruleId}-${file}`,
    detector: "pattern-match",
    location: { path: file },
    controls: [],
    signals
  }));
}

/**
 * Shannon entropy of a string.  High-entropy strings (>4.5) that look like
 * tokens/keys are likely hardcoded secrets.
 */
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

export async function goFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".go"]);
  if (files.length === 0) return [];

  // Cache file contents
  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-GO-001: Goroutine leak — go func() without context cancellation/timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const goFuncs = [...content.matchAll(/\bgo\s+func\s*\(\s*\)/g)];
      if (goFuncs.length === 0) continue;
      // Check if context.WithTimeout or context.WithCancel is used in the same file
      if (/context\.With(?:Timeout|Cancel|Deadline)/.test(content)) continue;
      // Check for select on ctx.Done() near the goroutine
      if (/ctx\.Done\(\)/.test(content)) continue;
      hits.set(file, [`${goFuncs.length} go func() without context cancellation/timeout`]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-001",
        title: "Goroutine leak: goroutine without context cancellation or timeout",
        severity: "high",
        confidence: "medium",
        missingControls: ["goroutineLifecycleManagement"],
        consequence: "Goroutines spawned without context cancellation or timeout will run indefinitely, causing goroutine leaks that exhaust memory and file descriptors over time.",
        acceptanceCriteria: [
          "Use context.WithTimeout or context.WithCancel to control goroutine lifetime.",
          "Pass a context to every goroutine and select on ctx.Done() to detect cancellation.",
          "Use errgroup for coordinated goroutine management.",
        ],
        evidence: evidence(hits, "go-001"),
      });
    }
  }

  // DK-GO-002: Unchecked error — err assigned but immediately discarded with _
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Pattern: _ = someFunc(...) or _, _ = someFunc(...)
        // Discarded error on the same line
        if (/_\s*=\s*[\w.]+\(.*\)/.test(line) && !/^\s*\/\//.test(line)) {
          // Only flag if there's an error-returning function in context
          if (/(?::=|,)\s*[\w.]+\(/.test(line)) continue; // normal assignment
          matches.push(`line ${i + 1}: ${line.trim().slice(0, 80)}`);
        }
      }
      // Also check for explicit `if err != nil` missing after `err` assignment
      // Pattern: varName, err := ... on one line, no err check within 5 lines
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const errAssign = line.match(/\b\w+\s*,\s*(?:err|e)\s*:=\s*/);
        if (!errAssign) continue;
        if (/^\s*\/\//.test(line)) continue;
        // Look ahead up to 5 lines for err != nil check
        const ahead = lines.slice(i + 1, i + 6).join("\n");
        if (!/(?:err|e)\s*!=\s*nil/.test(ahead) && !/if\s+err\b/.test(ahead)) {
          // Check if err is used as _ on the same line (explicit discard)
          if (!/,\s*_\s*:=/.test(line) && !/^\s*_\s*,/.test(line)) {
            matches.push(`line ${i + 1}: error return not checked within 5 lines`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-002",
        title: "Unchecked error: error return ignored or discarded",
        severity: "high",
        confidence: "medium",
        missingControls: ["errorChecking"],
        consequence: "Ignoring error return values in Go silently swallows failures. Unhandled errors lead to undefined behavior, data corruption, or security vulnerabilities.",
        acceptanceCriteria: [
          "Always check error returns: if err != nil { return err }.",
          "Use explicit error wrapping: if err != nil { return fmt.Errorf(\"context: %w\", err) }.",
          "Never discard errors with _ unless explicitly justified with a comment.",
        ],
        evidence: evidence(hits, "go-002"),
      });
    }
  }

  // DK-GO-003: Missing HTTP client timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // Check for http.Client{} without Timeout field
      const clientLiterals = content.match(/&(?:http\.Client|http\.Transport)\{[^}]*\}/g) ?? [];
      for (const lit of clientLiterals) {
        if (!/Timeout/.test(lit) && !/Transport/.test(lit)) {
          matches.push("http.Client{} without Timeout field");
        }
      }
      // Also check for http.DefaultClient usage (has no timeout by default)
      if (/http\.DefaultClient\b/.test(content)) {
        matches.push("http.DefaultClient used (no default timeout)");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-003",
        title: "Missing HTTP client timeout",
        severity: "high",
        confidence: "high",
        missingControls: ["httpClientTimeout"],
        consequence: "An HTTP client without a timeout can hang indefinitely on slow or unresponsive servers, tying up goroutines and eventually exhausting connections or memory.",
        acceptanceCriteria: [
          "Set Timeout on http.Client: &http.Client{Timeout: 10 * time.Second}.",
          "Configure Transport.TLSHandshakeTimeout and ResponseHeaderTimeout.",
          "Avoid http.DefaultClient in production code — always create a configured client.",
        ],
        evidence: evidence(hits, "go-003"),
      });
    }
  }

  // DK-GO-004: Context not propagated — context.Background() in handler
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Only flag in handler-like code (files with http handler patterns)
      if (!/func\s*\(\s*w\s+http\.ResponseWriter/.test(content)) continue;
      const bgCtx = content.match(/\bcontext\.Background\(\)/g) ?? [];
      if (bgCtx.length > 0) {
        // Check if r.Context() is also used — if so, this is just initialization, likely ok
        if (/\.Context\(\)/.test(content)) continue;
        hits.set(file, [`${bgCtx.length} context.Background() in HTTP handler without using r.Context()`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-004",
        title: "Context not propagated: context.Background() used in HTTP handler",
        severity: "medium",
        confidence: "medium",
        missingControls: ["contextPropagation"],
        consequence: "Using context.Background() in HTTP handlers bypasses request-scoped context, breaking cancellation propagation, deadline enforcement, and trace/span correlation.",
        acceptanceCriteria: [
          "Use r.Context() from the HTTP request instead of context.Background().",
          "Propagate request context to all downstream calls (database, HTTP clients).",
          "Use context.TODO() only as a temporary placeholder during development.",
        ],
        evidence: evidence(hits, "go-004"),
      });
    }
  }

  // DK-GO-005: SQL string concatenation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // db.Query("SELECT..." + var) or db.Exec("INSERT..." + fmt.Sprintf(...))
      const sqlConcat = /(?:Query|Exec|QueryRow|QueryContext|ExecContext)\s*\([^)]*\+\s*/g;
      for (const m of content.matchAll(sqlConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string concatenation`);
      }
      // fmt.Sprintf used in SQL context
      const sprintfInSQL = /(?:Query|Exec|QueryRow)\s*\(\s*(?:fmt\.Sprintf)\s*\(/g;
      for (const m of content.matchAll(sprintfInSQL)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with fmt.Sprintf`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-005",
        title: "SQL injection: query built via string concatenation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string concatenation or fmt.Sprintf allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data.",
        acceptanceCriteria: [
          "Use parameterized queries: db.Query(\"SELECT * FROM users WHERE id = $1\", id).",
          "Never use fmt.Sprintf or string concatenation to build SQL queries.",
          "Use a query builder (squirrel, goqu) for dynamic query construction.",
        ],
        evidence: evidence(hits, "go-005"),
      });
    }
  }

  // DK-GO-006: Panic in production code
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Skip test files already handled by EXCLUDE_RE
      const panics = content.match(/\bpanic\s*\(/g) ?? [];
      // Filter out recover() patterns — panic is handled
      const hasRecover = /\brecover\(\)/.test(content);
      if (panics.length > 0 && !hasRecover) {
        hits.set(file, [`${panics.length} panic() call(s) without recover()`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-006",
        title: "Panic in production code: panic() without recover()",
        severity: "high",
        confidence: "medium",
        missingControls: ["gracefulErrorHandling"],
        consequence: "Unrecovered panics crash the entire goroutine and, if in the main goroutine or an HTTP handler, crash the process. This causes service outages and lost in-flight requests.",
        acceptanceCriteria: [
          "Replace panic() with proper error returns: return fmt.Errorf(\"...\").",
          "If panic is unavoidable, add a deferred recover() to convert panic to error.",
          "Use middleware to recover from panics in HTTP handlers.",
        ],
        evidence: evidence(hits, "go-006"),
      });
    }
  }

  // DK-GO-007: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretVarRe = /\b(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\b/i;
    // Match Go string constant assignments
    const constAssignRe = /(?:const|var)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*(?:=\s*"([^"]{16,})"|(?:string\s*=\s*"([^"]{16,})"))/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(constAssignRe)) {
        const val = m[1] ?? m[2] ?? "";
        if (val && shannonEntropy(val) > 4.5) {
          matches.push(`high-entropy secret in constant (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check for hardcoded strings assigned to secret-named variables
      const assignRe = /\b\w*(?:token|secret|password|apikey|api_key)\w*\s*=\s*"([A-Za-z0-9+/=_\-]{20,})"/gi;
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
        ruleId: "DK-GO-007",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code are trivially extracted from repositories, CI logs, or compiled binaries. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables: os.Getenv(\"API_TOKEN\").",
          "Use a secret manager (Vault, AWS SSM, GCP Secret Manager).",
          "Never commit secrets to source control — use .env and .gitignore.",
        ],
        evidence: evidence(hits, "go-007"),
      });
    }
  }

  // DK-GO-008: Missing graceful shutdown
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/http\.ListenAndServe/.test(content) && !/\.ListenAndServe\(/.test(content)) continue;
      // Check for graceful shutdown patterns
      if (/\.Shutdown\s*\(/.test(content)) continue;
      if (/os\.Signal/.test(content) || /signal\.Notify/.test(content)) continue;
      hits.set(file, ["HTTP server without graceful shutdown (missing srv.Shutdown(ctx) or signal handling)"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-008",
        title: "Missing graceful shutdown for HTTP server",
        severity: "medium",
        confidence: "medium",
        missingControls: ["gracefulShutdown"],
        consequence: "An HTTP server without graceful shutdown drops in-flight requests when the process is terminated, causing data loss and client errors during deployments or scaling events.",
        acceptanceCriteria: [
          "Listen for os.Interrupt/SIGTERM and call srv.Shutdown(ctx) with a timeout.",
          "Use http.Server{} with a method receiver so Shutdown can be called on it.",
          "Wait for all goroutines to finish before exiting.",
        ],
        evidence: evidence(hits, "go-008"),
      });
    }
  }

  // DK-GO-009: Unbounded goroutine spawning in loops
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Look for `for` or `range` followed by `go func()` within 10 lines
        if (!/\bfor\b/.test(line)) continue;
        const ahead = lines.slice(i, i + 10).join("\n");
        if (!/\bgo\s+func\s*\(/.test(ahead)) continue;
        // Check for semaphore (buffered channel, errgroup, or sync.WaitGroup)
        if (/make\s*\(\s*chan\s+struct/.test(content)) continue;
        if (/errgroup|semaphore|sync\.WaitGroup|golang\.org\/x\/sync/.test(content)) continue;
        matches.push(`line ${i + 1}: go func() inside loop without semaphore/errgroup`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-009",
        title: "Unbounded goroutine spawning in loop",
        severity: "high",
        confidence: "low",
        missingControls: ["goroutineConcurrencyControl"],
        consequence: "Spawning goroutines inside a loop without concurrency limits creates O(n) goroutines that can exhaust memory, file descriptors, and cause scheduler starvation.",
        acceptanceCriteria: [
          "Use a buffered channel as a semaphore to limit concurrent goroutines.",
          "Use errgroup with SetLimit() for bounded concurrent execution.",
          "Use a worker pool pattern for batch processing.",
        ],
        evidence: evidence(hits, "go-009"),
      });
    }
  }

  // DK-GO-010: Missing request body limit
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/r\.Body/.test(content)) continue;
      const matches: string[] = [];
      // io.ReadAll(r.Body) without MaxBytesReader
      if (/io\.ReadAll\s*\(\s*r\.Body/.test(content) && !/MaxBytesReader/.test(content)) {
        matches.push("io.ReadAll(r.Body) without http.MaxBytesReader");
      }
      // json.NewDecoder(r.Body).Decode() without MaxBytesReader
      if (/json\.NewDecoder\s*\(\s*r\.Body/.test(content) && !/MaxBytesReader/.test(content)) {
        matches.push("json.NewDecoder(r.Body) without http.MaxBytesReader");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-010",
        title: "Missing request body limit: unbounded body read",
        severity: "high",
        confidence: "high",
        missingControls: ["requestBodySizeLimit"],
        consequence: "Reading an HTTP request body without a size limit allows an attacker to send an arbitrarily large payload, exhausting server memory and causing denial of service.",
        acceptanceCriteria: [
          "Wrap r.Body with http.MaxBytesReader(w, r.Body, maxBytes) before reading.",
          "Set a reasonable limit based on expected payload (e.g., 1MB for JSON APIs).",
          "Return 413 Request Entity Too Large when the limit is exceeded.",
        ],
        evidence: evidence(hits, "go-010"),
      });
    }
  }

  // DK-GO-011: Unsafe type assertion without ok check
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // Pattern: val := x.(Type) — without ok check
      // Safe: val, ok := x.(Type)
      const typeAssert = /(\w+)\s*:=\s*\w+\.\((\w+(?:\.\w+)?)\)/g;
      for (const m of content.matchAll(typeAssert)) {
        const fullMatch = m[0];
        // Check if it's the two-value form: x, ok := ...
        const lineStart = content.lastIndexOf("\n", m.index!) + 1;
        const linePrefix = content.slice(lineStart, m.index!);
        if (/,\s*(?:ok|_)\s*:=$/.test(linePrefix)) continue; // safe
        if (/,.*:=/.test(fullMatch)) continue; // has ok already
        matches.push(`${fullMatch.trim().slice(0, 60)} — type assertion without ok check`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-011",
        title: "Unsafe type assertion without ok check",
        severity: "medium",
        confidence: "medium",
        missingControls: ["typeAssertionSafety"],
        consequence: "A type assertion without the comma-ok form panics if the underlying type does not match. This causes runtime crashes in production when unexpected types are encountered.",
        acceptanceCriteria: [
          "Use the two-value form: val, ok := x.(Type); if !ok { handle error }.",
          "Use type switch for multiple possible types.",
          "Prefer explicit type checks over panicking assertions.",
        ],
        evidence: evidence(hits, "go-011"),
      });
    }
  }

  // DK-GO-012: Missing CORS middleware
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Only flag files that register HTTP routes/handlers
      if (!/(?:http\.Handle|mux\.Handle|r\.GET|r\.POST|r\.PUT|r\.DELETE|\.HandleFunc|gin\.Default|echo\.New|fiber\.New)/.test(content)) continue;
      // Check for CORS configuration
      if (/cors/i.test(content) || /Access-Control-Allow-Origin/.test(content)) continue;
      // Check if it's a library/SDK file (not a main server)
      if (/^package\s+(?:main|server|api|app)\b/m.test(content) === false) continue;
      hits.set(file, ["HTTP handlers registered without CORS middleware configuration"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-012",
        title: "Missing CORS middleware on HTTP server",
        severity: "medium",
        confidence: "low",
        missingControls: ["corsConfiguration"],
        consequence: "Without CORS middleware, the server either rejects all cross-origin requests (breaking legitimate clients) or relies on browser defaults, which may not match intended access policy.",
        acceptanceCriteria: [
          "Add CORS middleware with explicit allowed origins (not wildcard *).",
          "Configure allowed methods, headers, and credentials as needed.",
          "Use rs/cors or similar library for framework-agnostic CORS handling.",
        ],
        evidence: evidence(hits, "go-012"),
      });
    }
  }

  // DK-GO-013: Use of math/rand for security-sensitive operations
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/math\/rand/.test(content)) continue;
      // Check if the random values are used in security context
      const securityContext = /\b(?:token|nonce|session|password|secret|key|salt|challenge|otp)\b/i;
      if (!securityContext.test(content)) continue;
      const matches: string[] = [];
      const mathRandCalls = content.match(/\brand\.\w+\(/g) ?? [];
      if (mathRandCalls.length > 0) {
        matches.push("math/rand used in security-sensitive context (should use crypto/rand)");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-013",
        title: "math/rand used for security-sensitive operations",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["cryptographicRandomness"],
        consequence: "math/rand produces predictable pseudo-random numbers that are trivially reproducible. Using it for tokens, nonces, or keys allows attackers to predict values and bypass security controls.",
        acceptanceCriteria: [
          "Use crypto/rand for all security-sensitive random generation.",
          "Import \"crypto/rand\" and use rand.Read() for random bytes.",
          "For random strings, encode crypto/rand output to hex or base64.",
        ],
        evidence: evidence(hits, "go-013"),
      });
    }
  }

  // DK-GO-014: Missing health check endpoint
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/http\.ListenAndServe|\.Listen\(|\.ListenAndServe\(/.test(content)) continue;
      // Check for health check endpoint
      if (/\/health|\/healthz|\/ready|\/readiness|\/liveness|\/ping/.test(content)) continue;
      hits.set(file, ["HTTP server without /health or /healthz endpoint"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-014",
        title: "Missing health check endpoint",
        severity: "advisory",
        confidence: "medium",
        missingControls: ["healthCheckEndpoint"],
        consequence: "Without health check endpoints, load balancers and orchestrators (Kubernetes, ECS) cannot detect unresponsive instances, causing traffic to be routed to broken pods.",
        acceptanceCriteria: [
          "Add /healthz endpoint that returns 200 OK when the service is ready.",
          "Add /readiness that checks downstream dependencies (DB, cache).",
          "Configure Kubernetes liveness and readiness probes to use these endpoints.",
        ],
        evidence: evidence(hits, "go-014"),
      });
    }
  }

  // DK-GO-015: Unvalidated redirect
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // http.Redirect with user-controlled URL
      const redirectPatterns = [
        /http\.Redirect\s*\([^,]*,[^,]*,\s*(?:r\.(?:URL\.Query|FormValue|Header)|req\.(?:URL\.Query|FormValue))/g,
      ];
      for (const pat of redirectPatterns) {
        for (const m of content.matchAll(pat)) {
          // Check if there's a whitelist/allowed hosts check nearby
          if (/allowedHosts|whitelist|isAllowedRedirect|safeRedirect/.test(content)) continue;
          matches.push(`${m[0].trim().slice(0, 60)} — redirect without URL validation`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-015",
        title: "Unvalidated redirect: user-controlled redirect URL",
        severity: "high",
        confidence: "medium",
        missingControls: ["redirectValidation"],
        consequence: "An open redirect vulnerability allows an attacker to redirect users to a malicious site via a crafted URL parameter, enabling phishing attacks and OAuth token theft.",
        acceptanceCriteria: [
          "Validate redirect URLs against an allowlist of trusted hosts.",
          "Only allow relative redirects (starting with /) — reject absolute URLs.",
          "Never redirect to user-provided URLs without strict validation.",
        ],
        evidence: evidence(hits, "go-015"),
      });
    }
  }

  // DK-GO-016: Context cancellation leak — context.Background() in handler without timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/func\s*\(\s*w\s+http\.ResponseWriter/.test(content) && !/func\s+\w+\s*\(\s*w\s+http\.ResponseWriter/.test(content)) continue;
      const matches: string[] = [];
      const bgCtx = content.match(/\bcontext\.Background\(\)/g) ?? [];
      if (bgCtx.length === 0) continue;
      // Check if context.WithTimeout or context.WithDeadline is used with the background context
      if (/context\.With(?:Timeout|Deadline)\s*\(\s*context\.Background/.test(content)) continue;
      hits.set(file, [`context.Background() in HTTP handler without timeout — ${bgCtx.length} occurrence(s)`]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-016",
        title: "Context cancellation leak: context.Background() without timeout in handler",
        severity: "high",
        confidence: "medium",
        missingControls: ["contextCancellation"],
        consequence: "Using context.Background() in an HTTP handler without a timeout creates context cancellation leaks. Downstream calls never receive cancellation signals, tying up goroutines and connections indefinitely.",
        acceptanceCriteria: [
          "Use context.WithTimeout(r.Context(), duration) instead of context.Background().",
          "Pass request context to all downstream calls.",
          "Set appropriate timeouts based on expected operation duration.",
        ],
        evidence: evidence(hits, "go-016"),
      });
    }
  }

  // DK-GO-017: TLS config insecure
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      if (/InsecureSkipVerify\s*:\s*true/.test(content)) {
        matches.push("InsecureSkipVerify: true — TLS certificate verification disabled");
      }
      if (/MinVersion\s*:\s*tls\.VersionTLS10/.test(content) || /MinVersion\s*:\s*tls\.VersionTLS11/.test(content)) {
        matches.push("TLS 1.0 or 1.1 configured as minimum version — deprecated and insecure");
      }
      if (/MaxVersion\s*:\s*tls\.VersionTLS10/.test(content) || /MaxVersion\s*:\s*tls\.VersionTLS11/.test(content)) {
        matches.push("TLS 1.0 or 1.1 configured as maximum version — deprecated and insecure");
      }
      // Check for empty/insecure cipher suites
      if (/CipherSuites\s*:\s*\[\]uint16\s*\{?\s*\}?/.test(content)) {
        matches.push("Empty CipherSuites — using system defaults which may include weak ciphers");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-017",
        title: "Insecure TLS configuration",
        severity: "high",
        confidence: "high",
        missingControls: ["tlsConfiguration"],
        consequence: "Insecure TLS configuration (disabled certificate verification, deprecated TLS versions) exposes the application to man-in-the-middle attacks, protocol downgrade attacks, and data interception.",
        acceptanceCriteria: [
          "Never set InsecureSkipVerify to true in production — use proper certificate validation.",
          "Set MinVersion to tls.VersionTLS12 or higher.",
          "Use strong cipher suites: TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384, etc.",
        ],
        evidence: evidence(hits, "go-017"),
      });
    }
  }

  // DK-GO-018: Log injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // Check for log statements with unsanitized user input
      const logPatterns = [
        /log\.\w+\s*\([^)]*r\.(?:URL|Header|FormValue|RemoteAddr|UserAgent)/g,
        /log\.\w+\s*\([^)]*req\.(?:URL|Header|FormValue|RemoteAddr)/g,
        /logrus\.\w+\s*\([^)]*r\.(?:URL|Header|FormValue)/g,
        /zap\.\w+\s*\([^)]*r\.(?:URL|Header|FormValue)/g,
        /slog\.\w+\s*\([^)]*r\.(?:URL|Header|FormValue)/g,
      ];
      for (const pat of logPatterns) {
        for (const m of content.matchAll(pat)) {
          // Check if there's sanitization
          if (/sanitize|escape|clean|strings\.Replace|regexp\.Replace/.test(content)) continue;
          matches.push(`log with unsanitized request data: ${m[0].trim().slice(0, 60)}`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-018",
        title: "Log injection: user input in log fields without sanitization",
        severity: "high",
        confidence: "low",
        missingControls: ["logSanitization"],
        consequence: "Injecting unsanitized user input into logs enables log injection attacks. Attackers can forge log entries, inject malicious content into log analysis tools, or exploit log parsing vulnerabilities.",
        acceptanceCriteria: [
          "Sanitize user input before logging — strip newlines, control characters, and ANSI sequences.",
          "Use structured logging (zap, slog) with typed fields instead of string interpolation.",
          "Validate and encode log output to prevent log forgery.",
        ],
        evidence: evidence(hits, "go-018"),
      });
    }
  }

  // DK-GO-019: SSRF via user-controlled URL
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // HTTP request with user-controlled URL
      const ssrfPatterns = [
        /http\.(?:Get|Post|Do|Head|NewRequest)\s*\([^)]*(?:r\.|req\.)?(?:URL\.Query|FormValue|Header\.Get|Body)/g,
        /http\.(?:Get|Post|Do)\s*\([^)]*(?:url|target|endpoint|host)\b/g,
      ];
      for (const pat of ssrfPatterns) {
        for (const m of content.matchAll(pat)) {
          // Check for URL validation
          if (/allowedHosts|whitelist|isAllowedHost|validateURL|safeURL/.test(content)) continue;
          matches.push(`HTTP request with user-controlled URL: ${m[0].trim().slice(0, 60)}`);
        }
      }
      // Check for url.Parse with user input
      if (/url\.Parse\s*\([^)]*(?:r\.|req\.)?(?:FormValue|URL\.Query|Header)/.test(content)) {
        if (!/allowedHosts|whitelist|isAllowedHost/.test(content)) {
          matches.push("url.Parse with user-controlled input without host validation");
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-019",
        title: "SSRF via user-controlled URL",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["ssrfPrevention"],
        consequence: "Server-Side Request Forgery (SSRF) allows attackers to make the server send requests to internal services, cloud metadata endpoints, or other restricted resources. This can expose internal infrastructure, credentials, and private data.",
        acceptanceCriteria: [
          "Validate and restrict target URLs against an allowlist of trusted hosts.",
          "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x).",
          "Use a DNS resolver that validates resolved IPs against allowed ranges.",
        ],
        evidence: evidence(hits, "go-019"),
      });
    }
  }

  // DK-GO-020: Open redirect
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // http.Redirect with user-controlled destination
      const redirectWithInput = content.match(/http\.Redirect\s*\([^,]*,\s*[^,]*,\s*(?:r\.\w+|req\.\w+|[\w.]+\s*\()/g) ?? [];
      for (const m of redirectWithInput) {
        // Check for URL validation or allowlist
        if (/allowedHosts|whitelist|isAllowedRedirect|safeRedirect|isValidRedirect|url\.Parse/.test(content)) continue;
        matches.push(`http.Redirect with user input: ${m.trim().slice(0, 60)}`);
      }
      // Also check for redirect with parsed query params
      if (/r\.(?:URL\.Query|FormValue)\s*\(\s*["'](?:redirect|return|next|url|continue|dest)/.test(content)) {
        if (/http\.Redirect/.test(content) && !/allowedHosts|whitelist|isAllowedRedirect|safeRedirect/.test(content)) {
          matches.push("Redirect URL sourced from query parameter without validation");
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-GO-020",
        title: "Open redirect: user-controlled redirect destination",
        severity: "high",
        confidence: "medium",
        missingControls: ["redirectValidation"],
        consequence: "An open redirect vulnerability allows an attacker to redirect users to a malicious site via a crafted URL parameter, enabling phishing attacks, OAuth token theft, and credential harvesting.",
        acceptanceCriteria: [
          "Validate redirect URLs against an allowlist of trusted hosts.",
          "Only allow relative redirects (starting with /) — reject absolute URLs with scheme.",
          "Use url.Parse and check the host component matches trusted domains.",
        ],
        evidence: evidence(hits, "go-020"),
      });
    }
  }

  return findings;
}
