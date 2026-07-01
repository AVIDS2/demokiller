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

export async function rustFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".rs"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-RS-001: Unwrap abuse — .unwrap() in non-test code (>5 per file)
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const unwraps = content.match(/\.unwrap\(\)/g) ?? [];
      if (unwraps.length > 5) {
        hits.set(file, [`${unwraps.length} .unwrap() calls in production code`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-001",
        title: "Excessive .unwrap() usage in production code",
        severity: "high",
        confidence: "medium",
        missingControls: ["properErrorHandling"],
        consequence: "Excessive .unwrap() calls panic on Err/None, crashing the application. In production, each unwrap is a potential crash point that provides no error context.",
        acceptanceCriteria: [
          "Use the ? operator or match/expect instead of .unwrap().",
          "Replace .unwrap() with .expect(\"descriptive context\") at minimum.",
          "Use .unwrap_or(), .unwrap_or_else(), or .ok_or()? for fallback values.",
        ],
        evidence: evidence(hits, "rs-001"),
      });
    }
  }

  // DK-RS-002: Unsafe block usage
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const unsafeBlocks = content.match(/\bunsafe\s*\{/g) ?? [];
      if (unsafeBlocks.length > 0) {
        hits.set(file, [`${unsafeBlocks.length} unsafe block(s) — bypasses Rust safety guarantees`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-002",
        title: "Unsafe block usage: Rust safety guarantees bypassed",
        severity: "high",
        confidence: "medium",
        missingControls: ["unsafeCodeAuditing"],
        consequence: "Unsafe blocks bypass Rust's borrow checker and can lead to undefined behavior, memory corruption, and data races. Each unsafe block requires careful manual auditing.",
        acceptanceCriteria: [
          "Document every unsafe block with a SAFETY comment explaining why it's sound.",
          "Minimize unsafe block scope — isolate the unsafe operation, keep safe code outside.",
          "Run Miri on unsafe code to detect undefined behavior in tests.",
        ],
        evidence: evidence(hits, "rs-002"),
      });
    }
  }

  // DK-RS-003: Global mutable state — static mut
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const staticMuts = content.match(/\bstatic\s+mut\s+\w+/g) ?? [];
      if (staticMuts.length > 0) {
        hits.set(file, staticMuts.map(s => `${s} — global mutable state is unsafe`));
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-003",
        title: "Global mutable state: static mut declarations",
        severity: "high",
        confidence: "high",
        missingControls: ["globalStateSafety"],
        consequence: "static mut variables are inherently unsafe — any access requires an unsafe block and creates data races in multithreaded programs. This is deprecated in favor of safe alternatives.",
        acceptanceCriteria: [
          "Use Mutex<T>, RwLock<T>, or OnceLock<T> for global shared state.",
          "Use atomic types (AtomicBool, AtomicUsize) for simple counters/flags.",
          "Prefer lazy_static! or once_cell for one-time initialization.",
        ],
        evidence: evidence(hits, "rs-003"),
      });
    }
  }

  // DK-RS-004: Missing error propagation — unwrap in Result-returning functions
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Find functions that return Result but use .unwrap() inside
      const fnReturnsResult = /\bfn\s+\w+[^{]*->\s*.*Result\b/s;
      if (!fnReturnsResult.test(content)) continue;
      const unwraps = content.match(/\.unwrap\(\)/g) ?? [];
      if (unwraps.length > 0) {
        hits.set(file, [`${unwraps.length} .unwrap() in Result-returning function (use ? instead)`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-004",
        title: "Missing error propagation: .unwrap() in Result-returning function",
        severity: "medium",
        confidence: "medium",
        missingControls: ["errorPropagation"],
        consequence: "Using .unwrap() in a function that returns Result discards the error. The ? operator would propagate the error to the caller with proper context and stack trace.",
        acceptanceCriteria: [
          "Replace .unwrap() with the ? operator in Result-returning functions.",
          "Use .map_err(|e| ...)? to add context before propagating.",
          "Use anyhow or thiserror for ergonomic error handling.",
        ],
        evidence: evidence(hits, "rs-004"),
      });
    }
  }

  // DK-RS-005: Raw pointer dereference
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const derefPatterns = content.match(/\*\s*(?:self\.)?\w+\s*(?:as\s+\*|\)|;|\s*\.|\s*\+)/g) ?? [];
      // Filter: only flag inside unsafe blocks
      const hasUnsafe = /\bunsafe\s*\{/.test(content);
      if (!hasUnsafe) continue;
      // Count raw pointer operations
      const rawPtrOps = content.match(/\*const\s+\w+|\*mut\s+\w+/g) ?? [];
      if (rawPtrOps.length > 0) {
        hits.set(file, [`${rawPtrOps.length} raw pointer type(s) declared in code with unsafe blocks`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-005",
        title: "Raw pointer dereference inside unsafe block",
        severity: "high",
        confidence: "low",
        missingControls: ["rawPointerSafety"],
        consequence: "Dereferencing raw pointers bypasses Rust's borrow checker and can cause use-after-free, null pointer dereference, or data races. All pointer dereferences must be carefully audited.",
        acceptanceCriteria: [
          "Wrap raw pointer operations in minimal unsafe blocks with SAFETY comments.",
          "Prefer safe abstractions (Box, Rc, Arc, references) over raw pointers.",
          "Test raw pointer code under Miri to catch undefined behavior.",
        ],
        evidence: evidence(hits, "rs-005"),
      });
    }
  }

  // DK-RS-006: Missing TLS — HTTP server without TLS
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Check for HTTP server setup
      if (!/(?:TcpListener|hyper::Server|actix_web::HttpServer|axum::serve|rocket::build|warp::serve)/.test(content)) continue;
      // Check for TLS
      if (/(?:tls|ssl|https|rustls|native_tls|openssl)/i.test(content)) continue;
      hits.set(file, ["HTTP server configured without TLS (plaintext HTTP only)"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-006",
        title: "Missing TLS configuration on HTTP server",
        severity: "high",
        confidence: "low",
        missingControls: ["tlsEncryption"],
        consequence: "An HTTP server without TLS transmits all data in plaintext, including authentication credentials, session tokens, and sensitive user data. This is trivially intercepted on any network.",
        acceptanceCriteria: [
          "Configure TLS with rustls or native-tls for all production servers.",
          "Redirect HTTP to HTTPS (301 redirect).",
          "Use HTTPS-only cookies and HSTS headers.",
        ],
        evidence: evidence(hits, "rs-006"),
      });
    }
  }

  // DK-RS-007: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /(?:let|const)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*(?::\s*\w+\s*)?=\s*"([^"]{16,})"/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret in variable (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-007",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code are trivially extracted from repositories or compiled binaries. This leads to credential compromise and unauthorized access.",
        acceptanceCriteria: [
          "Load secrets from environment variables: std::env::var(\"API_TOKEN\").",
          "Use a secret manager (Vault, AWS SSM) for production secrets.",
          "Never commit secrets to source control.",
        ],
        evidence: evidence(hits, "rs-007"),
      });
    }
  }

  // DK-RS-008: Missing request timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // reqwest::Client::new() without timeout
      if (/reqwest::Client::new\(\)/.test(content) && !/\.timeout\(/.test(content)) {
        matches.push("reqwest::Client::new() without timeout configured");
      }
      // hyper server without timeout
      if (/hyper::Server/.test(content) && !/tcp_keepalive|http1_keep_alive|\.timeout/.test(content)) {
        matches.push("hyper server without connection timeout");
      }
      // actix-web without timeout
      if (/actix_web::HttpServer/.test(content) && !/\.client_timeout|\.client_disconnect|\.keep_alive/.test(content)) {
        matches.push("actix-web server without explicit timeout configuration");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-008",
        title: "Missing request timeout on HTTP client or server",
        severity: "medium",
        confidence: "medium",
        missingControls: ["requestTimeout"],
        consequence: "HTTP clients or servers without timeouts can hang indefinitely on slow responses, exhausting connection pools and memory. This is a common vector for denial-of-service.",
        acceptanceCriteria: [
          "Configure timeout on reqwest::Client: Client::builder().timeout(Duration::from_secs(30)).",
          "Set connection and request timeouts on HTTP servers.",
          "Use tokio::time::timeout for individual async operations.",
        ],
        evidence: evidence(hits, "rs-008"),
      });
    }
  }

  // DK-RS-009: Panic in FFI — extern "C" functions containing panic or unwrap
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/extern\s+"C"/.test(content)) continue;
      const matches: string[] = [];
      // Find extern "C" functions and check for panicking operations
      const externFnRe = /extern\s+"C"\s+fn\s+(\w+)[^{]*\{([\s\S]*?)\n\}/g;
      for (const m of content.matchAll(externFnRe)) {
        const fnName = m[1];
        const body = m[2];
        if (/\.unwrap\(\)/.test(body)) {
          matches.push(`extern "C" fn ${fnName} contains .unwrap() — will abort on panic`);
        }
        if (/panic!\s*\(/.test(body)) {
          matches.push(`extern "C" fn ${fnName} contains panic!() — will abort the process`);
        }
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-009",
        title: "Panic in FFI: extern C function with unwrap/panic",
        severity: "blocker",
        confidence: "high",
        missingControls: ["ffiPanicSafety"],
        consequence: "A panic crossing an FFI boundary causes undefined behavior in C callers. By default it unwinds into C stack frames, corrupting memory or aborting the process.",
        acceptanceCriteria: [
          "Wrap extern \"C\" function body in std::panic::catch_unwind().",
          "Replace .unwrap() with explicit error handling or .unwrap_or() in FFI functions.",
          "Never use panic!() in FFI functions — return error codes instead.",
        ],
        evidence: evidence(hits, "rs-009"),
      });
    }
  }

  // DK-RS-010: Missing input validation — route handlers without validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Check for web framework route handlers
      if (!/#\[(?:get|post|put|delete|patch|route)\s*\(/.test(content)) continue;
      // Check for input validation
      if (/(?:Validate|validate|validator|valid|sanitize|check)/i.test(content)) continue;
      // Check for serde deserialization (some validation via struct)
      if (/serde::Deserialize/.test(content) && /validator/.test(content)) continue;
      hits.set(file, ["Route handlers without input validation (no Validate/validator usage)"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-010",
        title: "Missing input validation in route handlers",
        severity: "medium",
        confidence: "low",
        missingControls: ["inputValidation"],
        consequence: "Route handlers that accept request data without validation are vulnerable to injection attacks, data corruption, and unexpected behavior from malformed input.",
        acceptanceCriteria: [
          "Add Validate derive macro and #[validate(...)] attributes to request structs.",
          "Validate all user input before processing — check lengths, ranges, and formats.",
          "Return 400 Bad Request for invalid input with descriptive error messages.",
        ],
        evidence: evidence(hits, "rs-010"),
      });
    }
  }

  // DK-RS-011: Missing TLS — http:// in reqwest URLs
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // reqwest with http:// URLs
      const httpUrls = content.match(/(?:reqwest::(?:get|Client|Url)|url::Url::parse)\s*\(\s*"http:\/\//g) ?? [];
      for (const m of httpUrls) {
        if (/localhost|127\.0\.0\.1|0\.0\.0\.0|::1/.test(m)) continue;
        matches.push(`insecure HTTP URL in HTTP client: ${m.trim().slice(0, 60)}`);
      }
      // General http:// URLs in request context
      const reqHttpUrls = content.match(/"(http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0|::1)[^"]+)"/g) ?? [];
      if (reqHttpUrls.length > 0 && /reqwest|hyper|surf|ureq|attohttpc/.test(content)) {
        matches.push(`${reqHttpUrls.length} HTTP (non-HTTPS) URL(s) in HTTP client code`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-011",
        title: "Missing TLS: HTTP (plaintext) URLs in HTTP client",
        severity: "high",
        confidence: "medium",
        missingControls: ["httpsEnforcement"],
        consequence: "Using HTTP instead of HTTPS in HTTP client requests transmits all data in plaintext, including credentials and tokens. This is trivially intercepted on any network.",
        acceptanceCriteria: [
          "Use HTTPS for all external API calls and URLs.",
          "Configure HTTP clients to reject non-HTTPS URLs.",
          "Add TLS certificate pinning for sensitive endpoints.",
        ],
        evidence: evidence(hits, "rs-011"),
      });
    }
  }

  // DK-RS-012: Log injection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // tracing/log macros with user input
      const logWithReq = content.match(/(?:info!|warn!|error!|debug!|trace!|log::\w!)\s*\([^)]*(?:req\.|request\.|input\.|params\.|header)/g) ?? [];
      for (const m of logWithReq) {
        if (/sanitize|escape|clean|strip/.test(content)) continue;
        matches.push(`log macro with request data: ${m.trim().slice(0, 60)}`);
      }
      // println/format with user input
      const printWithReq = content.match(/(?:println!|eprintln!|format!)\s*\([^)]*(?:req\.|request\.|input\.|params\.)/g) ?? [];
      for (const m of printWithReq) {
        matches.push(`print macro with request data: ${m.trim().slice(0, 60)}`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-012",
        title: "Log injection: user input in log/tracing macros without sanitization",
        severity: "high",
        confidence: "low",
        missingControls: ["logSanitization"],
        consequence: "Injecting unsanitized user input into log macros enables log injection attacks. Attackers can forge log entries, inject malicious content into log analysis tools, or exploit log parsing vulnerabilities.",
        acceptanceCriteria: [
          "Sanitize user input before logging — strip newlines, control characters, and ANSI sequences.",
          "Use structured logging fields with typed values instead of string interpolation.",
          "Use tracing crate with structured fields: tracing::info!(user = %sanitized_input, \"message\").",
        ],
        evidence: evidence(hits, "rs-012"),
      });
    }
  }

  // DK-RS-013: SSRF via user-controlled URL
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // reqwest::get with user input
      if (/reqwest::(?:get|Client)\s*\(\s*[^)]*(?:input|param|url|query|form|body|request)/i.test(content)) {
        if (!/allowed_hosts|whitelist|validate_url|safe_url|is_allowed/.test(content)) {
          matches.push("reqwest request with potentially user-controlled URL without host validation");
        }
      }
      // Hyper client with user input
      if (/hyper::(?:Client|Request)\s*::.*(?:input|param|url)/i.test(content)) {
        if (!/allowed_hosts|whitelist|validate_url/.test(content)) {
          matches.push("hyper request with potentially user-controlled URL without host validation");
        }
      }
      // General pattern: HTTP request constructed from user input
      if (/(?:reqwest|hyper|surf|ureq)\b/.test(content) && /(?:input|param|url|query|redirect)\b/.test(content)) {
        const userInputUrl = content.match(/(?:reqwest::(?:get|post)|Client::new\(\)\.(?:get|post))\s*\(\s*(?:&?\w+|(?:format!|"")\s*\()/g) ?? [];
        if (userInputUrl.length > 0 && !/allowed_hosts|whitelist|validate_url|safe_url/.test(content)) {
          matches.push(`HTTP request with dynamic URL: ${(userInputUrl[0] ?? "").trim().slice(0, 60)}`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-013",
        title: "SSRF via user-controlled URL",
        severity: "blocker",
        confidence: "low",
        missingControls: ["ssrfPrevention"],
        consequence: "Server-Side Request Forgery (SSRF) allows attackers to make the server send requests to internal services, cloud metadata endpoints, or other restricted resources. This can expose internal infrastructure and credentials.",
        acceptanceCriteria: [
          "Validate and restrict target URLs against an allowlist of trusted hosts.",
          "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x).",
          "Use a DNS resolver that validates resolved IPs against allowed ranges.",
        ],
        evidence: evidence(hits, "rs-013"),
      });
    }
  }

  // DK-RS-014: Open redirect
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // Redirect with user-controlled Location header
      const redirectPatterns = [
        /(?:header|Header)\s*\(\s*["']Location["']\s*,\s*(?:req|request|input|params|query)/gi,
        /(?:StatusCode|status)\s*::\s*(?:FOUND|MOVED_PERMANENTLY|TEMPORARY_REDIRECT|SEE_OTHER).*Location/gi,
        /redirect\s*\(\s*(?:req|request|input|params|query|form)/gi,
      ];
      for (const pat of redirectPatterns) {
        for (const m of content.matchAll(pat)) {
          if (/allowed_hosts|whitelist|validate_redirect|safe_redirect|is_allowed/.test(content)) continue;
          matches.push(`redirect with user-controlled URL: ${m[0].trim().slice(0, 60)}`);
        }
      }
      // Check for redirect_from_request patterns
      if (/(?:redirect|Redirect)\s*\(\s*(?:&?\w*url|&?\w*redirect|&?\w*return|&?\w*next)/i.test(content)) {
        if (!/allowed_hosts|whitelist|validate_redirect|safe_redirect/.test(content)) {
          matches.push("redirect with user-provided destination without validation");
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-014",
        title: "Open redirect: user-controlled redirect destination",
        severity: "high",
        confidence: "low",
        missingControls: ["redirectValidation"],
        consequence: "An open redirect vulnerability allows an attacker to redirect users to a malicious site via a crafted URL parameter, enabling phishing attacks, OAuth token theft, and credential harvesting.",
        acceptanceCriteria: [
          "Validate redirect URLs against an allowlist of trusted hosts.",
          "Only allow relative redirects (starting with /) — reject absolute URLs with scheme.",
          "Never redirect to user-provided URLs without strict validation.",
        ],
        evidence: evidence(hits, "rs-014"),
      });
    }
  }

  // DK-RS-015: Missing CORS configuration
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Check for web server setup
      if (!/(?:actix_web::HttpServer|axum::Router|warp::path|rocket::build|tide::new|poem::Route)/.test(content)) continue;
      // Check for CORS configuration
      if (/cors|Cors|CORS|Access-Control-Allow-Origin|CorsLayer|CorsMiddleware/.test(content)) continue;
      hits.set(file, ["Web server configured without CORS headers/layer"]);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-RS-015",
        title: "Missing CORS configuration on web server",
        severity: "high",
        confidence: "low",
        missingControls: ["corsConfiguration"],
        consequence: "Without CORS configuration, the server either rejects all cross-origin requests (breaking legitimate clients) or relies on browser defaults, which may not match the intended access policy. This can cause frontend integration failures.",
        acceptanceCriteria: [
          "Add CORS middleware with explicit allowed origins (not wildcard *).",
          "Configure allowed methods, headers, and credentials as needed.",
          "Use tower-http CorsLayer or framework-specific CORS middleware.",
        ],
        evidence: evidence(hits, "rs-015"),
      });
    }
  }

  return findings;
}
