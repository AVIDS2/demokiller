import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

export async function securityHardeningFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".java", ".kt", ".rb"]);
  if (files.length === 0) return [];

  const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|testdata|samples|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party)(?:[\\/]|$)/i;

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (FIXTURE_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  function evidence(hits: Map<string, string[]>, ruleId: string) {
    return [...hits.entries()].map(([file, signals]) => ({
      id: `${ruleId}-${file}`,
      detector: "pattern-match",
      location: { path: file },
      controls: [],
      signals
    }));
  }

  // DK-SEC-001: No security headers middleware (Helmet / secure headers)
  const routePresence = /\b(?:app\.(?:get|post|put|delete|patch|use|listen)|router\.(?:get|post|put|delete|patch|use))\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping)\b|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(|func\s+\w+(?:Handler|Controller)\s*\(|r\.GET\(|r\.POST\(|mux\.HandleFunc|http\.HandleFunc|HandleFunc\s*\(/;
  const securityHeadersPresent = /\b(?:helmet|secureHeaders|securityHeaders|X-Content-Type-Options|X-Frame-Options|X-XSS-Protection|Strict-Transport-Security|Content-Security-Policy)\b|cors\s*\(/;
  const ANALYSIS_INDICATORS_RE = /walkSourceFiles|walkPythonFiles|FUNC_PATTERNS|ROUTE_PATTERNS|extractFunctions|CallGraph|buildCallGraph|codegraph|detectNoAllowlist|detectUnsafeFs|routePresence/i;
  const missingHeadersFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!routePresence.test(content)) continue;
    if (securityHeadersPresent.test(content)) continue;
    const routeMatches = content.match(new RegExp(routePresence.source, "g")) ?? [];
    missingHeadersFiles.set(file, [`${routeMatches.length} route(s) found but no security headers middleware`]);
  }
  if (missingHeadersFiles.size > 0) {
    findings.push({
      ruleId: "DK-SEC-001",
      title: "No security headers middleware detected",
      severity: "high",
      confidence: "high",
      missingControls: ["securityHeaders"],
      consequence: "Without security headers, your app is vulnerable to clickjacking, MIME-type sniffing attacks, and reflected XSS. Production deployments need defense-in-depth headers on every response.",
      acceptanceCriteria: [
        "Add helmet() middleware for Express/Fastify apps.",
        "Set X-Content-Type-Options: nosniff on all responses.",
        "Set X-Frame-Options: DENY or SAMEORIGIN.",
        "Set Strict-Transport-Security for HTTPS enforcement.",
      ],
      evidence: evidence(missingHeadersFiles, "sec-001"),
    });
  }

  // DK-SEC-002: No HTTPS enforcement / HSTS
  const httpListen = /\b(?:listen\s*\(\s*[^)]*,\s*80\b|listen\s*\(\s*80\b|:\s*80\b|:80["'])/;
  const httpsRedirect = /\b(?:redirect.*https|301.*https|302.*https|secure\s*:\s*true|https.*redirect|hsts|Strict-Transport-Security)\b/i;
  const insecureCookie = /\b(?:secure\s*:\s*false|httpOnly\s*:\s*false)\b/i;
  const noHttpsFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    const hits: string[] = [];
    if (httpListen.test(content) && !httpsRedirect.test(content)) {
      hits.push("listens on HTTP port 80 without HTTPS redirect");
    }
    if (insecureCookie.test(content)) {
      const cookieMatches = content.match(new RegExp(insecureCookie.source, "gi")) ?? [];
      hits.push(...cookieMatches.map(m => `insecure cookie config: ${m.trim()}`));
    }
    if (hits.length > 0) noHttpsFiles.set(file, hits);
  }
  if (noHttpsFiles.size > 0) {
    findings.push({
      ruleId: "DK-SEC-002",
      title: "No HTTPS enforcement or HSTS detected",
      severity: "high",
      confidence: "medium",
      missingControls: ["httpsEnforcement"],
      consequence: "HTTP traffic can be intercepted by anyone on the network. Credentials, session tokens, and sensitive data travel in plaintext. Without HSTS, users can be tricked into using HTTP even when HTTPS is available.",
      acceptanceCriteria: [
        "Redirect all HTTP traffic to HTTPS.",
        "Set Strict-Transport-Security header with max-age of at least 1 year.",
        "Set cookies with secure: true flag.",
        "Never listen on port 80 without an HTTPS redirect.",
      ],
      evidence: evidence(noHttpsFiles, "sec-002"),
    });
  }

  // DK-SEC-003: Weak JWT secret or 'none' algorithm
  const jwtUsage = /\b(?:jsonwebtoken|jose|jwt\.sign|jwt\.verify|JwtBearer|pyjwt|jwt\.encode|jwt\.decode)\b/;
  const noneAlgorithm = /\balgorithm(?:s)?\s*[:=].*['"`]none['"`]/i;
  const shortSecret = /secret\s*[=:]\s*['"`](.{1,8})['"`]/;
  const insecureEnvFallback = /process\.env\.JWT_SECRET\s*\|\|.*['"`]/;
  const weakJwtFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (!jwtUsage.test(content)) continue;
    // Strong patterns — skip if present
    if (/\b(?:RS256|ES256|EdDSA|algorithms?\s*[:=]\s*\[|kid|jku)\b/.test(content)) continue;
    const hits: string[] = [];
    if (noneAlgorithm.test(content)) hits.push("accepts 'none' algorithm — tokens can be forged without a secret");
    if (shortSecret.test(content)) {
      const m = content.match(shortSecret);
      hits.push(`JWT secret too short (${m![1].length} chars): "${m![1]}"`);
    }
    if (insecureEnvFallback.test(content)) hits.push("JWT_SECRET env var with insecure fallback default");
    if (hits.length > 0) weakJwtFiles.set(file, hits);
  }
  if (weakJwtFiles.size > 0) {
    findings.push({
      ruleId: "DK-SEC-003",
      title: "Weak JWT secret or 'none' algorithm detected",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["jwtSecurity"],
      consequence: "A weak JWT secret allows attackers to forge tokens and impersonate any user. The 'none' algorithm bypass lets attackers create valid-looking tokens without any secret.",
      acceptanceCriteria: [
        "Use RS256 or ES256 instead of HS256 when possible.",
        "JWT secret must be at least 256 bits (32 characters).",
        "Never accept 'none' as a valid algorithm.",
        "Load JWT secret from environment variables, never hardcode.",
      ],
      evidence: evidence(weakJwtFiles, "sec-003"),
    });
  }

  // DK-SEC-004: SQL query built with string concatenation (not parameterized)
  const sqlConcatPatterns: { lang: string; pattern: RegExp }[] = [
    // JS/TS: template literals
    { lang: "js/template", pattern: /`[^`]*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^`]*\$\{/gi },
    // JS/TS: string concatenation with + operator
    { lang: "js/concat", pattern: /(["'`])(?:[^"'`])*(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"'`]*\1\s*\+/gi },
    // Python: % formatting
    { lang: "py/%", pattern: /(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"'"]*%s/gi },
    // Python: .format()
    { lang: "py/format", pattern: /["'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"']*["']\s*\.format\s*\(/gi },
    // Python: f-string
    { lang: "py/fstring", pattern: /f["'](?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"']*\{/gi },
    // Go: string concatenation with +
    { lang: "go/concat", pattern: /"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"]*"\s*\+/gi },
    // Go: fmt.Sprintf with SQL
    { lang: "go/sprintf", pattern: /fmt\.Sprintf\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)/gi },
    // Java: string concatenation
    { lang: "java/concat", pattern: /"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)[^"]*"\s*\+/gi },
    // Java: String.format with SQL
    { lang: "java/format", pattern: /String\.format\s*\(\s*"(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN)/gi },
  ];
  const META_LINE_RE = /(?:new RegExp|RegExp\(|\/(?:SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN).*\/[gimsuy]|re\.compile|\.test\(|\.match\(|\.exec\(|Pattern\.compile)/i;
  const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;
  const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;
  const sqlConcatFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    // Skip report utilities, rule files, and taint analysis — they contain SQL keywords in detection patterns, not real queries
    if (REPORT_UTIL_RE.test(file)) continue;
    const lines = content.split(/\r?\n/);
    const hits: string[] = [];
    for (const { lang, pattern } of sqlConcatPatterns) {
      const regex = new RegExp(pattern.source, pattern.flags);
      let match: RegExpExecArray | null;
      while ((match = regex.exec(content)) !== null) {
        // Skip matches inside regex literals or detection code (meta-code checking for SQL patterns)
        const matchLine = content.slice(0, match.index).split(/\r?\n/).length;
        const lineText = lines[matchLine - 1] ?? "";
        if (META_LINE_RE.test(lineText)) continue;
        hits.push(`[${lang}] ${match[0].slice(0, 80)}`);
        if (hits.length >= 5) break;
      }
      if (hits.length >= 5) break;
    }
    if (hits.length > 0) sqlConcatFiles.set(file, hits.slice(0, 10));
  }
  if (sqlConcatFiles.size > 0) {
    findings.push({
      ruleId: "DK-SEC-004",
      title: "SQL query built with string concatenation instead of parameterized queries",
      severity: "blocker",
      confidence: "high",
      missingControls: ["parameterizedQueries"],
      consequence: "String-built SQL queries are the #1 cause of SQL injection. Even 'internal' queries become exploitable when requirements change and user input flows in later.",
      acceptanceCriteria: [
        "Use parameterized queries (prepared statements) for all SQL.",
        "Use ORM query builders that handle parameterization.",
        "Never interpolate user input into SQL strings.",
      ],
      evidence: evidence(sqlConcatFiles, "sec-004"),
    });
  }

  // ── DK-XSS-001: User input rendered without escaping ──────────────
  const XSS_ROUTE_RE = /\b(?:app\.(?:get|post|put|delete|patch|use|listen)|router\.(?:get|post|put|delete|patch|use))\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping)\b|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(|func\s+\w+(?:Handler|Controller)\s*\(|r\.GET\(|r\.POST\(|mux\.HandleFunc|http\.HandleFunc|HandleFunc\s*\(/;
  const XSS_PATTERNS: { lang: string; pattern: RegExp }[] = [
    { lang: "js/innerHTML",     pattern: /\.innerHTML\s*=\s*(?!["']""|['']'')/ },
    { lang: "js/dangerously",   pattern: /dangerouslySetInnerHTML\s*[=:]\s*\{/ },
    { lang: "js/resSendBody",   pattern: /res\.(?:send|write)\s*\(\s*(?:req\.(?:body|query|params)|user(?:Input|Content|Data))/ },
    { lang: "py/safe",          pattern: /\|\s*safe\b/ },
    { lang: "jsx/raw",          pattern: /\{\!\![\s\S]*?\!\!\}/ },
    { lang: "vue/v-html",       pattern: /\bv-html\s*=/ },
  ];
  const xssFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (REPORT_UTIL_RE.test(file)) continue;
    if (EXCLUDE_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!XSS_ROUTE_RE.test(content)) continue;
    const hits: string[] = [];
    for (const { lang, pattern } of XSS_PATTERNS) {
      if (pattern.test(content)) {
        hits.push(`[${lang}] matched`);
      }
    }
    if (hits.length > 0) xssFiles.set(file, hits);
  }
  if (xssFiles.size > 0) {
    findings.push({
      ruleId: "DK-XSS-001",
      title: "User input rendered without escaping",
      severity: "blocker",
      confidence: "high",
      missingControls: ["outputEscaping"],
      consequence: "Rendering user input without escaping allows attackers to inject arbitrary HTML/JavaScript, enabling session hijacking, credential theft, and account takeover.",
      acceptanceCriteria: [
        "Use textContent instead of innerHTML for user-supplied content.",
        "Remove dangerouslySetInnerHTML or ensure content is sanitized first.",
        "Use template engine auto-escaping (e.g., Jinja2 without |safe).",
        "For Vue, use v-text instead of v-html for user data.",
      ],
      evidence: evidence(xssFiles, "xss-001"),
    });
  }

  // ── DK-CSRF-001: State-changing endpoints without CSRF protection ─
  const CSRF_MIDDLEWARE = /\b(?:csrf|csurf|csrfProtect|csrfProtection|CsrfProtect|doubleSubmit|synchronizer[_-]?token|_csrf|csrf_token|X-CSRF-Token)\b/i;
  const STATE_CHANGING_ROUTE = /\b(?:app|router)\.(?:post|put|delete|patch)\s*\(|@(?:Post|Put|Delete|Patch)\b|\.POST\(|\.PUT\(|\.DELETE\(|\.PATCH\(/i;
  const CSRF_FILES = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (REPORT_UTIL_RE.test(file)) continue;
    if (EXCLUDE_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    // Only fire if file has state-changing routes
    if (!STATE_CHANGING_ROUTE.test(content)) continue;
    // Skip if CSRF protection already present
    if (CSRF_MIDDLEWARE.test(content)) continue;
    const routeCount = (content.match(new RegExp(STATE_CHANGING_ROUTE.source, "gi")) ?? []).length;
    CSRF_FILES.set(file, [`${routeCount} state-changing route(s) without CSRF middleware`]);
  }
  if (CSRF_FILES.size > 0) {
    findings.push({
      ruleId: "DK-CSRF-001",
      title: "State-changing endpoints without CSRF protection",
      severity: "high",
      confidence: "medium",
      missingControls: ["csrfProtection"],
      consequence: "Without CSRF protection, attackers can trick authenticated users into submitting malicious requests, leading to unauthorized actions such as data modification or account compromise.",
      acceptanceCriteria: [
        "Add csurf or csrf-csrf middleware for Express apps.",
        "Use Django's CsrfViewMiddleware (enabled by default).",
        "Include synchronizer token pattern in all state-changing forms.",
        "Verify Origin/Referer headers for state-changing API requests.",
      ],
      evidence: evidence(CSRF_FILES, "csrf-001"),
    });
  }

  // ── DK-REDIRECT-001: Open redirect via user-controlled URL ───────
  const REDIRECT_FROM_INPUT: { lang: string; pattern: RegExp }[] = [
    { lang: "js/res.redirect",  pattern: /res\.(?:redirect|location)\s*\(\s*(?:req\.(?:query|body|params|headers))/ },
    { lang: "py/redirect",      pattern: /redirect\s*\(\s*(?:request\.(?:args|form|GET|POST)\.get|request\.(?:args|form|GET|POST)\[)/ },
    { lang: "js/location-header", pattern: /res\.(?:set|header)\s*\(\s*['"]Location['"]\s*,\s*(?:req\.)/ },
    { lang: "py/location-header", pattern: /\[.Location.\]\s*=\s*(?:request\.)/ },
  ];
  const SAFE_REDIRECT = /\b(?:url_for|safe_redirect|is_safe_url|allowed_redirect|redirect_whitelist|ALLOWED_HOSTS|url_has_allowed_host|validate_redirect)\b/i;
  const REDIRECT_ROUTE_RE = /\b(?:app\.(?:get|post|put|delete|patch|use|listen)|router\.(?:get|post|put|delete|patch|use))\s*\(|@(?:app|router|bp)\.(?:route|get|post|put|delete)\b|@(?:Get|Post|Put|Delete|Patch|RequestMapping)\b|\.GET\(|\.POST\(|\.PUT\(|\.DELETE\(/;
  const redirectFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (REPORT_UTIL_RE.test(file)) continue;
    if (EXCLUDE_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!REDIRECT_ROUTE_RE.test(content)) continue;
    if (SAFE_REDIRECT.test(content)) continue;
    const hits: string[] = [];
    for (const { lang, pattern } of REDIRECT_FROM_INPUT) {
      if (pattern.test(content)) hits.push(`[${lang}] matched`);
    }
    if (hits.length > 0) redirectFiles.set(file, hits);
  }
  if (redirectFiles.size > 0) {
    findings.push({
      ruleId: "DK-REDIRECT-001",
      title: "Open redirect via user-controlled URL",
      severity: "high",
      confidence: "high",
      missingControls: ["redirectValidation"],
      consequence: "Attacker-controlled redirect URLs enable phishing attacks by redirecting users from your legitimate domain to malicious sites, bypassing security warnings.",
      acceptanceCriteria: [
        "Validate redirect URLs against a whitelist of allowed domains.",
        "Only allow relative redirects (starting with /) for internal URLs.",
        "Use framework-provided safe redirect helpers (e.g., url_for).",
        "Never pass raw user input directly to redirect responses.",
      ],
      evidence: evidence(redirectFiles, "redirect-001"),
    });
  }

  // ── DK-RATE-001: No rate limiting on public endpoints ─────────────
  const RATE_LIMIT_MIDDLEWARE = /\b(?:expressRateLimit|express-rate-limit|rateLimit|rate[_-]?limit|RateLimit|RateLimiter|flask[-_]?limiter|Limiter|throttle|Throttle|Throttler|@nestjs\/throttler|slowDown|slow[-_]?down|express-slow-down)\b/i;
  const RATE_LIMIT_FILES = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (REPORT_UTIL_RE.test(file)) continue;
    if (EXCLUDE_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!XSS_ROUTE_RE.test(content)) continue;
    // Only fire for apps with 3+ routes
    const routeCount = (content.match(new RegExp(XSS_ROUTE_RE.source, "gi")) ?? []).length;
    if (routeCount < 3) continue;
    if (RATE_LIMIT_MIDDLEWARE.test(content)) continue;
    RATE_LIMIT_FILES.set(file, [`${routeCount} route(s) without rate limiting middleware`]);
  }
  if (RATE_LIMIT_FILES.size > 0) {
    findings.push({
      ruleId: "DK-RATE-001",
      title: "No rate limiting on public endpoints",
      severity: "high",
      confidence: "medium",
      missingControls: ["rateLimiting"],
      consequence: "Without rate limiting, attackers can brute-force credentials, exhaust server resources, and perform denial-of-service attacks on your endpoints.",
      acceptanceCriteria: [
        "Add express-rate-limit or equivalent middleware globally.",
        "Apply stricter limits on authentication endpoints (login, register).",
        "Configure per-IP or per-user rate limits based on your architecture.",
        "Return 429 Too Many Requests with Retry-After header.",
      ],
      evidence: evidence(RATE_LIMIT_FILES, "rate-001"),
    });
  }

  // ── DK-SANITIZE-001: User input rendered to DOM/HTML without sanitization ─
  const SANITIZE_SAFE = /\b(?:DOMPurify|sanitize[_-]?html|XSS\s*\(|bleach|nh3|sanitize[_-]?css|cure53|jsdom\.JSDOM|xss[_-]?filter|xss-filters)\b/i;
  const UNSAFE_DOM_PATTERNS: { lang: string; pattern: RegExp }[] = [
    { lang: "js/innerHTML-assign",   pattern: /\.\s*innerHTML\s*=\s*(?!["']""|['']'')/ },
    { lang: "js/jQuery-html",        pattern: /\$\s*\([^)]*\)\s*\.html\s*\(/ },
    { lang: "js/resSendTemplate",    pattern: /res\.(?:send|write)\s*\(\s*`/ },
    { lang: "py/markupSafe",         pattern: /Markup\s*\(\s*(?!["']["'])/ },
  ];
  const sanitizeFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (REPORT_UTIL_RE.test(file)) continue;
    if (EXCLUDE_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!XSS_ROUTE_RE.test(content)) continue;
    if (SANITIZE_SAFE.test(content)) continue;
    const hits: string[] = [];
    for (const { lang, pattern } of UNSAFE_DOM_PATTERNS) {
      if (pattern.test(content)) hits.push(`[${lang}] matched`);
    }
    if (hits.length > 0) sanitizeFiles.set(file, hits);
  }
  if (sanitizeFiles.size > 0) {
    findings.push({
      ruleId: "DK-SANITIZE-001",
      title: "User input rendered to DOM/HTML without sanitization",
      severity: "high",
      confidence: "medium",
      missingControls: ["inputSanitization"],
      consequence: "Rendering unsanitized user input to the DOM allows XSS injection, enabling attackers to execute arbitrary JavaScript in users' browsers.",
      acceptanceCriteria: [
        "Use DOMPurify.sanitize() before setting innerHTML.",
        "Prefer textContent over innerHTML for user-supplied data.",
        "Use framework auto-escaping (React JSX, Vue template interpolation).",
        "Sanitize HTML server-side before sending to the client.",
      ],
      evidence: evidence(sanitizeFiles, "sanitize-001"),
    });
  }

  return findings;
}
