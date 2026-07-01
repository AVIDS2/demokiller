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

export async function javaFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".java", ".kt", ".kts"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-JAVA-001: SQL injection via string concatenation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // "SELECT " + var or "INSERT " + var patterns
      const sqlConcat = /"(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM|JOIN)\s+[^"]*"\s*\+\s*\w+/gi;
      for (const m of content.matchAll(sqlConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with string concatenation`);
      }
      // Statement.execute("SELECT " + userInput)
      const stmtConcat = /(?:execute|executeQuery|executeUpdate)\s*\(\s*"[^"]*"\s*\+/gi;
      for (const m of content.matchAll(stmtConcat)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL statement with concatenation`);
      }
      // String.format used in SQL context
      const fmtSQL = /(?:execute|executeQuery|executeUpdate)\s*\(\s*(?:String\.format)\s*\(/gi;
      for (const m of content.matchAll(fmtSQL)) {
        matches.push(`${m[0].trim().slice(0, 60)} — SQL with String.format`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-001",
        title: "SQL injection: query built via string concatenation",
        severity: "blocker",
        confidence: "high",
        missingControls: ["parameterizedQueries"],
        consequence: "Building SQL queries via string concatenation allows SQL injection. An attacker can manipulate query logic to read, modify, or delete arbitrary data from the database.",
        acceptanceCriteria: [
          "Use PreparedStatement with parameterized queries: SELECT * FROM users WHERE id = ?",
          "Never concatenate user input into SQL strings.",
          "Use JPA/Hibernate criteria API or MyBatis parameterized mappings for dynamic queries.",
        ],
        evidence: evidence(hits, "java-001"),
      });
    }
  }

  // DK-JAVA-002: Empty catch block
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // catch (Exception e) { } — empty catch blocks
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
        ruleId: "DK-JAVA-002",
        title: "Empty catch block: exception silently swallowed",
        severity: "high",
        confidence: "high",
        missingControls: ["exceptionHandling"],
        consequence: "Empty catch blocks silently swallow exceptions, hiding bugs and security issues. Failed operations (DB queries, auth checks, network calls) appear to succeed when their errors are ignored.",
        acceptanceCriteria: [
          "Log the exception with sufficient context for debugging.",
          "Rethrow as a more specific exception if the caller should handle it.",
          "At minimum, add a comment explaining why the exception is intentionally ignored.",
        ],
        evidence: evidence(hits, "java-002"),
      });
    }
  }

  // DK-JAVA-003: Unsafe deserialization
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      if (/ObjectInputStream\s*\(/.test(content) || /\.readObject\s*\(/.test(content)) {
        matches.push("Java native deserialization via ObjectInputStream.readObject()");
      }
      if (/XMLDecoder/.test(content)) {
        matches.push("XMLDecoder used — trivially exploitable deserialization");
      }
      if (/XStream/.test(content) && !/XStream\.setupDefaultSecurity/.test(content)) {
        matches.push("XStream without security setup — vulnerable to deserialization attacks");
      }
      if (/Kryo\s*\(/.test(content) && !/\.setRegistrationRequired\s*\(\s*true/.test(content)) {
        matches.push("Kryo without registration required — allows arbitrary class instantiation");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-003",
        title: "Unsafe deserialization: Java native deserialization or XMLDecoder",
        severity: "blocker",
        confidence: "high",
        missingControls: ["safeDeserialization"],
        consequence: "Java native deserialization and XMLDecoder allow arbitrary code execution when processing untrusted input. This is one of the most exploited vulnerability classes in Java applications.",
        acceptanceCriteria: [
          "Never use ObjectInputStream with untrusted input — use JSON (Jackson/Gson) instead.",
          "Replace XMLDecoder with a safe XML parser (JAXB with whitelist).",
          "If XStream is required, call setupDefaultSecurity() and whitelist allowed classes.",
        ],
        evidence: evidence(hits, "java-003"),
      });
    }
  }

  // DK-JAVA-004: SSRF — user-controlled URL in HTTP client
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // new URL(userVar).openConnection()
      if (/new\s+URL\s*\(\s*\w+\s*\)\s*\.?\s*openConnection/.test(content)) {
        matches.push("new URL(variable).openConnection() — potential SSRF");
      }
      // HttpClient.send() with variable URL
      if (/HttpClient.*\.send\s*\(/.test(content) && /URI\.create\s*\(\s*\w+/.test(content)) {
        matches.push("HttpClient.send() with variable URI — potential SSRF");
      }
      // RestTemplate with variable URL
      if (/restTemplate\.\w+\(\s*\w+\s*\)/i.test(content)) {
        matches.push("RestTemplate with variable URL — potential SSRF");
      }
      // OkHttp with variable URL
      if (/new\s+Request\.Builder\(\)\s*\.url\s*\(\s*\w+/.test(content)) {
        matches.push("OkHttp Request.Builder().url(variable) — potential SSRF");
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-004",
        title: "Server-Side Request Forgery (SSRF): user-controlled URL in HTTP client",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["ssrfPrevention"],
        consequence: "Allowing user-controlled URLs in server-side HTTP requests enables SSRF attacks. Attackers can access internal services, cloud metadata endpoints (169.254.169.254), and private networks.",
        acceptanceCriteria: [
          "Validate and whitelist allowed URL schemes and hosts before making requests.",
          "Block requests to private IP ranges (10.x, 172.16-31.x, 192.168.x, 169.254.x).",
          "Use a URL allowlist or DNS-based validation for user-provided URLs.",
        ],
        evidence: evidence(hits, "java-004"),
      });
    }
  }

  // DK-JAVA-005: Missing CSRF protection
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Only check Spring Security config files
      if (!/@(?:Configuration|EnableWebSecurity|Controller|RestController)/.test(content)) continue;
      if (!/(?:@PostMapping|@PutMapping|@DeleteMapping|@PatchMapping|csrf|CsrfFilter)/i.test(content)) continue;
      // If it has @EnableWebSecurity but CSRF is disabled
      if (/@EnableWebSecurity/.test(content)) {
        if (/csrf\(\)\s*\.\s*disable\(\)/.test(content)) {
          hits.set(file, ["Spring Security CSRF protection explicitly disabled"]);
          continue;
        }
        // Has @EnableWebSecurity and CSRF is not disabled — likely OK
        continue;
      }
      // Has controllers but no @EnableWebSecurity
      if (/@(?:Controller|RestController)/.test(content) && !/@EnableWebSecurity/.test(content)) {
        // Only flag if there's a Spring Boot app (check for @SpringBootApplication elsewhere)
        hits.set(file, ["Spring controller without @EnableWebSecurity — CSRF protection may be missing"]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-005",
        title: "Missing CSRF protection in Spring application",
        severity: "high",
        confidence: "low",
        missingControls: ["csrfProtection"],
        consequence: "Without CSRF protection, an attacker can trick an authenticated user into performing state-changing operations (transfers, password changes, deletions) via a malicious website.",
        acceptanceCriteria: [
          "Enable CSRF protection: do not call csrf().disable() in SecurityFilterChain.",
          "Include CSRF token in all state-changing forms and AJAX requests.",
          "Use SameSite cookie attribute as an additional CSRF defense layer.",
        ],
        evidence: evidence(hits, "java-005"),
      });
    }
  }

  // DK-JAVA-006: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /(?:"((?:token|secret|password|apikey|api_key|passwd|credential))"\s*(?:=>|:)\s*"([^"]{16,})"|(?:String\s+\w*(?:token|secret|password|apikey|api_key|passwd|credential)\w*\s*=\s*"([^"]{16,})"))/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[2] ?? m[3] ?? "";
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check application.properties/yml for hardcoded values
      if (/(?:password|secret|token|api-key)\s*[:=]\s*[A-Za-z0-9+/=_\-]{20,}/.test(content)) {
        const propMatches = content.match(/(?:password|secret|token|api-key)\s*[:=]\s*([A-Za-z0-9+/=_\-]{20,})/gi) ?? [];
        for (const pm of propMatches) {
          const valMatch = pm.match(/[:=]\s*([A-Za-z0-9+/=_\-]{20,})/);
          if (valMatch && shannonEntropy(valMatch[1]) > 4.5) {
            matches.push(`hardcoded secret in config (entropy=${shannonEntropy(valMatch[1]).toFixed(1)})`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-006",
        title: "Hardcoded secret: high-entropy string in secret-named variable or config",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in source code or configuration files are trivially extracted from repositories, Docker images, or CI artifacts. This leads to credential compromise.",
        acceptanceCriteria: [
          "Load secrets from environment variables or a vault service.",
          "Use Spring Cloud Config, HashiCorp Vault, or AWS Secrets Manager.",
          "Never commit secrets to source control — use .gitignore and secret scanning.",
        ],
        evidence: evidence(hits, "java-006"),
      });
    }
  }

  // DK-JAVA-007: Missing request timeout
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // HttpClient without timeout
      if (/HttpClient\.newHttpClient\(\)/.test(content) && !/\.connectTimeout|\.timeout/.test(content)) {
        matches.push("HttpClient.newHttpClient() without timeout");
      }
      // OkHttpClient without timeout
      if (/new\s+OkHttpClient\s*\(\s*\)/.test(content) && !/\.connectTimeout|\.readTimeout|\.writeTimeout/.test(content)) {
        matches.push("OkHttpClient() without timeout configuration");
      }
      // RestTemplate without timeout
      if (/new\s+RestTemplate\s*\(\s*\)/.test(content) && !/setConnectTimeout|setReadTimeout|HttpComponentsClientHttpRequestFactory/.test(content)) {
        matches.push("RestTemplate() without timeout configuration");
      }
      // WebClient without timeout
      if (/WebClient\.create\(\)/.test(content) && !/HttpClient\.create.*\.option.*CONNECT_TIMEOUT/.test(content)) {
        matches.push("WebClient.create() without timeout");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-007",
        title: "Missing request timeout on HTTP client",
        severity: "medium",
        confidence: "medium",
        missingControls: ["httpClientTimeout"],
        consequence: "HTTP clients without timeouts can hang indefinitely on slow or unresponsive servers, tying up thread pool threads and eventually causing thread pool exhaustion and service outage.",
        acceptanceCriteria: [
          "Set connect and read timeouts on all HTTP clients.",
          "For OkHttp: new OkHttpClient.Builder().connectTimeout(10, SECONDS).build().",
          "For HttpClient: HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(10)).build().",
        ],
        evidence: evidence(hits, "java-007"),
      });
    }
  }

  // DK-JAVA-008: Thread safety issue — shared mutable state in @Service/@Component
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/@(?:Service|Component|Controller|RestController|Repository)/.test(content)) continue;
      const matches: string[] = [];
      // Mutable fields without synchronization
      const mutableField = /(?:private|protected)\s+(?!final\b)(?:static\s+)?(?:List|Map|Set|HashMap|ArrayList|HashSet|LinkedList|Queue|ConcurrentHashMap)\s*<[^>]*>\s+(\w+)/g;
      for (const m of content.matchAll(mutableField)) {
        const varName = m[1];
        // Check for synchronization around this field
        if (new RegExp(`synchronized\\b.*${varName}|@GuardedBy|volatile\\b.*${varName}|ConcurrentHashMap`).test(content)) continue;
        matches.push(`mutable ${m[0].trim().slice(0, 60)} in singleton bean without synchronization`);
      }
      // Non-final instance fields in singleton (Spring beans are singletons by default)
      const nonFinalField = /(?:private|protected)\s+(?!final\b)(?!static\b)\w+(?:<[^>]*>)?\s+(\w+)\s*[;=]/g;
      for (const m of content.matchAll(nonFinalField)) {
        const varName = m[1];
        // Skip simple types that are likely config
        if (/(?:int|long|boolean|String)\b/.test(m[0])) continue;
        if (/synchronized|volatile|AtomicInteger|AtomicLong|AtomicReference|ThreadLocal/.test(content)) continue;
        matches.push(`shared mutable state '${varName}' in singleton without synchronization`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-008",
        title: "Thread safety: shared mutable state in Spring singleton bean",
        severity: "high",
        confidence: "low",
        missingControls: ["threadSafety"],
        consequence: "Spring beans are singletons by default. Mutable instance fields are shared across all request threads, leading to data races, corrupted state, and intermittent bugs under load.",
        acceptanceCriteria: [
          "Make mutable fields thread-safe with ConcurrentHashMap, AtomicInteger, etc.",
          "Use @Scope(\"request\") or @Scope(\"prototype\") for stateful beans.",
          "Prefer stateless service design — pass state as method parameters.",
        ],
        evidence: evidence(hits, "java-008"),
      });
    }
  }

  // DK-JAVA-009: Missing @Valid on @RequestBody
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/@(?:PostMapping|PutMapping|PatchMapping)/.test(content)) continue;
      const matches: string[] = [];
      // @RequestBody without @Valid
      const requestBodyRe = /@RequestBody\s+(?!.*@Valid)(\w+(?:<[^>]*>)?)\s+(\w+)/g;
      for (const m of content.matchAll(requestBodyRe)) {
        // Check if @Valid is on the same parameter (look at surrounding context)
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
        ruleId: "DK-JAVA-009",
        title: "Missing @Valid on @RequestBody: request body not validated",
        severity: "medium",
        confidence: "medium",
        missingControls: ["inputValidation"],
        consequence: "Without @Valid, Spring does not run Bean Validation constraints (@NotNull, @Size, @Pattern, etc.) on the request body. This allows malformed or malicious data to reach business logic unchecked.",
        acceptanceCriteria: [
          "Add @Valid annotation to @RequestBody parameters.",
          "Define validation constraints on DTO fields (@NotNull, @Size, @Email, etc.).",
          "Add @ControllerAdvice to handle MethodArgumentNotValidException with 400 response.",
        ],
        evidence: evidence(hits, "java-009"),
      });
    }
  }

  // DK-JAVA-010: Actuator exposure without security
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Check for actuator in application.properties/yml or pom.xml/build.gradle
      if (!/actuator/.test(content)) continue;
      const matches: string[] = [];
      // management.endpoints.web.exposure.include=* (exposes everything)
      if (/exposure\.include\s*[:=]\s*\*/.test(content)) {
        matches.push("All actuator endpoints exposed: management.endpoints.web.exposure.include=*");
      }
      // management.server.port without security
      if (/management\.server\.port/.test(content) && !/management\.endpoints\.enabled-by-default\s*=\s*false/.test(content)) {
        matches.push("Actuator on separate port without restricting endpoints");
      }
      // Spring Security config excluding actuator from security
      if (/requestMatchers.*actuator.*permitAll/.test(content)) {
        matches.push("Actuator endpoints accessible without authentication (permitAll)");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-JAVA-010",
        title: "Spring Boot Actuator exposed without security",
        severity: "high",
        confidence: "medium",
        missingControls: ["actuatorSecurity"],
        consequence: "Exposed actuator endpoints leak sensitive information (environment variables, heap dumps, thread dumps, config properties) and may allow remote code execution via /jolokia or /gateway routes.",
        acceptanceCriteria: [
          "Restrict exposed endpoints: management.endpoints.web.exposure.include=health,info",
          "Secure actuator endpoints with Spring Security — require authentication.",
          "Use management.server.port to put actuator on a separate internal-only port.",
        ],
        evidence: evidence(hits, "java-010"),
      });
    }
  }

  return findings;
}
