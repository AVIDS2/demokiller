import path from "node:path";
import { Project, SyntaxKind } from "ts-morph";

export interface RouteSourceEvidence {
  path: string;
  capabilities: string[];
  controls: string[];
  envVars: string[];
  line: number;
}

// ─── Language-agnostic text-based detection ────────────────────────

function pushUnique(target: string[], value: string) {
  if (!target.includes(value)) target.push(value);
}

function detectCapabilitiesFromText(text: string, capabilities: string[]) {
  // AI/ML providers
  if (text.includes("openai") || text.includes("OpenAI") || text.includes("chat.completions")) {
    pushUnique(capabilities, "callsOpenAI");
  }
  if (text.includes("anthropic") || text.includes("Anthropic")) {
    pushUnique(capabilities, "callsAnthropic");
  }

  // Payment providers
  if (text.includes("stripe") || text.includes("Stripe")) {
    pushUnique(capabilities, "handlesPaymentProvider");
  }

  // Database mutations
  if (text.includes("prisma.") && text.match(/\.\s*(delete|update|create|upsert)\s*\(/)) {
    pushUnique(capabilities, "mutatesDatabase");
  }
  if (
    text.includes("prisma.") &&
    text.match(/\.\s*(findFirst|findMany|findUnique|findFirstOrThrow|findUniqueOrThrow)\s*\(/)
  ) {
    pushUnique(capabilities, "readsDatabase");
  }
  // Python ORM: SQLAlchemy, Django ORM — require Python-specific markers
  if (
    (text.includes("session.add(") || text.includes("session.delete(") || text.includes("session.commit()") ||
     text.includes(".objects.create(") || text.includes(".objects.filter(") || text.includes("db.session"))
  ) {
    pushUnique(capabilities, "mutatesDatabase");
  }
  if (
    (text.includes("session.query(") || text.includes(".objects.all()") || text.includes(".objects.get(") ||
     text.includes("db.session.query") || text.includes("select("))
  ) {
    pushUnique(capabilities, "readsDatabase");
  }

  // Request body consumption
  if (
    text.match(/await\s+(request|req)\.json\s*\(/) ||
    text.match(/\b(request|req)\.body\b/) ||
    text.match(/\brequest\.json\s*\(/) ||
    text.match(/\bawait\s+request\.json\s*\(\s*\)/) ||
    text.match(/\brequest\.form\s*\(/) ||
    text.match(/\bawait\s+request\.form\s*\(\s*\)/)
  ) {
    pushUnique(capabilities, "consumesRequestBody");
  }
  // Python: Pydantic model as function parameter (FastAPI pattern)
  if (text.match(/:\s*[A-Z]\w+\s*[,)]/) && (text.includes("BaseModel") || text.includes("Schema"))) {
    pushUnique(capabilities, "consumesRequestBody");
  }

  // Command execution
  if (
    text.match(/\b(exec|execSync|execFile|spawn|spawnSync|child_process)\s*\(/) ||
    text.match(/\bsubprocess\.(run|Popen|call|check_output)\s*\(/) ||
    text.match(/\bos\.system\s*\(/) ||
    text.match(/\bos\.popen\s*\(/)
  ) {
    pushUnique(capabilities, "commandExecution");
  }

  // ── Go capabilities ────────────────────────────────────────────
  if (text.match(/\bc\s*\.\s*(ShouldBindJSON|Bind|BindJSON|ShouldBind)\s*\(/)) {
    pushUnique(capabilities, "consumesRequestBody");
  }
  if (text.match(/\bdb\s*\.\s*(Create|Delete|Update|Save|Where)\s*\(/)) {
    pushUnique(capabilities, "mutatesDatabase");
  }
  if (text.match(/\bdb\s*\.\s*(Find|First|Take|FindOne)\s*\(/)) {
    pushUnique(capabilities, "readsDatabase");
  }

  // ── Rust capabilities ──────────────────────────────────────────
  if (text.match(/\b(Json|web::Json|axum::Json)\s*\(/) || text.includes("Payload")) {
    pushUnique(capabilities, "consumesRequestBody");
  }

  // ── Java capabilities ──────────────────────────────────────────
  if (text.includes("@RequestBody")) {
    pushUnique(capabilities, "consumesRequestBody");
  }
  if (text.includes("@Repository") || text.includes("CrudRepository") || text.includes("JpaRepository") || text.includes("EntityManager")) {
    pushUnique(capabilities, "readsDatabase");
  }
}

function detectControlsFromText(text: string, controls: string[]) {
  // Auth — JS/TS
  if (
    text.match(/\bauth\s*\(/) ||
    text.includes("getServerSession") ||
    text.includes("currentUser") ||
    text.includes("req.user") ||
    text.includes("req.isAuthenticated") ||
    text.includes("passport.authenticate") ||
    text.includes("verifyToken") ||
    text.includes("authenticate(")
  ) {
    pushUnique(controls, "auth");
  }
  // Auth — Python
  if (
    text.includes("@login_required") ||
    text.includes("Depends(get_current_user") ||
    text.includes("current_user") ||
    text.includes("login_user") ||
    text.includes("jwt.decode") ||
    text.includes("verify_jwt") ||
    text.includes("TokenAuth") ||
    text.includes("HTTPBearer") ||
    text.includes("APIKeyHeader") ||
    text.includes("get_current_user") ||
    text.includes("Permission") ||
    text.includes("permissions_classes")
  ) {
    pushUnique(controls, "auth");
  }

  if (text.includes("role") || text.includes("isAdmin") || text.includes("permission")) {
    pushUnique(controls, "authorization");
  }
  if (text.includes("rateLimit") || text.includes("limiter") || text.includes("slowapi") || text.includes("RateLimiter")) {
    pushUnique(controls, "rateLimit");
  }
  if (text.includes("quota") || text.includes("usageLimit") || text.includes("monthlyLimit")) {
    pushUnique(controls, "quota");
  }
  if (text.includes("constructEvent") || text.includes("STRIPE_WEBHOOK_SECRET")) {
    pushUnique(controls, "signatureVerification");
  }
  if (text.includes("idempotency") || text.includes("event.id")) {
    pushUnique(controls, "idempotency");
  }

  // Input validation — JS/TS + Python + Go + Rust + Java
  if (
    text.match(/\bimport\b.*\bfrom\b.*['"]zod['"]/) ||
    text.match(/\bimport\b.*\bfrom\b.*['"]yup['"]/) ||
    text.match(/\bimport\b.*\bfrom\b.*['"]joi['"]/) ||
    text.match(/\brequire\s*\(\s*['"]zod['"]\s*\)/) ||
    text.match(/\brequire\s*\(\s*['"]yup['"]\s*\)/) ||
    text.match(/\brequire\s*\(\s*['"]joi['"]\s*\)/) ||
    text.includes("BaseModel") || text.includes("Schema(") || text.includes("dataclass") ||
    text.match(/\.parse\s*\(/) || text.match(/\.safeParse\s*\(/) || text.match(/\.validate\s*\(/) || text.match(/\.model_validate\s*\(/) ||
    text.includes("validator.New") || text.includes("go-playground/validator") || // Go
    text.includes("Validate()") || text.includes(".Struct(") || // Go
    text.includes("serde::Deserialize") || text.includes("#[validate(") || // Rust
    text.includes("Validated<") || // Rust
    text.includes("@Valid") || text.includes("@NotNull") || text.includes("@NotBlank") || // Java
    text.includes("@Size") || text.includes("@Pattern") // Java
  ) {
    pushUnique(controls, "inputValidation");
  }

  // Error handling — JS + Python + Go + Rust + Java
  if (
    text.match(/\.catch\s*\(/) ||
    text.match(/\bexcept\b/) || text.match(/\btry:\s*$/m) ||
    text.match(/\bif\s+err\s*!=\s*nil/) || // Go
    text.match(/\brecover\s*\(\s*\)/) || // Go
    text.includes("Result<") || // Rust
    text.match(/\bcatch\s*\(\s*\w+/) || // Java/C#/TS
    text.includes("@ExceptionHandler") // Java
  ) {
    pushUnique(controls, "errorHandling");
  }

  if (
    text.includes("Access-Control-Allow-Origin") ||
    text.match(/\bcors\s*\(\s*\)/) ||
    text.match(/\bcors\s*\(\s*\{\s*\}\s*\)/) ||
    text.match(/origin:\s*['"]?\*['"]?/) ||
    text.includes("CORSMiddleware") ||
    text.match(/allow_origins\s*=\s*\[\s*['"]?\*['"]?\s*\]/)
  ) {
    pushUnique(controls, "corsWildcard");
  }

  // SSRF risk — fetch/requests with user-controlled URL
  if (
    text.match(/\bfetch\s*\(\s*(req|request|body|params|query|input|url)/) ||
    text.match(/\baxios\s*\.\s*(get|post|put|delete)\s*\(\s*(req|request|body|params)/) ||
    text.match(/\brequests\s*\.\s*(get|post|put|delete)\s*\(\s*(req|request|body|params|url)/) ||
    text.match(/\bhttp\s*\.\s*(get|post|request)\s*\(\s*(req|request|body|params|url)/)
  ) {
    pushUnique(controls, "ssrfRisk");
  }

  // Hardcoded secrets
  if (
    text.match(/['"]sk-[a-zA-Z0-9]{20,}['"]/) ||
    text.match(/['"]sk_live_[a-zA-Z0-9]+['"]/) ||
    text.match(/['"]sk_test_[a-zA-Z0-9]+['"]/) ||
    text.match(/['"]AKIA[A-Z0-9]{16}['"]/) ||
    text.match(/['"]ghp_[a-zA-Z0-9]{36}['"]/) ||
    text.match(/['"]xoxb-[a-zA-Z0-9-]+['"]/) ||
    text.match(/['"]whsec_[a-zA-Z0-9]+['"]/) ||
    text.match(/(SECRET|TOKEN|PASSWORD|API_KEY)\s*[:=]\s*['"][a-zA-Z0-9]{16,}['"]/i)
  ) {
    pushUnique(controls, "hardcodedSecrets");
  }

  // Structured logging (used to suppress log injection false positives)
  if (
    text.includes("structuredLog") ||
    text.includes("JSON.stringify") ||
    text.match(/log\.\w+\s*\([^)]*\{/) ||
    text.match(/logger\.\w+\s*\([^)]*\{/) ||
    text.match(/auditLog\s*\([^)]*\{/)
  ) {
    pushUnique(controls, "logSanitization");
  }

  // ── Go/Rust/Java auth ──────────────────────────────────────────
  // Go: middleware, JWT, session
  if (
    text.includes("middleware.Auth") || text.includes("JWT") ||
    text.includes("session.Get(") || text.includes("c.Set(") ||
    text.match(/gin\.BasicAuth/) || text.match(/middleware\.BasicAuth/)
  ) {
    pushUnique(controls, "auth");
  }
  // Rust: extractors, guards
  if (
    text.includes("Authorization") || text.includes("Bearer") ||
    text.includes("Session") || text.includes("Identity")
  ) {
    pushUnique(controls, "auth");
  }
  // Java: Spring Security
  if (
    text.includes("@PreAuthorize") || text.includes("@Secured") ||
    text.includes("SecurityContext") || text.includes("AuthenticationPrincipal") ||
    text.includes("@AuthenticationPrincipal")
  ) {
    pushUnique(controls, "auth");
  }

  // ── SQL injection risk ─────────────────────────────────────────
  if (
    text.match(/\.query\s*\(\s*["'`].*\$\{/) ||      // JS template literal SQL
    text.match(/\.query\s*\(\s*["'`].*\+/) ||         // JS string concat SQL
    text.match(/\.raw\s*\(\s*["'`].*\$\{/) ||
    text.match(/\.raw\s*\(\s*["'`].*\+/) ||
    text.match(/execute\s*\(\s*["'`].*%s/) ||          // Python % format SQL
    text.match(/execute\s*\(\s*f["']/) ||              // Python f-string SQL
    text.match(/\.query\s*\(\s*fmt\.Sprintf/) ||       // Go fmt.Sprintf SQL
    text.match(/\.exec\s*\(\s*fmt\.Sprintf/) ||
    text.match(/\.Query\s*\(\s*fmt\.Sprintf/) ||
    text.match(/createQuery\s*\(\s*["'`].*\+/) ||      // Java string concat SQL
    text.match(/createNativeQuery\s*\(\s*["'`].*\+/) ||
    text.match(/sqlx?\.\w+\s*\(\s*["'`].*\$/)         // Rust format SQL
  ) {
    pushUnique(controls, "sqlInjectionRisk");
  }

  // ── Path traversal risk ────────────────────────────────────────
  if (
    text.match(/readFile\s*\(\s*(req|request|params|query|body)\./) ||
    text.match(/readFile\s*\(\s*path\.join\s*\(\s*.*?(req|request|params|query)/) ||
    text.match(/open\s*\(\s*(req|request|params|body)\./) ||
    text.match(/os\.open\s*\(\s*(request|req)\./) ||
    text.match(/sendFile\s*\(\s*(req|request|params|query)\./)
  ) {
    pushUnique(controls, "pathTraversalRisk");
  }

  // ── CSP / security headers ─────────────────────────────────────
  if (
    text.includes("Content-Security-Policy") ||
    text.includes("helmet(") ||
    text.includes("helmet.csp") ||
    text.includes("X-Frame-Options") ||
    text.includes("X-Content-Type-Options")
  ) {
    pushUnique(controls, "securityHeaders");
  }

  // ── HTTPS / HSTS ───────────────────────────────────────────────
  if (
    text.includes("Strict-Transport-Security") ||
    text.includes("HTTPS") || text.includes("https") ||
    text.includes("redirectHttps") || text.includes("forceSSL") ||
    text.match(/301.*https/) || text.match(/302.*https/)
  ) {
    pushUnique(controls, "httpsEnforcement");
  }

  // ── Insecure deserialization / code injection ──────────────────
  if (
    text.match(/pickle\.loads?\s*\(/) ||
    text.match(/yaml\.load\s*\(\s*[^,)]+\s*\)/) ||
    text.match(/\beval\s*\(\s*(req|request|input|body|params|query)/) ||
    text.match(/\bnew\s+Function\s*\(\s*(req|request|input|body)/) ||
    text.match(/compile\s*\(\s*(req|request|input|body)/)
  ) {
    pushUnique(controls, "insecureDeserialization");
  }
}

function extractEnvVars(text: string): string[] {
  return Array.from(text.matchAll(/(?:process\.env|os\.environ|os\.getenv)\s*\(?['".]*([A-Z0-9_]+)/g)).map(
    (match) => match[1],
  );
}

// ─── TypeScript/JavaScript AST detection (ts-morph) ───────────────

function detectFromJsTsAst(
  text: string,
  sourceFile: ReturnType<InstanceType<typeof Project>["addSourceFileAtPath"]>,
  controls: string[],
  line: number): number {
  const firstFunction = sourceFile.getFunctions()[0];
  const detectedLine = firstFunction?.getStartLineNumber() ?? line;

  if (
    sourceFile
      .getDescendantsOfKind(SyntaxKind.CallExpression)
      .some((call) => {
        const t = call.getText();
        return (
          t.startsWith("console.") ||
          t.startsWith("logger.") ||
          t.startsWith("log.") ||
          t.startsWith("auditLog") ||
          t.startsWith("structuredLog")
        );
      })
  ) {
    pushUnique(controls, "logging");
  }
  if (sourceFile.getDescendantsOfKind(SyntaxKind.TryStatement).length > 0) {
    pushUnique(controls, "errorHandling");
  }
  if (
    sourceFile
      .getDescendantsOfKind(SyntaxKind.CallExpression)
      .some((call) => {
        const t = call.getText();
        return t.startsWith("console.log") || t.startsWith("console.debug");
      })
  ) {
    pushUnique(controls, "debugStatements");
  }

  return detectedLine;
}

// ─── Public API ───────────────────────────────────────────────────

const JS_TS_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"];

export async function inspectRouteSource(
  root: string,
  relativePath: string,
): Promise<RouteSourceEvidence> {
  const fullPath = path.join(root, relativePath);
  const ext = path.extname(relativePath);
  const capabilities: string[] = [];
  const controls: string[] = [];
  let line = 1;

  if (JS_TS_EXTS.includes(ext)) {
    const project = new Project({ useInMemoryFileSystem: false });
    const sourceFile = project.addSourceFileAtPath(fullPath);
    const text = sourceFile.getFullText();

    detectCapabilitiesFromText(text, capabilities);
    detectControlsFromText(text, controls);
    const envVars = extractEnvVars(text);
    line = detectFromJsTsAst(text, sourceFile, controls, line);

    return { path: relativePath, capabilities, controls, envVars, line };
  }

  // Fallback: text-only detection for unknown file types (including Python)
  const { promises: fs } = await import("node:fs");
  const text = await fs.readFile(fullPath, "utf8");

  detectCapabilitiesFromText(text, capabilities);
  detectControlsFromText(text, controls);
  const envVars = extractEnvVars(text);

  // Python-specific AST-like text detections
  if (ext === ".py") {
    if (text.match(/\blogging\.(debug|info|warning|error|critical)\s*\(/) || text.match(/\blogger\.(debug|info|warning|error|critical)\s*\(/)) {
      pushUnique(controls, "logging");
    }
    if (text.match(/\bprint\s*\(/)) {
      pushUnique(controls, "debugStatements");
    }
    if (text.match(/\bexcept\s+/) || text.match(/\btry:\s*$/m)) {
      pushUnique(controls, "errorHandling");
    }
  }

  // Go-specific detections
  if (ext === ".go") {
    if (text.match(/\blog\.\w+\s*\(/) || text.match(/\blogrus\.\w+\s*\(/) || text.match(/\bzap\.\w+\s*\(/)) {
      pushUnique(controls, "logging");
    }
    if (text.match(/\bfmt\.Print(ln|f)?\s*\(/) || text.match(/\blog\.Println\s*\(/)) {
      pushUnique(controls, "debugStatements");
    }
    if (text.match(/\bif\s+err\s*!=\s*nil/)) {
      pushUnique(controls, "errorHandling");
    }
  }

  // Rust-specific detections
  if (ext === ".rs") {
    if (text.match(/\b(log|tracing)::\w+!/) || text.match(/\bprintln!\s*\(/) || text.match(/\binfo!\s*\(/) || text.match(/\bwarn!\s*\(/)) {
      pushUnique(controls, "logging");
    }
    if (text.match(/\bprintln!\s*\(/) || text.match(/\bdbg!\s*\(/) || text.match(/\beprintln!\s*\(/)) {
      pushUnique(controls, "debugStatements");
    }
    if (text.includes("Result<") || text.match(/\?;\s*$/m)) {
      pushUnique(controls, "errorHandling");
    }
  }

  // Java-specific detections
  if (ext === ".java") {
    if (text.match(/\blogger?\.(debug|info|warn|error)\s*\(/) || text.match(/\bLOGGER?\.(debug|info|warn|error)\s*\(/)) {
      pushUnique(controls, "logging");
    }
    if (text.match(/\bSystem\.out\.print(ln)?\s*\(/) || text.match(/\bSystem\.err\.print(ln)?\s*\(/)) {
      pushUnique(controls, "debugStatements");
    }
    if (text.match(/\bcatch\s*\(\s*\w+/)) {
      pushUnique(controls, "errorHandling");
    }
  }

  return { path: relativePath, capabilities, controls, envVars, line };
}
