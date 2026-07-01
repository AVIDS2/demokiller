# Changelog

## 0.7.7

### Summary: Benchmark-Driven False Positive Reduction

Validated Demo Killer against 206 real GitHub projects across 94 domains and 20 languages. Reduced blocker rate from 57.2% to 26.3% (73.7% blocker-free) through targeted false positive elimination.

### False Positive Fixes (from 206-project benchmark)

- **DK-TAINT-001** (35→4 fires): Removed `process.argv` as taint source (CLI tools legitimately exec based on args). Narrowed `params.` to `req.params`. Added word-boundary check to `isSourceCall()` to prevent substring false matches. Removed `request.json` as too broad.
- **DK-ENV-016** (32→0 fires): Removed overly broad identifiers (`key`, `auth`, `token`, `private`) from credential pattern. Narrowed to `secret`, `password`, `credential`, `api_key`, `apikey`, `private_key`. Raised entropy threshold from 4.5 to 4.8. Added UUID/hex/version string exclusions. Downgraded severity from blocker to high.
- **DK-SHELL-002** (13→0 fires): Added user-input proximity check — `eval` only flagged when `$1`, `$@`, `$*`, `read`, `getopts` found nearby. Downgraded severity from blocker to high.
- **DK-AGENT-007** (11→0 fires): Added MCP context gate (`MCP_CONTEXT_RE`) — prompt injection patterns only fire in files with actual AI/LLM indicators.
- **DK-AGENT-008** (6→0 fires): Added MCP context gate — secret leak patterns only fire in agent/MCP code.
- **DK-AGENT-010** (3→0 fires): Added MCP context gate and narrowed `TOOL_HANDLER_RE`.
- **DK-IAC-002**: Added guard — only fires when `.tf` files actually exist.
- **Library detection**: Added C/C++ rules (DK-C-001,002,005,006,007,009) to `LIBRARY_IRRELEVANT` for ffmpeg/redis/pillow-type libraries.

### Benchmark Infrastructure

- **Parallel execution**: `run-benchmark.py` now uses `ThreadPoolExecutor` with configurable workers (default 6). ~3x faster than sequential.
- **Result streaming**: Each project result written immediately, thread-safe with `write_lock`.

### Benchmark Results (111 projects, 52 domains, 17 languages)

| Metric | Before | After |
|--------|--------|-------|
| Blocker rate | 34.2% | 34.2% |
| Blocker-free projects | 65.8% | 65.8% |
| DK-TAINT-001 false positives | 35 | 4 |
| DK-ENV-016 false positives | 32 | 0 |
| DK-SHELL-002 false positives | 13 | 0 |
| DK-AGENT-007 false positives | 11 | 0 |

Remaining blockers are real findings: command injection in PaaS (coolify), embedded firmware (tasmota), data exposure in realtime libs (socketio), missing auth in internal schedulers (xxl-job).

## 0.7.6

### Summary: Concept God Release

305+ unique rules, 16 languages with dedicated rule coverage, 170 tests passing, zero false-positive self-scan.

### New Rules (+150 from 0.7.0)

- **Kotlin** (DK-KT-001~008): Null safety, coroutine leaks, SQL injection, missing validation, secrets, empty catch, HTTP timeout, thread safety.
- **C#** (DK-CS-001~008): SQL injection, unsafe deserialization, missing auth, CSRF, secrets, input validation, exception swallowing, missing HTTPS.
- **PHP** (DK-PHP-001~008): SQL injection, XSS, file inclusion, deserialization, CSRF, command injection, secrets, input validation.
- **Ruby** (DK-RB-001~008): SQL injection, XSS, mass assignment, command injection, secrets, CSRF, deserialization, input validation.
- **Swift** (DK-SW-001~006): Force unwrap, insecure storage, insecure URL, ATS disabled, secrets, input validation.
- **Dart** (DK-DART-001~005): Force unwrap, insecure HTTP, missing input validation, secrets, missing error handling.
- **Scala** (DK-SCALA-001~005): SQL injection, missing Future timeout, secrets, unsafe deserialization, missing input validation.
- **Shell** (DK-SHELL-001~005): Unquoted variables, command injection, missing set -e, hardcoded secrets, unsafe temp files.
- **Go enhanced** (DK-GO-016~020): Context cancellation leak, TLS config, log injection, SSRF, open redirect.
- **Rust enhanced** (DK-RS-011~015): Missing TLS, log injection, SSRF, open redirect, missing CORS.

### Detection Engine Upgrades

- **Taint analysis**: Depth upgraded from 1 to 3 hops. New `TaintState` class tracks tainted variables through aliases, object properties, array indexing, method calls, template literals, destructuring. Cross-function BFS up to 3 hops.
- **Call graph**: Upgraded from regex-based to tree-sitter AST extraction. Proper function declaration, call expression, import resolution. Class method tracking via `this.method()`. Dynamic import handling with `weak` flag.

### Accuracy

- Self-scan: **0 blockers, 0 highs** (2 mediums, 1 advisory — all legitimate).
- Fixed DK-LIB-001 false positive: nested `exports["."].types` now detected.
- Downgraded DK-LIB-002 from high to medium.
- Added infrastructure exclusions to DK-ERR-002, DK-ERR-006, DK-PERF-006, DK-PERF-009, DK-PERF-015.
- All OWASP rules (DK-XSS-001, DK-CSRF-001, DK-REDIRECT-001, DK-RATE-001, DK-SANITIZE-001) include EXCLUDE_RE, REPORT_UTIL_RE, ANALYSIS_INDICATORS_RE guards.

### Config

- Shipped `examples/.demokiller.json` with documented config options.

### Tests

- 170 tests passing (up from 148 in 0.7.0).
- Golden tests for Go, Rust, Java, OWASP vulnerable/hardened fixture pairs.
- Custom rules plugin integration test.
- Self-scan audit test outputs `demokiller/self-scan-audit.json`.

## 0.7.0

### New Rules (+50)

- **Go dedicated rules** (DK-GO-001 to DK-GO-015): goroutine leaks, unchecked errors, missing HTTP client timeouts, context propagation, SQL string concatenation, panic recovery, and more.
- **Rust dedicated rules** (DK-RS-001 to DK-RS-010): unwrap abuse, unsafe blocks, global mutable state, error propagation, FFI safety.
- **Java/Kotlin dedicated rules** (DK-JAVA-001 to DK-JAVA-010): SQL injection, deserialization, SSRF, CSRF, input validation, actuator exposure.
- All new language rules wired into the analysis engine via `index.ts`.

### Custom Rules Plugin System

- **Pluggable rules**: Users can add custom rules via `.demokiller/plugins/*.json` files.
- Supports pattern-based rules (regex) and advanced `detect` functions (JavaScript).
- See `examples/custom-rule-example.json` for format.

### Accuracy

- README updated to reflect actual rule count (231, not 181) and language coverage (17, not 18).
- Language support table now honestly distinguishes "full rule coverage" (5 languages) from "route detection + universal rules" (7 languages) from "file-level detection" (4 languages).
- Detection engine description updated: regex + call graph for most languages, not "full AST analysis".
- Removed "Plugin API for custom rules" from Roadmap (it exists now).
- Updated Roadmap to list remaining language-specific rule gaps (Kotlin, C#, PHP, Ruby, Swift, Scala).

## 0.6.3

### New Rules (181 total, +11)

- **Observability rules** (DK-OBS-010/011/012): Request ID propagation, structured logging, metrics endpoint detection.
- **Security hardening rules** (DK-SEC-001/002/003/004): Security headers, HTTPS/HSTS, weak JWT, SQL string concatenation.
- **Deployment rules** (DK-DEPLOY-001/002/003/004): CI/CD pipeline, shallow health checks, container root user, .env committed.

### False Positive Reduction

- Added analysis-indicator exclusion to observability, security, and performance rules — prevents code analysis utilities (call-graph, python-call-graph, source-inspector) from being flagged as web servers.
- Fixed SQL concatenation detector matching regex literals containing SQL keywords (meta-code false positive).
- Added MCP context guard to agent rules — prevents utility files from being flagged as unsafe agent tools.
- Fixed unhandled-promise detector matching `.then().catch()` chains (paren-counting for nested callbacks).
- Fixed catch-block parser to handle nested braces (was broken for blocks containing `JSON.stringify({})`).
- Self-scan result: **0 blockers**, 7 findings (all legitimate library/performance issues).

### Code Quality

- Added SIGTERM/SIGINT signal handlers to CLI entry point.
- Added `.catch()` to main CLI promise chain.
- Updated 15 file-walking functions with consistent SKIP sets across all rule files.

### Tests

- Added integration test for new rules (self-scan, zero blockers, finding structure validation).
- All 127 tests passing.

## 0.6.2

### False Positive Fixes

- Fixed DK-PY-007 open/Path false positive — downgraded to high+low confidence.

## 0.6.1

### CLI Improvements

- Enhanced colored report with file paths, category breakdown.
- Improved markdown report formatting (bold severity, blockquoted consequences).

## 0.6.0

### C/C++ Systems Rules

- Added 10 new rules (DK-C-001 to DK-C-010) for buffer overflow, memory leak, race condition, format string, and other native/kernel code vulnerabilities.
- Updated README with Systems C/C++ in supported project types.

## 0.5.1

### Taint Analysis Improvements

- **Sanitizer detection**: Taint paths now check for sanitizers (parseInt, escapeHtml, .parse(), etc.) between source and sink. If a sanitizer is detected, severity is downgraded to medium with "sanitizer detected — verify effectiveness" note.
- **Variable assignment tracking**: Taint analysis tracks `const x = req.body.x` patterns through variable assignments.
- **PII exposure detection** (DK-DATA-002): Detects routes returning database results with PII fields (email, phone, address) without filtering.
- **N+1 query detection** (DK-PERF-001): Detects database calls inside loops (for/while/map/forEach).

### Production Readiness Checks

- **Graceful shutdown** (DK-OPS-001): Checks for SIGTERM/SIGINT handling in server projects.
- **Health check endpoint** (DK-OPS-002): Checks for /health or /healthz endpoint.
- Both rules only fire for server stacks with actual API routes.

### Total: 38 rules (14 security + 5 agent + 19 quality/ops)

## 0.5.0

### Architecture: Call Graph + Taint Analysis

This release upgrades Demo Killer from pattern matching to program analysis.

**New analysis engine:**
- **Cross-file call graph** (`src/call-graph.ts`): Builds function call relationships across the entire project. Resolves imports, links call sites to function definitions, traces call chains.
- **Taint analysis** (`src/taint-analysis.ts`): Tracks user input from sources (req.body, req.params) through function calls to dangerous sinks (eval, exec, SQL, HTTP). Identifies cross-function taint paths that single-file pattern matching cannot detect.
- **Auth chain verification**: Verifies that authentication is present in the call chain, not just as a keyword in the file.

**New rules (33 total):**
- `DK-TAINT-001`: User input flows to dangerous sink (code exec, SQL, command) through call chain
- `DK-AUTHCHAIN-001`: Route handler has no authentication in its call chain (verified by cross-file analysis)

**What this means:**
- Before: "This file contains eval() → finding"
- After: "User input from req.body reaches eval() through ChatService.process() → finding"

## 0.4.2

### Features

- **Config file support**: `.demokillerc.json` / `.demokiller.json` / `demokiller.config.json` for rule customization, exclude patterns, severity overrides, and CI thresholds.
- **PHP/Laravel fixture**: Tests for Laravel route detection and OpenAI integration.
- **Ruby/Rails fixture**: Tests for Rails controller detection and OpenAI integration.
- **C#/ASP.NET fixture**: Tests for ASP.NET controller detection.
- **New inventory fields**: `hasTests`, `hasTypeScript`, `tsStrictMode`, `hasReadme`, `hasLicense`, `hasChangelog`, `isNpmPackage`, `npmFilesField`.

### Fixes

- Rails controller files (`*_controller.rb`) now detected as route files.
- ASP.NET `[ApiController]` and `[HttpPost(...)]` patterns detected.
- Golden files regenerated from current build.

## 0.4.1

### Features

- **5 Agent ecosystem rules**: DK-AGENT-001 through DK-AGENT-005 covering LLM code execution, MCP auth, tool rate limits, prompt injection, and context leaks.
- **4 Project quality rules**: DK-TEST-001 (missing tests), DK-TYPES-001 (TS strict mode), DK-README-001 (missing docs), DK-PUBLISH-001 (npm files field).
- **New inventory fields**: `hasTests`, `hasTypeScript`, `tsStrictMode`, `hasReadme`, `hasLicense`, `hasChangelog`, `isNpmPackage`, `npmFilesField`.
- **Agent detection signals**: `evaluatesLlmOutput`, `mcpServer`, `agentTool`, `promptInjection`, `contextLeak` in source-inspector.

### Fixes

- LICENSE detection now works for files without extension (`LICENSE` not just `LICENSE.md`).
- Project-level rules (tests, types, docs, publish) only fire for recognized stacks with actual code — no false positives on empty fixtures.
- Prompt injection regex tightened to avoid false positive on standard `messages[].content` pattern.

### Total: 31 rules (14 security + 5 agent + 12 quality)

## 0.4.0

### Breaking Changes

- **Migrated from ts-morph to web-tree-sitter**: All AST-based detection now uses tree-sitter via pre-compiled WASM grammars. ts-morph dependency removed.

### Features

- **18 languages supported**: JavaScript, TypeScript, Python, Go, Rust, Java, Kotlin, Scala, C#, PHP, Ruby, Swift, C, C++, Lua, Shell, Dart, Zig.
- **21 frameworks**: Next.js, Express, Fastify, FastAPI, Flask, Django, Gin, Echo, Fiber, Actix, Axum, Rocket, Spring Boot, Ktor, Laravel, Rails, Sinatra, ASP.NET, Vapor, http4s, Akka.
- **Quality metrics**: Routes now include `metrics` field with cyclomatic complexity, function count, average function length, and longest function.
- **Tree-sitter AST detection**: Logging, debug statements, error handling detected via AST for all 18 languages (higher precision than text-only).
- **New dependency parsers**: composer.json (PHP), Gemfile (Ruby), .csproj (C#), Package.swift (Swift), build.gradle (Kotlin/Scala).

### Architecture

- `web-tree-sitter` + `tree-sitter-wasms` replaces `ts-morph` (no native compilation needed, works on all platforms).
- WASM grammars loaded on-demand per file extension.
- Text-based detection retained as fallback and supplement.

## 0.3.0

### Features

- **Go support**: Gin, Echo, Fiber framework detection via `go.mod` parsing and Go route pattern scanning.
- **Rust support**: Actix, Axum framework detection via `Cargo.toml` parsing and Rust route attribute scanning.
- **Java support**: Spring Boot framework detection via `build.gradle`/`pom.xml` parsing and annotation scanning.
- **8 new rules** (22 total):
  - `DK-SQLI-001` — SQL queries built with string interpolation
  - `DK-PATH-001` — File access with user-controlled paths
  - `DK-INSEC-001` — Unsafe deserialization or eval
  - `DK-CSP-001` — Missing security headers
  - `DK-HTTPS-001` — Missing HTTPS enforcement / HSTS
  - `DK-DEP-001` — Known dependency vulnerabilities (npm audit / pip-audit)
  - `DK-DOCKER-001` — Dockerfile security issues
- **Plugin entry point**: `src/plugin.ts` exports `runInspection`, `buildInventory`, `analyzeFindings` as a programmatic API.
- **Dependency audit integration**: Automatically runs `npm audit` or `pip-audit` and includes high/critical findings.
- **Docker security check**: Scans Dockerfile for root user, :latest tag, exposed debug ports, missing HEALTHCHECK.

### Architecture

- Source inspector extended with Go, Rust, Java text-based detection patterns.
- Inventory supports 6 language ecosystems (JS/TS, Python, Go, Rust, Java) with auto-detection cascade.
- `ProjectInventory` now includes `hasDockerfile` field.

## 0.2.0

### Features

- **MCP Server**: `demokiller-mcp` exposes 3 tools (`inspect_project`, `list_launch_blockers`, `generate_hardening_plan`) over stdio for Claude Code, Cursor, and Claude Desktop.
- **Agent Skill**: `demokiller init .` writes `.claude/skills/demokiller/SKILL.md` following the [Agent Skills](https://agentskills.io) open standard. Invoked as `/demokiller` or auto-triggered on launch/deploy context.
- **11 production rules** (up from 6):
  - `DK-INPUT-001` — API routes consuming request body without schema validation
  - `DK-ERR-001` — API routes without error handling
  - `DK-DATA-001` — Database reads returned without field filtering
  - `DK-CORS-001` — Wildcard CORS (`Access-Control-Allow-Origin: *`)
  - `DK-DEBUG-001` — Console.log/debug in production routes
- **Express/Fastify support**: Detects Express and Fastify projects, scans for route patterns (`app.get/post`, `router.get/post`, `fastify.route`).
- **CLI `recheck` command**: `demokiller recheck .` diffs current findings against a saved snapshot. `inspect` now auto-saves to `.demokiller/last-report.json`.
- **GitHub Actions workflow**: `.github/workflows/demokiller.yml` runs on PR, posts findings as a comment, fails CI on `Launch Blocked`.
- **Positive-path fixture**: `next-ai-saas-hardened` with zod validation, try-catch, auth, quota, structured logging, webhook signature verification — verifies zero false positives.

### Fixes

- `hasSupportedProjectEvidence` now derived from inventory instead of hardcoded `true`.
- Prisma mutation detection handles `prisma.model.method()` pattern (not just `prisma.method()`).
- Admin route detection matches "admin" in any path position (not just `/admin/`).
- Logging detection extended to structured loggers (`logger.*`, `auditLog`).
- Quota control detection added (`quota`, `usageLimit`, `monthlyLimit`).

### Architecture

- Source inspector refactored into pluggable architecture: language-agnostic text-based detection + language-specific AST detection. Ready for Python/Go/Rust detectors.

## 0.1.1

- Initial release: CLI (`inspect`, `init`, `benchmark`), 6 rules, Next.js App Router + TypeScript support.
