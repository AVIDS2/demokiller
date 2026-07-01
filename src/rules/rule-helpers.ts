import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { promises as fs } from "node:fs";
import path from "node:path";

/**
 * Detect whether a project is a library/framework (not a deployable application).
 * Libraries are NOT expected to have app-level concerns like rate limiting,
 * HTTPS enforcement, metrics endpoints, or security headers middleware.
 */
export async function detectIsLibrary(root: string, inventory: ProjectInventory): Promise<boolean> {
  try {
    const pkgPath = path.join(root, "package.json");
    const pkgRaw = await fs.readFile(pkgPath, "utf8");
    const pkg = JSON.parse(pkgRaw);
    // Library indicators: has exports/main/module/types/files AND no start script
    const hasLibField = !!(pkg.exports || pkg.module || pkg.types || pkg.typings || pkg.files);
    const hasStart = !!(pkg.scripts?.start || pkg.scripts?.dev);
    if (hasLibField && !hasStart) return true;
    // Also: private=false AND has a "main" pointing to lib code, no start/dev scripts
    if (pkg.main && !hasStart && pkg.private !== true) return true;
  } catch { /* no package.json or parse error */ }

  // Rust: [lib] or [workspace] section in Cargo.toml
  try {
    const cargo = await fs.readFile(path.join(root, "Cargo.toml"), "utf8");
    if (/^\[lib\]/m.test(cargo) || /^\[workspace\]/m.test(cargo)) return true;
  } catch {}

  // Python: has setup.py or pyproject.toml with library markers
  try {
    const setupPy = await fs.readFile(path.join(root, "setup.py"), "utf8");
    if (/packages\s*=|py_modules\s*=/i.test(setupPy)) return true;
  } catch {}
  try {
    const pyproject = await fs.readFile(path.join(root, "pyproject.toml"), "utf8");
    if (/^\[project\]/m.test(pyproject)) return true;
  } catch {}

  // Go: has go.mod — library if has internal/ or pkg/ dirs, or no main func in root
  try {
    const goMod = await fs.readFile(path.join(root, "go.mod"), "utf8");
    if (goMod.includes("module ")) {
      const goFiles = await fs.readdir(root);
      const hasMain = goFiles.some(f => f === "main.go");
      const hasLibDirs = goFiles.some(f => f === "internal" || f === "pkg" || f === "lib");
      if (!hasMain || hasLibDirs) return true;
    }
  } catch {}

  // Java/Kotlin: has gradle with java-library plugin
  try {
    const gradle = await fs.readFile(path.join(root, "build.gradle"), "utf8");
    if (/java-library/.test(gradle)) return true;
  } catch {}
  try {
    const gradle = await fs.readFile(path.join(root, "build.gradle.kts"), "utf8");
    if (/java-library/.test(gradle)) return true;
  } catch {}

  // PHP: composer.json with type=library
  try {
    const composer = JSON.parse(await fs.readFile(path.join(root, "composer.json"), "utf8"));
    if (composer.type === "library") return true;
  } catch {}

  // Ruby: has .gemspec file
  try {
    const entries = await fs.readdir(root);
    if (entries.some(e => e.endsWith(".gemspec"))) return true;
    // Swift: has Package.swift (Swift Package Manager library)
    if (entries.some(e => e === "Package.swift")) return true;
  } catch {}

  // Monorepo detection: frameworks that ship as monorepos (NestJS, Prisma, etc.)
  // If the root has monorepo config files, treat as library
  try {
    const entries = await fs.readdir(root);
    const MONOREPO_MARKERS = ["lerna.json", "nx.json", "turbo.json", "pnpm-workspace.yaml", "rush.json"];
    if (entries.some(e => MONOREPO_MARKERS.includes(e))) return true;
    // Also: workspaces field in package.json (already read above, but re-check)
    try {
      const pkg = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
      if (pkg.workspaces) return true;
    } catch {}
  } catch {}

  return false;
}

/**
 * Rules that are only relevant to deployable applications, not libraries.
 * When a project is detected as a library, these findings get removed entirely
 * because a library/framework's own source code legitimately contains patterns
 * like string concatenation, template rendering, user input routing, etc.
 */
const LIBRARY_IRRELEVANT = new Set([
  // Application-layer concerns
  "DK-PERF-010",  // No rate limiting
  "DK-PERF-048",  // No payload size limit
  "DK-OBS-010",   // No request ID propagation
  "DK-OBS-012",   // No metrics endpoint
  "DK-SEC-001",   // No security headers middleware
  "DK-SEC-002",   // No HTTPS enforcement
  "DK-ERR-010",   // Error handler returns stack trace
  "DK-RATE-001",  // No rate limiting (perf variant)
  "DK-CSRF-001",  // State-changing endpoints without CSRF
  "DK-REDIRECT-001", // Open redirect (framework routing is by design)
  "DK-ENV-016",   // High-entropy credentials (libraries have config defaults, example keys, test fixtures)
  // Framework internals legitimately use these patterns
  "DK-SEC-004",   // SQL query built with string concatenation (framework routing internals)
  "DK-XSS-001",   // User input rendered without escaping (template engine internals)
  "DK-SANITIZE-001", // User input to DOM/HTML (template internals)
  // Not applicable to non-agent libraries
  "DK-AGENT-008", // Secret/context leak (only relevant for agent/MCP code)
  "DK-AGENT-009", // Unbounded agent loop
  // Hardcoded localhost is common and legitimate in library internals
  "DK-ENV-002",   // Hardcoded localhost
  // Framework internals (routing, middleware) legitimately use these
  "DK-GO-013",    // math/rand in framework internals (not security-sensitive)
  "DK-PERF-032",  // Blocking DB transaction (framework internals don't do DB)
  "DK-GO-001",    // Goroutine patterns in framework internals
  "DK-GO-002",    // Unchecked error in framework internals
  "DK-GO-003",    // Missing HTTP client timeout (framework is the server, not client)
  "DK-GO-006",    // panic() in framework internals (control flow pattern)
  "DK-GO-017",    // TLS config defaults in framework internals
  "DK-GO-020",    // Open redirect in framework routing (by design)
  "DK-RS-011",    // Missing TLS in Rust framework internals
  "DK-RS-013",    // SSRF in framework internals
  "DK-RS-014",    // Open redirect in Rust framework routing
  "DK-ENV-018",   // Hardcoded connection strings (framework defaults)
  "DK-ERR-006",   // Unhandled Promise rejection (framework internals)
  "DK-TAINT-001", // Taint analysis (framework internals handle sanitization by design)
  "DK-PY-007",    // Python cross-function taint (framework ORM internals)
  "DK-DEVOPS-001", // Hardcoded secrets in scripts (framework management commands)
  "DK-ENV-004",   // Hardcoded env values (framework defaults/constants)
  "DK-STATE-021", // State mutation in framework internals
  "DK-CICD-001",  // CI/CD secrets (framework CI config, not production)
  "DK-INPUT-001", // Input validation (framework routes don't validate — app's job)
  // Language-specific security rules that fire on framework internals
  "DK-GO-019",    // SSRF (framework HTTP client internals)
  "DK-GO-005",    // SQL injection via string concat (framework routing)
  "DK-AGENT-011", // MCP server auth (not applicable to non-agent code)
  "DK-JAVA-003",  // Unsafe deserialization (framework internals)
  "DK-KT-003",    // SQL injection via interpolation (framework routing)
  "DK-PHP-003",   // File inclusion (framework routing internals)
  "DK-RB-001",    // SQL injection (framework ORM internals)
  "DK-RB-004",    // Command injection (framework internals)
  "DK-RB-007",    // Unsafe deserialization (framework internals)
  "DK-AUTHCHAIN-001", // Auth chain (public routes in frameworks don't need auth)
  // C/C++ library internals (ffmpeg, redis, pillow, etc. legitimately use unsafe C patterns)
  "DK-C-001",     // Buffer overflow via unsafe string functions (library internals)
  "DK-C-002",     // Use-after-free (library internals)
  "DK-C-005",     // Format string (library internals)
  "DK-C-006",     // Integer overflow (library internals)
  "DK-C-007",     // Missing bounds check (library internals)
  "DK-C-009",     // Race condition (library internals)
]);

/**
 * Remove library-irrelevant findings when project is a library/framework.
 * These patterns are expected in library source code (routing, templating, etc.)
 * and only become problems in end-user applications.
 */
export function downgradeLibraryFindings(findings: Finding[], isLibrary: boolean): Finding[] {
  if (!isLibrary) return findings;
  return findings.filter(f => !LIBRARY_IRRELEVANT.has(f.ruleId));
}

const SKIP = new Set([
  "node_modules","dist","build",".git","__pycache__","target","vendor",".next","out",
  // Test fixtures and dev tooling
  "fixtures","testdata","test_data","test-data","samples","sample-data",
  "e2e","cypress","playwright",".worktrees",".demokiller",".claude",".vscode",
  // Example/demo/bench/docs directories
  "example","examples","demo","demos","sample","samples","integration","integrations",
  "bench","benchmark","benchmarks","docs","doc","third_party","scripts",
]);

export async function walkSourceFiles(root: string, exts: string[]): Promise<string[]> {
  const results: string[] = [];
  async function walk(dir: string) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    for (const e of entries) {
      if (SKIP.has(e.name)) continue;
      const full = path.join(dir, e.name);
      if (e.isDirectory()) await walk(full);
      else if (exts.some(ext => e.name.endsWith(ext))) results.push(path.relative(root, full).replaceAll("\\", "/"));
    }
  }
  await walk(root);
  return results;
}

export async function readFileContent(root: string, file: string): Promise<string> {
  try { return await fs.readFile(path.join(root, file), "utf8"); } catch { return ""; }
}

/**
 * Safe regex test that resets lastIndex for global regexes before each test.
 * Prevents the stale-lastIndex bug when using g-flagged regex with .test().
 */
export function safeTest(re: RegExp, content: string): boolean {
  re.lastIndex = 0;
  return re.test(content);
}
