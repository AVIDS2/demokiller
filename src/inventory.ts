import { promises as fs } from "node:fs";
import path from "node:path";

export type StackType =
  | "nextjs" | "express" | "fastify"
  | "flask" | "fastapi" | "django"
  | "gin" | "echo" | "fiber"
  | "actix" | "axum"
  | "spring-boot"
  | "unknown";

export interface ProjectInventory {
  root: string;
  stack: StackType;
  apiRoutes: string[];
  envExamplePath?: string;
  prismaSchemaPath?: string;
  migrationPaths: string[];
  hasDockerfile: boolean;
  packageJson: {
    dependencies: Record<string, string>;
    devDependencies: Record<string, string>;
  };
}

async function walk(root: string, dir = root): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const result: string[] = [];

  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name);
    if (
      entry.name === "node_modules" || entry.name === ".next" ||
      entry.name === "dist" || entry.name === "__pycache__" ||
      entry.name === ".venv" || entry.name === "venv" ||
      entry.name === "target" || entry.name === "vendor"
    ) continue;

    if (entry.isDirectory()) {
      result.push(...(await walk(root, fullPath)));
    } else {
      result.push(path.relative(root, fullPath).replaceAll("\\", "/"));
    }
  }

  return result;
}

const JS_TS_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"];
const PYTHON_EXTS = [".py"];
const GO_EXTS = [".go"];
const RUST_EXTS = [".rs"];
const JAVA_EXTS = [".java"];

async function fileContainsPattern(root: string, file: string, patterns: RegExp[]): Promise<boolean> {
  try {
    const text = await fs.readFile(path.join(root, file), "utf8");
    return patterns.some((p) => p.test(text));
  } catch {
    return false;
  }
}

const JS_ROUTE_PATTERNS = [
  /\bapp\s*\.\s*(get|post|put|patch|delete)\s*\(/,
  /\brouter\s*\.\s*(get|post|put|patch|delete)\s*\(/,
  /\bfastify\s*\.\s*(get|post|put|patch|delete)\s*\(/,
  /\bfastify\s*\.\s*route\s*\(/,
];

const PYTHON_ROUTE_PATTERNS = [
  /@(?:app|router|api)\s*\.\s*(get|post|put|patch|delete|route)\s*\(/,
  /@(?:app|bp)\s*\.\s*route\s*\(/,
  /\bpath\s*\(\s*['"]/,
  /\bre_path\s*\(\s*['"]/,
  /@api_view\s*\(/,
];

const GO_ROUTE_PATTERNS = [
  /\b[re]\s*\.\s*(GET|POST|PUT|PATCH|DELETE)\s*\(/,
  /\bapp\s*\.\s*(Get|Post|Put|Delete)\s*\(/,
  /\brouter\s*\.\s*Handle\s*\(/,
  /\be\.\s*(GET|POST|PUT|DELETE)\s*\(/,
];

const RUST_ROUTE_PATTERNS = [
  /#\[get\s*\(/,
  /#\[post\s*\(/,
  /#\[put\s*\(/,
  /#\[delete\s*\(/,
  /\.route\s*\(\s*["']/,
];

const JAVA_ROUTE_PATTERNS = [
  /@(Get|Post|Put|Delete|Request)Mapping\s*\(/,
  /@RestController/,
];

async function findRoutes(root: string, files: string[], exts: string[], patterns: RegExp[], excludeDirs: string[] = []): Promise<string[]> {
  const candidates = files.filter((f) => {
    if (!exts.some((ext) => f.endsWith(ext))) return false;
    if (excludeDirs.some((d) => f.includes(d))) return false;
    if (f.includes("test") || f.includes("spec") || f.includes("Test.") || f.includes("_test.")) return false;
    return true;
  });

  const results: string[] = [];
  for (const file of candidates) {
    if (await fileContainsPattern(root, file, patterns)) {
      results.push(file);
    }
  }
  return results;
}

// ─── Dependency parsers ───────────────────────────────────────────

type DepMap = Record<string, string>;

async function readGoDeps(root: string): Promise<DepMap> {
  const deps: DepMap = {};
  try {
    const text = await fs.readFile(path.join(root, "go.mod"), "utf8");
    for (const match of text.matchAll(/^\s*([a-z0-9./-]+)\s+v/gm)) {
      deps[match[1].toLowerCase()] = "latest";
    }
  } catch { /* no go.mod */ }
  return deps;
}

async function readCargoDeps(root: string): Promise<DepMap> {
  const deps: DepMap = {};
  try {
    const text = await fs.readFile(path.join(root, "Cargo.toml"), "utf8");
    const depSection = text.match(/\[dependencies\]([\s\S]*?)(?:\n\[|\n*$)/);
    if (depSection) {
      for (const match of depSection[1].matchAll(/^([a-zA-Z0-9_-]+)\s*=/gm)) {
        deps[match[1].toLowerCase()] = "latest";
      }
    }
  } catch { /* no Cargo.toml */ }
  return deps;
}

async function readJavaDeps(root: string): Promise<DepMap> {
  const deps: DepMap = {};

  // build.gradle
  try {
    const text = await fs.readFile(path.join(root, "build.gradle"), "utf8");
    if (text.includes("spring-boot") || text.includes("org.springframework.boot")) {
      deps["spring-boot"] = "latest";
    }
  } catch { /* no build.gradle */ }

  // pom.xml
  try {
    const text = await fs.readFile(path.join(root, "pom.xml"), "utf8");
    if (text.includes("spring-boot") || text.includes("spring-boot-starter")) {
      deps["spring-boot"] = "latest";
    }
  } catch { /* no pom.xml */ }

  return deps;
}

async function readPythonDeps(root: string): Promise<DepMap> {
  const deps: DepMap = {};

  try {
    const text = await fs.readFile(path.join(root, "requirements.txt"), "utf8");
    for (const line of text.split(/\r?\n/)) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const name = trimmed.split(/[>=<\[!;]/)[0].trim().toLowerCase();
      if (name) deps[name] = "latest";
    }
  } catch { /* no requirements.txt */ }

  try {
    const text = await fs.readFile(path.join(root, "pyproject.toml"), "utf8");
    const depBlockMatch = text.match(/\[project\][\s\S]*?dependencies\s*=\s*\[([\s\S]*?)\]/);
    if (depBlockMatch) {
      for (const match of depBlockMatch[1].matchAll(/['"]([a-zA-Z0-9_-]+)/g)) {
        deps[match[1].toLowerCase()] = "latest";
      }
    }
  } catch { /* no pyproject.toml */ }

  return deps;
}

// ─── Stack detection ──────────────────────────────────────────────

function detectJsStack(deps: DepMap, devDeps: DepMap): StackType {
  if (deps.next || devDeps.next) return "nextjs";
  if (deps.fastify || devDeps.fastify) return "fastify";
  if (deps.express || devDeps.express) return "express";
  return "unknown";
}

function detectPythonStack(deps: DepMap): StackType {
  if (deps.fastapi) return "fastapi";
  if (deps.django) return "django";
  if (deps.flask) return "flask";
  return "unknown";
}

function detectGoStack(deps: DepMap): StackType {
  if (deps["github.com/gin-gonic/gin"]) return "gin";
  if (deps["github.com/labstack/echo"]) return "echo";
  if (deps["github.com/gofiber/fiber"]) return "fiber";
  return "unknown";
}

function detectRustStack(deps: DepMap): StackType {
  if (deps["actix-web"]) return "actix";
  if (deps["axum"]) return "axum";
  return "unknown";
}

function detectJavaStack(deps: DepMap): StackType {
  if (deps["spring-boot"]) return "spring-boot";
  return "unknown";
}

// ─── Main inventory builder ──────────────────────────────────────

export async function buildInventory(root: string): Promise<ProjectInventory> {
  const files = await walk(root);
  const hasDockerfile = files.some((f) => f === "Dockerfile" || f.endsWith("/Dockerfile"));

  // Try Node.js
  let packageJson: { dependencies?: DepMap; devDependencies?: DepMap } = { dependencies: {}, devDependencies: {} };
  try {
    packageJson = JSON.parse(await fs.readFile(path.join(root, "package.json"), "utf8"));
  } catch { /* no package.json */ }

  const dependencies = packageJson.dependencies ?? {};
  const devDependencies = packageJson.devDependencies ?? {};
  let stack = detectJsStack(dependencies, devDependencies);
  let apiRoutes: string[] = [];

  if (stack !== "unknown") {
    apiRoutes = stack === "nextjs"
      ? files.filter((f) => f.startsWith("app/api/") && f.endsWith("/route.ts"))
      : await findRoutes(root, files, JS_TS_EXTS, JS_ROUTE_PATTERNS, ["node_modules", ".next", "dist/"]);
  } else {
    // Try Python
    const pyDeps = await readPythonDeps(root);
    stack = detectPythonStack(pyDeps);
    if (stack !== "unknown") {
      apiRoutes = await findRoutes(root, files, PYTHON_EXTS, PYTHON_ROUTE_PATTERNS, ["__pycache__", ".venv", "venv/"]);
    } else {
      // Try Go
      const goDeps = await readGoDeps(root);
      stack = detectGoStack(goDeps);
      if (stack !== "unknown") {
        apiRoutes = await findRoutes(root, files, GO_EXTS, GO_ROUTE_PATTERNS, ["vendor/"]);
      } else {
        // Try Rust
        const rustDeps = await readCargoDeps(root);
        stack = detectRustStack(rustDeps);
        if (stack !== "unknown") {
          apiRoutes = await findRoutes(root, files, RUST_EXTS, RUST_ROUTE_PATTERNS, ["target/"]);
        } else {
          // Try Java
          const javaDeps = await readJavaDeps(root);
          stack = detectJavaStack(javaDeps);
          if (stack !== "unknown") {
            apiRoutes = await findRoutes(root, files, JAVA_EXTS, JAVA_ROUTE_PATTERNS, ["build/", "target/"]);
          }
        }
      }
    }
  }

  return {
    root,
    stack,
    apiRoutes,
    envExamplePath: files.includes(".env.example") ? ".env.example" : undefined,
    prismaSchemaPath: files.includes("prisma/schema.prisma") ? "prisma/schema.prisma" : undefined,
    migrationPaths: files.filter((f) => f.startsWith("prisma/migrations/") && f.endsWith(".sql")),
    hasDockerfile,
    packageJson: { dependencies, devDependencies },
  };
}
