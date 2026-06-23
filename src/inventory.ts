import { promises as fs } from "node:fs";
import path from "node:path";

export type StackType = "nextjs" | "express" | "fastify" | "unknown";

export interface ProjectInventory {
  root: string;
  stack: StackType;
  apiRoutes: string[];
  envExamplePath?: string;
  prismaSchemaPath?: string;
  migrationPaths: string[];
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
    if (entry.name === "node_modules" || entry.name === ".next" || entry.name === "dist") continue;

    if (entry.isDirectory()) {
      result.push(...(await walk(root, fullPath)));
    } else {
      result.push(path.relative(root, fullPath).replaceAll("\\", "/"));
    }
  }

  return result;
}

const SOURCE_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs"];

function isSourceFile(file: string): boolean {
  return SOURCE_EXTS.some((ext) => file.endsWith(ext));
}

async function fileContainsRoutePattern(root: string, file: string): Promise<boolean> {
  try {
    const text = await fs.readFile(path.join(root, file), "utf8");
    return (
      /\bapp\s*\.\s*(get|post|put|patch|delete)\s*\(/.test(text) ||
      /\brouter\s*\.\s*(get|post|put|patch|delete)\s*\(/.test(text) ||
      /\bfastify\s*\.\s*(get|post|put|patch|delete)\s*\(/.test(text) ||
      /\bfastify\s*\.\s*route\s*\(/.test(text)
    );
  } catch {
    return false;
  }
}

function detectStack(deps: Record<string, string>, devDeps: Record<string, string>): StackType {
  if (deps.next || devDeps.next) return "nextjs";
  if (deps.fastify || devDeps.fastify) return "fastify";
  if (deps.express || devDeps.express) return "express";
  return "unknown";
}

async function findExpressRoutes(root: string, files: string[]): Promise<string[]> {
  const candidates = files.filter((f) => {
    if (!isSourceFile(f)) return false;
    if (f.includes("node_modules") || f.includes(".next") || f.includes("dist/")) return false;
    if (f.includes("test") || f.includes("spec") || f.includes("__test")) return false;
    if (f.includes("routes/") || f.includes("route.") || f.includes("api/")) return true;
    return true;
  });

  const results: string[] = [];
  for (const file of candidates) {
    if (await fileContainsRoutePattern(root, file)) {
      results.push(file);
    }
  }
  return results;
}

export async function buildInventory(root: string): Promise<ProjectInventory> {
  const packageJsonPath = path.join(root, "package.json");
  let packageJson: {
    dependencies?: Record<string, string>;
    devDependencies?: Record<string, string>;
  } = { dependencies: {}, devDependencies: {} };

  try {
    packageJson = JSON.parse(await fs.readFile(packageJsonPath, "utf8"));
  } catch {
    // no package.json — treat as unknown
  }

  const files = await walk(root);
  const dependencies = packageJson.dependencies ?? {};
  const devDependencies = packageJson.devDependencies ?? {};
  const stack = detectStack(dependencies, devDependencies);

  let apiRoutes: string[];
  if (stack === "nextjs") {
    apiRoutes = files.filter((file) => file.startsWith("app/api/") && file.endsWith("/route.ts"));
  } else if (stack === "express" || stack === "fastify") {
    apiRoutes = await findExpressRoutes(root, files);
  } else {
    apiRoutes = [];
  }

  return {
    root,
    stack,
    apiRoutes,
    envExamplePath: files.includes(".env.example") ? ".env.example" : undefined,
    prismaSchemaPath: files.includes("prisma/schema.prisma") ? "prisma/schema.prisma" : undefined,
    migrationPaths: files.filter(
      (file) => file.startsWith("prisma/migrations/") && file.endsWith(".sql"),
    ),
    packageJson: { dependencies, devDependencies },
  };
}
