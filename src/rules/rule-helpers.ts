import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { promises as fs } from "node:fs";
import path from "node:path";

const SKIP = new Set(["node_modules","dist","build",".git","__pycache__","target","vendor",".next","out"]);

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
