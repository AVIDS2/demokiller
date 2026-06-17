import { analyzeFindings } from "./rules/index.js";
import { buildJsonReport } from "./report/json.js";
import { renderMarkdownReport } from "./report/markdown.js";
import { resolveRepository } from "./repository.js";
import path from "node:path";
import { pathToFileURL } from "node:url";

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export async function runCli(argv: string[] = process.argv.slice(2)): Promise<CliResult> {
  const command = argv[0];
  const input = argv[1] && !argv[1].startsWith("--") ? argv[1] : process.cwd();
  const wantsJson = argv.includes("--json");

  if (command !== "inspect") {
    return {
      exitCode: 1,
      stdout: "Usage: demokiller inspect [project-root-or-github-url] [--json|--markdown]",
      stderr: "",
    };
  }

  const resolved = await resolveRepository(input);
  try {
    const findings = await analyzeFindings(resolved.root);
    const report = buildJsonReport(findings);
    const stdout = wantsJson ? JSON.stringify(report, null, 2) : renderMarkdownReport(report);

    return { exitCode: 0, stdout, stderr: "" };
  } finally {
    await resolved.cleanup?.();
  }
}

export function isDirectCliInvocation(moduleUrl: string, argvPath?: string): boolean {
  if (!argvPath) return false;
  return moduleUrl === pathToFileURL(path.resolve(argvPath)).href;
}

if (isDirectCliInvocation(import.meta.url, process.argv[1])) {
  runCli().then((result) => {
    if (result.stdout) process.stdout.write(`${result.stdout}\n`);
    if (result.stderr) process.stderr.write(`${result.stderr}\n`);
    process.exitCode = result.exitCode;
  });
}
