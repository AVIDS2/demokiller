#!/usr/bin/env node
import { analyzeFindings } from "./rules/index.js";
import { buildInventory } from "./inventory.js";
import { loadConfig, applyConfig } from "./config.js";
import { loadBenchmarkManifest } from "./benchmark.js";
import { initializeProject } from "./init.js";
import { runBenchmarkSuite } from "./benchmark-runner.js";
import { buildJsonReport } from "./report/json.js";
import { renderBenchmarkMarkdown } from "./report/benchmark-markdown.js";
import { renderMarkdownReport } from "./report/markdown.js";
import { renderColoredReport } from "./report/colored.js";
import { renderHtmlReport } from "./report/html.js";
import { resolveRepository } from "./repository.js";
import { diffSnapshots } from "./state.js";
import { toSarif } from "./sarif.js";
import { loadBaseline, saveBaseline, diffFindings } from "./baseline.js";
import { findSuppressionComments } from "./suppressions.js";
import path from "node:path";

const SUPPORTED_STACKS = [
  "nextjs", "express", "fastify", "flask", "fastapi", "django",
  "gin", "echo", "fiber", "actix", "axum", "rocket",
  "spring-boot", "ktor", "laravel", "rails", "sinatra",
  "aspnet", "vapor", "http4s", "akka",
];
import { pathToFileURL } from "node:url";
import type { AnalysisReport, Finding } from "./types.js";
import type { ResolvedRepository } from "./repository.js";
import type { ProjectInventory } from "./inventory.js";

export interface CliResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export interface CliDependencies {
  resolveRepository(input: string): Promise<ResolvedRepository>;
  analyzeFindings(root: string): Promise<{ findings: Finding[]; inventory: ProjectInventory }>;
  hasSupportedProjectEvidence(root: string): Promise<boolean>;
}

const defaultDependencies: CliDependencies = {
  resolveRepository,
  analyzeFindings,
  hasSupportedProjectEvidence: async (root) => {
    const inventory = await buildInventory(root);
    return SUPPORTED_STACKS.includes(inventory.stack) && inventory.apiRoutes.length > 0;
  },
};

const usage = [
  "Usage: demokiller init [project-root]",
  "       demokiller inspect [project-root-or-github-url] [--json|--markdown]",
  "       demokiller recheck [project-root] [--snapshot <path>] [--json|--markdown]",
  "       demokiller benchmark [manifest-path]",
].join("\n");

const DEFAULT_SNAPSHOT = ".demokiller/last-report.json";

async function runInspection(
  input: string,
  dependencies: CliDependencies,
): Promise<{ report: AnalysisReport; resolved: ResolvedRepository }> {
  const resolved = await dependencies.resolveRepository(input);
  const { findings, inventory } = await dependencies.analyzeFindings(resolved.root);
  const config = await loadConfig(resolved.root);
  const filteredFindings = applyConfig(findings, config);
  const hasEvidence = SUPPORTED_STACKS.includes(inventory.stack) && inventory.apiRoutes.length > 0;
  const report = buildJsonReport(filteredFindings, new Date().toISOString(), {
    hasSupportedProjectEvidence: hasEvidence,
  });
  return { report, resolved };
}

export async function runCli(
  argv: string[] = process.argv.slice(2),
  dependencies: CliDependencies = defaultDependencies,
): Promise<CliResult> {
  const command = argv[0];
  const input = argv[1] && !argv[1].startsWith("--") ? argv[1] : process.cwd();
  const wantsJson = argv.includes("--json");
  const formatFlag = argv.find(a => a.startsWith("--format="))?.split("=")[1]
    || (argv.includes("--format") ? argv[argv.indexOf("--format") + 1] : undefined)
    || (wantsJson ? "json" : undefined);
  const baselineIdx = argv.indexOf("--baseline");
  const baselinePath = baselineIdx >= 0 && argv[baselineIdx + 1] ? argv[baselineIdx + 1] : undefined;
  const wantsSaveBaseline = argv.includes("--save-baseline");
  const severityIdx = argv.indexOf("--severity");
  const minSeverity = severityIdx >= 0 && argv[severityIdx + 1] ? argv[severityIdx + 1] : undefined;

  const SEVERITY_ORDER = ["advisory", "low", "medium", "high", "blocker"];

  if (!command || command === "--help" || command === "-h") {
    return {
      exitCode: 0,
      stdout: usage,
      stderr: "",
    };
  }

  if (command === "init") {
    try {
      const result = await initializeProject(input);
      const files = result.files.map((file) => `- ${file.path}: ${file.status}`).join("\n");
      return {
        exitCode: 0,
        stdout: `Initialized Demo Killer in ${result.root}\n\n${files}`,
        stderr: "",
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        exitCode: 1,
        stdout: "",
        stderr: `Failed to initialize Demo Killer: ${message}`,
      };
    }
  }

  if (command === "benchmark") {
    const manifestPath = input;
    const samples = await loadBenchmarkManifest(manifestPath);
    const benchmark = await runBenchmarkSuite(samples, {
      inspectRepository: async (sample) => {
        const resolved = await dependencies.resolveRepository(sample.repo);
        try {
          const { findings, inventory } = await dependencies.analyzeFindings(resolved.root);
          const hasEvidence = inventory.stack === "nextjs" && inventory.apiRoutes.length > 0;
          return buildJsonReport(findings, new Date().toISOString(), {
            hasSupportedProjectEvidence: hasEvidence,
          });
        } finally {
          await resolved.cleanup?.();
        }
      },
    });

    return {
      exitCode: 0,
      stdout: renderBenchmarkMarkdown(benchmark),
      stderr: "",
    };
  }

  if (command === "recheck") {
    const snapshotIdx = argv.indexOf("--snapshot");
    const snapshotPath =
      snapshotIdx >= 0 && argv[snapshotIdx + 1] ? argv[snapshotIdx + 1] : DEFAULT_SNAPSHOT;

    try {
      const { promises: fs } = await import("node:fs");
      const previous: AnalysisReport = JSON.parse(await fs.readFile(snapshotPath, "utf8"));
      const { report: current, resolved } = await runInspection(input, dependencies);
      await resolved.cleanup?.();

      const diff = diffSnapshots(previous, current);
      const result = {
        previousVerdict: diff.previousVerdict,
        currentVerdict: diff.currentVerdict,
        resolved: diff.resolvedRuleIds,
        remaining: diff.remainingRuleIds,
        newFindings: diff.newRuleIds,
      };

      if (wantsJson) {
        return { exitCode: 0, stdout: JSON.stringify(result, null, 2), stderr: "" };
      }

      const lines = [
        `Previous verdict: ${diff.previousVerdict}`,
        `Current verdict:  ${diff.currentVerdict}`,
        "",
      ];
      if (diff.resolvedRuleIds.length > 0) {
        lines.push(`Resolved (${diff.resolvedRuleIds.length}):`, ...diff.resolvedRuleIds.map((id) => `  + ${id}`), "");
      }
      if (diff.newRuleIds.length > 0) {
        lines.push(`New findings (${diff.newRuleIds.length}):`, ...diff.newRuleIds.map((id) => `  ! ${id}`), "");
      }
      if (diff.remainingRuleIds.length > 0) {
        lines.push(`Remaining (${diff.remainingRuleIds.length}):`, ...diff.remainingRuleIds.map((id) => `  - ${id}`));
      }
      return { exitCode: 0, stdout: lines.join("\n"), stderr: "" };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        exitCode: 1,
        stdout: "",
        stderr: `Failed to recheck: ${message}`,
      };
    }
  }

  if (command === "inspect") {
    try {
      const { report, resolved } = await runInspection(input, dependencies);

      try {
        const { promises: fs } = await import("node:fs");
        await fs.mkdir(path.dirname(DEFAULT_SNAPSHOT), { recursive: true });
        await fs.writeFile(DEFAULT_SNAPSHOT, JSON.stringify(report, null, 2), "utf8");
      } catch {
        // snapshot save is best-effort
      }

      const wantsWatch = argv.includes("--watch");

      // Watch mode: loop and re-inspect on file changes
      if (wantsWatch) {
        const dim = "\x1b[2m", red = "\x1b[31m", green = "\x1b[32m", reset = "\x1b[0m";
        process.stdout.write(renderColoredReport(report));
        process.stdout.write("\n" + dim + "  Watching for changes... (Ctrl+C to stop)" + reset + "\n");
        await resolved.cleanup?.();

        const { watch } = await import("node:fs");
        let lastFindingsCount = report.findings.length;
        let lastBlockers = report.findings.filter(f => f.severity === "blocker").length;

        // Polling-based watch (works cross-platform)
        let timer: ReturnType<typeof setInterval>;
        await new Promise<void>((_resolve) => {
          timer = setInterval(async () => {
            try {
              const reResolved = await dependencies.resolveRepository(input);
              try {
                const reResult = await dependencies.analyzeFindings(reResolved.root);
                const cfg = await loadConfig(reResolved.root);
                const filtered = applyConfig(reResult.findings, cfg);
                const stacks = ["nextjs", "express", "fastify", "flask", "fastapi", "django", "gin", "echo", "fiber", "actix", "axum", "rocket", "spring-boot", "ktor", "laravel", "rails", "sinatra", "aspnet", "vapor", "http4s", "akka"];
                const hasEv = stacks.includes(reResult.inventory.stack) && reResult.inventory.apiRoutes.length > 0;
                const newReport = buildJsonReport(filtered, new Date().toISOString(), { hasSupportedProjectEvidence: hasEv });
                const newBlockers = newReport.findings.filter(f => f.severity === "blocker").length;

                if (newReport.findings.length !== lastFindingsCount || newBlockers !== lastBlockers) {
                  // Clear screen
                  process.stdout.write("\x1b[2J\x1b[H");
                  process.stdout.write(renderColoredReport(newReport));
                  const delta = newReport.findings.length - lastFindingsCount;
                  const blockerDelta = newBlockers - lastBlockers;
                  if (delta !== 0) {
                    process.stdout.write(`${delta > 0 ? red : green}  ${delta > 0 ? "+" : ""}${delta} findings${reset}\n`);
                  }
                  if (blockerDelta !== 0) {
                    process.stdout.write(`${blockerDelta > 0 ? red : green}  ${blockerDelta > 0 ? "+" : ""}${blockerDelta} blockers${reset}\n`);
                  }
                  process.stdout.write("\n" + dim + "  Watching for changes... (Ctrl+C to stop)" + reset + "\n");
                  lastFindingsCount = newReport.findings.length;
                  lastBlockers = newBlockers;
                }
              } finally {
                await reResolved.cleanup?.();
              }
            } catch { /* ignore re-inspection errors */ }
          }, 3000);
        });

        clearInterval(timer!);
        return { exitCode: 0, stdout: "", stderr: "" };
      }

      const wantsMarkdown = argv.includes("--markdown");
      const wantsHtml = argv.includes("--html");

      // Severity filtering
      let outputFindings = report.findings;
      if (minSeverity) {
        const minIdx = SEVERITY_ORDER.indexOf(minSeverity);
        if (minIdx >= 0) {
          outputFindings = outputFindings.filter(f => SEVERITY_ORDER.indexOf(f.severity) >= minIdx);
        }
      }

      // Baseline diff
      if (baselinePath) {
        try {
          const baseline = await loadBaseline(baselinePath);
          const diff = diffFindings(outputFindings, baseline);
          outputFindings = diff.newFindings;
          // Report fixed findings
          if (diff.fixedFindings.length > 0) {
            process.stdout.write(`\x1b[32m  ${diff.fixedFindings.length} findings resolved since baseline\x1b[0m\n`);
          }
          if (diff.existingFindings.length > 0) {
            process.stdout.write(`\x1b[2m  ${diff.existingFindings.length} findings suppressed (in baseline)\x1b[0m\n`);
          }
        } catch { /* no baseline file — treat all as new */ }
      }

      // Inline suppression
      const { promises: fsProm } = await import("node:fs");
      outputFindings = (await Promise.all(outputFindings.map(async (f) => {
        const loc = f.evidence?.[0]?.location?.path;
        if (!loc) return f;
        try {
          const fullPath = path.join(resolved.root, loc);
          const content = await fsProm.readFile(fullPath, "utf8");
          if (findSuppressionComments(content, f.ruleId)) return null;
        } catch {}
        return f;
      }))).filter((f): f is Finding => f !== null);

      const reportFiltered = { ...report, findings: outputFindings };

      // Save baseline
      if (wantsSaveBaseline) {
        await saveBaseline(report.findings, ".demokiller/baseline.json");
        process.stdout.write("\x1b[32m  Baseline saved to .demokiller/baseline.json\x1b[0m\n");
      }

      const stdout = formatFlag === "sarif"
        ? JSON.stringify(toSarif(reportFiltered), null, 2)
        : wantsJson
          ? JSON.stringify(reportFiltered, null, 2)
          : wantsHtml
            ? renderHtmlReport(reportFiltered)
            : wantsMarkdown
              ? renderMarkdownReport(reportFiltered)
              : renderColoredReport(reportFiltered);
      await resolved.cleanup?.();
      return { exitCode: 0, stdout, stderr: "" };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      return {
        exitCode: 1,
        stdout: "",
        stderr: `Failed to inspect repository: ${message}`,
      };
    }
  }

  return {
    exitCode: 1,
    stdout: usage,
    stderr: "",
  };
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
