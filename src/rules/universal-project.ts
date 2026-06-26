import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

export function cliEntryPointFindings(inventory: ProjectInventory): Finding[] {
  // Only fires for non-web projects (CLI, library, tool)
  if (inventory.apiRoutes.length > 0) return [];
  if (inventory.isNpmPackage === false && inventory.hasTypeScript === false) return [];

  // For CLI/bin projects: check for common safety patterns
  const warnings: Finding[] = [];

  // Check bin entry safety from package.json
  const deps = inventory.packageJson?.dependencies ?? {};
  const devDeps = inventory.packageJson?.devDependencies ?? {};
  const hasBinEntry = !!(inventory as any)._hasBinEntry;

  // Signal handling for CLI apps
  warnings.push({
    ruleId: "DK-UNIVERSAL-001",
    title: "CLI/library project — verify production readiness beyond web API checks",
    severity: "advisory",
    confidence: "medium",
    missingControls: ["universalChecks"],
    consequence: "Demo Killer's web-focused checks (auth, webhook, CORS, etc.) do not apply to this project type. Verify CLI-specific safety: argument validation, signal handling, error exit codes.",
    acceptanceCriteria: [
      "CLI arguments are validated (missing required args produce clear errors).",
      "SIGTERM/SIGINT handlers exist for graceful shutdown.",
      "Non-zero exit codes on errors for CI integration.",
      "Library exports include TypeScript types.",
      "Sensitive files are excluded from npm publish via .npmignore or files field."
    ],
    evidence: [{ id: "project-type", detector: "inventory", location: { path: "package.json" }, controls: [], signals: ["non-web project"] }],
  });

  return warnings;
}
