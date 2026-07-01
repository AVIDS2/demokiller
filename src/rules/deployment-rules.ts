import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import path from "node:path";
import { promises as fs } from "node:fs";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|testdata|samples|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party)(?:[\\/]|$)/i;

export async function deploymentFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [
    ".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".java", ".kt", ".rb",
    ".yaml", ".yml", ".toml", ".json",
  ]);

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    fileContents.set(file, await readFileContent(root, file));
  }

  function evidence(hits: Map<string, string[]>, ruleId: string) {
    return [...hits.entries()].map(([file, signals]) => ({
      id: `${ruleId}-${file}`,
      detector: "pattern-match",
      location: { path: file },
      controls: [],
      signals
    }));
  }

  // --- DK-DEPLOY-001: No CI/CD pipeline configuration ---
  {
    const ciPatterns = [
      ".github/workflows/",
      ".gitlab-ci.yml",
      "Jenkinsfile",
      ".circleci/config.yml",
      "bitbucket-pipelines.yml",
      ".travis.yml",
      "azure-pipelines.yml",
    ];

    let hasCiConfig = false;
    // Walk all files including yaml/yml/json to find CI configs
    for (const file of files) {
      if (FIXTURE_RE.test(file)) continue;
      const normalized = file.replace(/\\/g, "/");
      if (ciPatterns.some(pattern => normalized.includes(pattern) || normalized === pattern.replace(/\/$/, ""))) {
        hasCiConfig = true;
        break;
      }
    }

    if (!hasCiConfig) {
      // Skip libraries — they are not deployed apps and don't need CI/CD pipelines
      const DEPLOYABLE_KINDS = new Set(["web-app", "web-api", "mq-worker", "cli-tool", "agent-app", "serverless-func", "payment-system", "auth-service", "api-gateway"]);
      // Check if this looks like a software project (has package.json or requirements.txt)
      const hasPackageJson = files.some(f => f === "package.json" || f.endsWith("/package.json"));
      const hasRequirementsTxt = files.some(f => f === "requirements.txt" || f.endsWith("/requirements.txt"));
      const isSoftwareProject = hasPackageJson || hasRequirementsTxt;

      if (isSoftwareProject && DEPLOYABLE_KINDS.has(inventory.projectKind)) {
        let confidence: "high" | "medium" = "high";

        // Downgrade confidence if package.json has a ci or test script
        if (hasPackageJson) {
          const pkgFile = files.find(f => f === "package.json" || f.endsWith("/package.json"));
          if (pkgFile) {
            const content = fileContents.get(pkgFile) ?? await readFileContent(root, pkgFile);
            try {
              const pkg = JSON.parse(content);
              if (pkg?.scripts?.ci || pkg?.scripts?.test) {
                confidence = "medium";
              }
            } catch {
              // ignore parse errors
            }
          }
        }

        findings.push({
          ruleId: "DK-DEPLOY-001",
          title: "No CI/CD pipeline configuration found",
          severity: "high",
          confidence,
          missingControls: ["ciCdPipeline"],
          consequence: "Without CI/CD, every deployment is a manual, error-prone process. There's no automated gate to catch regressions, no reproducible builds, and no audit trail of what was deployed when.",
          acceptanceCriteria: [
            "Add a CI pipeline (.github/workflows, .gitlab-ci.yml, etc.).",
            "Run tests automatically on every push and pull request.",
            "Include linting and type checking in the pipeline.",
            "Automate deployment to staging on merge to main.",
          ],
          evidence: [{
            id: "deploy-001-root",
            detector: "pattern-match",
            location: { path: "(project root)" },
            controls: [],
            signals: ["No CI/CD configuration files found (.github/workflows, .gitlab-ci.yml, Jenkinsfile, etc.)"],
          }],
        });
      }
    }
  }

  // --- DK-DEPLOY-002: No health check depth (shallow /health endpoint) ---
  {
    const healthRouteRe = /(?:app|router|server)\s*\.\s*(?:get|all|use)\s*\(\s*['"`](?:\/health|\/healthz|\/healthcheck|\/ping|\/ready|\/readiness|\/alive|\/liveness)['"`]/g;
    const deepCheckPatterns = /(?:SELECT\s+1|ping\s*\(\)|getConnection|db\.query|redis\.ping|mongoose\.connection|sequelize\.authenticate|knex\.raw|amqp\.connect|connect\s*\(\s*\))/i;
    const shallowResponseRe = /(?:res\.json\s*\(\s*\{[^}]*status\s*:\s*['"]ok['"]|res\.sendStatus\s*\(\s*200\s*\)|res\.send\s*\(\s*['"]ok['"]|return\s+['"]ok['"]|return\s+['"]healthy['"])/i;

    const healthFiles = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (FIXTURE_RE.test(file)) continue;
      if (/\.(?:test|spec)\.\w+$/.test(file)) continue;

      const routeMatches = [...content.matchAll(healthRouteRe)];
      if (routeMatches.length === 0) continue;

      for (const match of routeMatches) {
        const startIdx = match.index ?? 0;
        // Look at the ~10 lines after the route definition (approx 500 chars)
        const snippet = content.slice(startIdx, startIdx + 500);
        const lines = content.slice(0, startIdx).split(/\r?\n/).length;

        // Check if the handler contains deep check patterns
        if (deepCheckPatterns.test(snippet)) continue;

        // If it only returns a shallow response, flag it
        if (shallowResponseRe.test(snippet)) {
          const existing = healthFiles.get(file) ?? [];
          existing.push(`line ${lines}: shallow health check — only returns status without verifying dependencies`);
          healthFiles.set(file, existing);
        }
      }
    }

    if (healthFiles.size > 0) {
      findings.push({
        ruleId: "DK-DEPLOY-002",
        title: "Shallow health check endpoint does not verify dependencies",
        severity: "medium",
        confidence: "high",
        missingControls: ["healthCheckDepth"],
        consequence: "A health check that always returns 200 is worse than no health check — it gives false confidence. The app appears healthy while the database is down, the cache is cold, and every user request fails.",
        acceptanceCriteria: [
          "Health check must verify connectivity to all critical dependencies (database, cache, message queue).",
          "Return degraded status (503) when any dependency is unreachable.",
          "Include response time measurements for dependency checks.",
          "Separate liveness (/alive) from readiness (/ready) probes.",
        ],
        evidence: evidence(healthFiles, "deploy-002"),
      });
    }
  }

  // --- DK-DEPLOY-003: Container runs as root (Dockerfile USER not set) ---
  {
    // Find all Dockerfile* files (not filtered by walkSourceFiles since Dockerfiles have no extension)
    const dockerfiles: string[] = [];
    for (const file of files) {
      // Dockerfiles aren't in the standard extension list, so we also check by name
      const normalized = file.replace(/\\/g, "/");
      if (/Dockerfile/i.test(normalized) || /dockerfile/i.test(normalized)) {
        dockerfiles.push(file);
      }
    }

    // If walkSourceFiles didn't find Dockerfiles, try directly looking for them
    if (dockerfiles.length === 0) {
      try {
        async function findDockerfiles(dir: string): Promise<string[]> {
          const results: string[] = [];
          const SKIP_DIRS = new Set([
            "node_modules", "dist", "build", ".git", "__pycache__", "target", "vendor",
            ".next", "out", "fixtures", "testdata", "samples", ".worktrees",
          ]);
          async function walk(dir: string) {
            const entries = await fs.readdir(dir, { withFileTypes: true });
            for (const e of entries) {
              if (SKIP_DIRS.has(e.name)) continue;
              const full = path.join(dir, e.name);
              if (e.isDirectory()) await walk(full);
              else if (/^Dockerfile/i.test(e.name) || /^dockerfile/i.test(e.name)) {
                results.push(path.relative(dir === root ? root : root, full).replaceAll("\\", "/"));
              }
            }
          }
          await walk(dir);
          return results;
        }

        const found = await findDockerfiles(root);
        for (const f of found) {
          dockerfiles.push(f);
          fileContents.set(f, await readFileContent(root, f));
        }
      } catch {
        // ignore
      }
    }

    const rootDockerFiles = new Map<string, string[]>();
    for (const file of dockerfiles) {
      if (FIXTURE_RE.test(file)) continue;
      const content = fileContents.get(file) ?? await readFileContent(root, file);

      // Check for USER directive (excluding USER root)
      const userDirectives = content.match(/^\s*USER\s+(\S+)/gim) ?? [];
      const hasNonRootUser = userDirectives.some(d => {
        const match = d.match(/^\s*USER\s+(\S+)/i);
        return match && match[1].toLowerCase() !== "root";
      });

      if (!hasNonRootUser) {
        rootDockerFiles.set(file, ["No non-root USER directive — container will run as root"]);
      }
    }

    // Also check docker-compose files for --user flags
    for (const [file, content] of fileContents) {
      if (!/docker-compose/i.test(file) && !/compose\.(ya?ml|json)$/i.test(file)) continue;
      if (FIXTURE_RE.test(file)) continue;

      // If the compose file has "user:" entries, note them
      const hasUserDirective = /^\s*user\s*:/gim.test(content);
      if (!hasUserDirective) {
        // Check if there are Dockerfile references
        const usesDockerfile = /build\s*:/i.test(content) || /dockerfile\s*:/i.test(content);
        if (usesDockerfile && rootDockerFiles.size === 0) {
          rootDockerFiles.set(file, ["docker-compose build without user directive — containers may run as root"]);
        }
      }
    }

    if (rootDockerFiles.size > 0) {
      findings.push({
        ruleId: "DK-DEPLOY-003",
        title: "Container runs as root: no non-root USER directive in Dockerfile",
        severity: "high",
        confidence: "high",
        missingControls: ["containerNonRootUser"],
        consequence: "Containers running as root can be exploited to gain root access on the host. A single container escape vulnerability gives the attacker full control of the host system.",
        acceptanceCriteria: [
          "Add USER directive after installing dependencies.",
          "Create a dedicated non-root user for the application.",
          "Never use USER root in production Dockerfiles.",
          "Use multi-stage builds to keep the final image minimal.",
        ],
        evidence: evidence(rootDockerFiles, "deploy-003"),
      });
    }
  }

  // --- DK-DEPLOY-004: .env file committed to version control ---
  {
    const envFiles = new Map<string, string[]>();
    const dangerousEnvNames = [".env", ".env.local", ".env.production", ".env.staging"];
    const dangerousEnvRe = /\.env\.(?:local|production|staging|prod)$/i;
    const safeEnvRe = /\.env\.(?:example|template|test|sample|development)$/i;

    // Find .env files in the project
    for (const file of files) {
      const normalized = file.replace(/\\/g, "/");
      const basename = normalized.split("/").pop() ?? "";
      // Only check root-level env files (or top-level .env)
      if (!basename.startsWith(".env")) continue;
      if (safeEnvRe.test(normalized)) continue;
      if (FIXTURE_RE.test(file)) continue;

      // Only flag if the file is at the project root or very close
      const depth = normalized.split("/").length;
      if (depth > 2) continue; // skip deeply nested env files

      if (dangerousEnvNames.includes(basename) || dangerousEnvRe.test(basename)) {
        // Check if .gitignore covers this
        let gitignoreContent = "";
        try {
          gitignoreContent = await readFileContent(root, ".gitignore");
        } catch {
          // no .gitignore
        }

        const gitignoreLines = gitignoreContent.split(/\r?\n/).map(l => l.trim());
        const isIgnored = gitignoreLines.some(line => {
          if (!line || line.startsWith("#")) return false;
          // Match .env, .env.*, *.env patterns
          if (line === basename) return true;
          if (line === ".env" && basename.startsWith(".env")) return true;
          if (line === ".env*" || line === ".env.*") return true;
          if (line.endsWith("/.env") && basename === ".env") return true;
          return false;
        });

        if (!isIgnored) {
          const signals: string[] = [`${basename} exists and is not listed in .gitignore`];
          // Check if the file contains actual secrets (key=value patterns)
          const content = fileContents.get(file) ?? await readFileContent(root, file);
          const secretPatterns = /=\s*\S+/.test(content);
          if (secretPatterns) {
            signals.push("File contains key=value pairs that may be real secrets");
          }
          envFiles.set(file, signals);
        }
      }
    }

    // Also check if .gitignore exists at all and is missing .env
    if (envFiles.size === 0) {
      // Even if no .env files are found, check if .gitignore is missing .env
      // This is a warning that .env would not be ignored if created
      // Only flag if .gitignore exists but doesn't contain .env
      let gitignoreContent = "";
      try {
        gitignoreContent = await readFileContent(root, ".gitignore");
      } catch {
        // no .gitignore at all — don't flag this case (covered by other rules)
      }

      if (gitignoreContent && !/(?:^|\n)\s*\.env[\s.*]/m.test(gitignoreContent) && !/(?:^|\n)\s*\.env\s*$/m.test(gitignoreContent)) {
        // .gitignore exists but doesn't contain .env — only flag if there are actual .env files we may have missed
        // We already checked above, so this is a no-op in most cases
      }
    }

    if (envFiles.size > 0) {
      findings.push({
        ruleId: "DK-DEPLOY-004",
        title: ".env file committed to version control without .gitignore protection",
        severity: "blocker",
        confidence: "high",
        missingControls: ["secretManagement"],
        consequence: "A .env file in version control exposes every secret: database passwords, API keys, encryption keys. Anyone with repo access (or if the repo is public, anyone on the internet) can read them.",
        acceptanceCriteria: [
          "Add .env to .gitignore.",
          "Only commit .env.example with placeholder values.",
          "Use secrets management (Vault, AWS Secrets Manager, etc.) for production secrets.",
          "Rotate all exposed credentials immediately if .env was committed.",
        ],
        evidence: evidence(envFiles, "deploy-004"),
      });
    }
  }

  return findings;
}
