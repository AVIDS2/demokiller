import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;
const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;
const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe|agent-mcp|security-hardening|error-handling|performance-rules|observability|deployment-rules|python-rules|environment-rules)/;
const ANALYSIS_INDICATORS_RE = /walkSourceFiles|walkPythonFiles|FUNC_PATTERNS|ROUTE_PATTERNS|extractFunctions|CallGraph|buildCallGraph|detectMcp|detectUnsafe|walkSourceFiles|codegraph/i;
const INFRA_RE = /src[/\\](?:rules|call-graph|python-call-graph|source-inspector|cli|inventory)[/\\.]|(?:vscode-extension)/;

function evidence(hits: Map<string, string[]>, ruleId: string) {
  return [...hits.entries()].map(([file, signals]) => ({
    id: `${ruleId}-${file}`,
    detector: "pattern-match",
    location: { path: file },
    controls: [],
    signals
  }));
}

export async function shellFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".sh", ".bash", ".zsh", ".ksh"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-SHELL-001: Unquoted variable expansion
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*#/.test(line)) continue;
        // Look for $VAR or ${VAR} in command context without surrounding quotes
        // Exclude lines that are variable assignments (VAR=$OTHER)
        if (/^\s*\w+=/.test(line)) continue;
        // Find unquoted $VAR usage in command arguments
        const unquotedVars = line.match(/(?<=^|\s)\$\{?\w+\}?(?=\s|$|;|\||&|>|<)/g);
        if (unquotedVars) {
          // Check if the whole line has proper quoting
          if (!/(?:"\$[{]?\w+}|'\$\{?\w+}'|"\$\{?\w+")/.test(line)) {
            matches.push(`line ${i + 1}: unquoted variable — ${line.trim().slice(0, 60)}`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SHELL-001",
        title: "Unquoted variable expansion in shell script",
        severity: "high",
        confidence: "low",
        missingControls: ["variableQuoting"],
        consequence: "Unquoted variable expansion in shell scripts is subject to word splitting and glob expansion. This causes unexpected behavior with filenames containing spaces, newlines, or glob characters, and can lead to command injection.",
        acceptanceCriteria: [
          "Always double-quote variable expansions: \"$VAR\" instead of $VAR.",
          "Use \"${VAR}\" syntax for clarity and to avoid ambiguity.",
          "Enable set -u to catch unset variable references.",
        ],
        evidence: evidence(hits, "shell-001"),
      });
    }
  }

  // DK-SHELL-002: Command injection via eval
  // Narrowed: require user-input evidence near eval (not just any eval usage)
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*#/.test(line)) continue;
        // Direct eval usage — only flag if user-controlled input is nearby
        if (/\beval\b/.test(line) && !/^\s*#/.test(line)) {
          const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join("\n");
          // Only flag when eval operates on user-controllable variables
          const hasUserInput = /\$(?:1|2|\*|@|\{(?:1|2|\*|@)\})|(?:read|getopts|OPTARG)/.test(context) || /(?:curl|wget)\s/.test(context);
          if (hasUserInput) {
            matches.push(`line ${i + 1}: eval used with user-controlled input — command injection: ${line.trim().slice(0, 60)}`);
          }
        }
        // bash -c with variable interpolation — only flag with external input
        if (/bash\s+-c\s+["']?\$/.test(line)) {
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join("\n");
          const hasUserInput = /\$(?:1|2|\*|@)|read\s|getopts|OPTARG/.test(context);
          if (hasUserInput) {
            matches.push(`line ${i + 1}: bash -c with external input — command injection risk: ${line.trim().slice(0, 60)}`);
          }
        }
        // sh -c with variable
        if (/\bsh\s+-c\s+["']?\$/.test(line)) {
          const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join("\n");
          const hasUserInput = /\$(?:1|2|\*|@)|read\s|getopts|OPTARG/.test(context);
          if (hasUserInput) {
            matches.push(`line ${i + 1}: sh -c with external input — command injection risk: ${line.trim().slice(0, 60)}`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SHELL-002",
        title: "Command injection via eval or shell -c with user input",
        severity: "high",
        confidence: "medium",
        missingControls: ["commandInjectionPrevention"],
        consequence: "Using eval or passing variables to bash -c allows arbitrary command execution. If any variable contains user-controlled input, an attacker can execute arbitrary commands on the host.",
        acceptanceCriteria: [
          "Avoid eval entirely — use arrays, functions, or case statements instead.",
          "Never pass user-controlled variables to bash -c or sh -c.",
          "If eval is necessary, validate and sanitize all input with strict allowlists.",
        ],
        evidence: evidence(hits, "shell-002"),
      });
    }
  }

  // DK-SHELL-003: Missing set -e / set -euo pipefail
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      // Only check scripts that have a shebang
      if (!/^#!.*(?:bash|sh|zsh|ksh)/m.test(content)) continue;
      // Check for error handling
      const hasSetE = /\bset\s+.*-e/.test(content);
      const hasSetU = /\bset\s+.*-u/.test(content);
      const hasPipefail = /\bset\s+.*-o\s+pipefail/.test(content);
      const hasStrict = /\bset\s+-[a-z]*e[a-z]*u/.test(content) || /set\s+-euo\s+pipefail/.test(content);
      if (!hasSetE && !hasStrict) {
        hits.set(file, [`Script missing 'set -e' — errors will not cause script exit${!hasSetU ? ", missing 'set -u'" : ""}${!hasPipefail ? ", missing 'set -o pipefail'" : ""}`]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SHELL-003",
        title: "Missing error exit in shell script",
        severity: "medium",
        confidence: "high",
        missingControls: ["scriptErrorHandling"],
        consequence: "Shell scripts without set -e continue executing after errors, leading to cascading failures, partial deployments, and data corruption. A failed command that is silently ignored can cause unpredictable downstream behavior.",
        acceptanceCriteria: [
          "Add 'set -euo pipefail' at the top of every shell script after the shebang.",
          "Use trap to clean up resources on exit.",
          "Check exit codes of critical commands explicitly when set -e is not suitable.",
        ],
        evidence: evidence(hits, "shell-003"),
      });
    }
  }

  // DK-SHELL-004: Hardcoded secrets in scripts
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /\b(?:export\s+)?(?:.*(?:PASSWORD|TOKEN|SECRET|API_KEY|APIKEY|AUTH|CREDENTIAL|PASSWD).*)=(["']?)([A-Za-z0-9+/=_\-]{16,})\1/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[2];
        if (val && !/example|placeholder|test|dummy|xxx|changeme|YOUR_|REPLACE|\$\{|\$\(/i.test(val)) {
          // Simple entropy check
          const freq = new Map<string, number>();
          for (const c of val) freq.set(c, (freq.get(c) ?? 0) + 1);
          let entropy = 0;
          for (const count of freq.values()) {
            const p = count / val.length;
            entropy -= p * Math.log2(p);
          }
          if (entropy > 3.0) {
            matches.push(`hardcoded secret (len=${val.length}, entropy=${entropy.toFixed(1)}): ${m[0].slice(0, 60)}`);
          }
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SHELL-004",
        title: "Hardcoded secret in shell script",
        severity: "blocker",
        confidence: "high",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in shell scripts are exposed in version control, CI logs, process listings (ps), and environment dumps. This leads to credential compromise.",
        acceptanceCriteria: [
          "Load secrets from environment variables set by the deployment system.",
          "Use a secret manager (Vault, AWS SSM) to inject secrets at runtime.",
          "Never commit scripts containing real credentials — use .env and .gitignore.",
        ],
        evidence: evidence(hits, "shell-004"),
      });
    }
  }

  // DK-SHELL-005: Unsafe temp file creation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      const matches: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*#/.test(line)) continue;
        // Predictable temp file names
        if (/\/tmp\/\w+/.test(line) && !/mktemp/.test(line) && !/TMPDIR/.test(line)) {
          // Check if it's a direct file creation (not just referencing /tmp)
          if (/(?:>|touch|mkdir)\s*\/tmp\//.test(line) || /(?:=|echo)\s*\/tmp\//.test(line)) {
            matches.push(`line ${i + 1}: predictable temp file path: ${line.trim().slice(0, 60)}`);
          }
        }
        // mktemp without template (uses default which is ok, but check for patterns)
        if (/mktemp\s/.test(line) && /\/tmp\/.*XXXX/.test(line)) {
          // This is actually ok — mktemp with template in /tmp
          continue;
        }
        // Hardcoded temp file without mktemp
        if (/(?:TMP_FILE|TEMP_FILE|tmpfile)\s*=\s*["']?\/tmp\/[a-zA-Z0-9_]+["']?/.test(line)) {
          matches.push(`line ${i + 1}: hardcoded temp filename without mktemp: ${line.trim().slice(0, 60)}`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SHELL-005",
        title: "Unsafe temp file creation: predictable filenames",
        severity: "high",
        confidence: "medium",
        missingControls: ["secureTempFiles"],
        consequence: "Creating temp files with predictable names in /tmp enables symlink attacks where an attacker pre-creates a symlink at the expected path, causing the script to write to an arbitrary file. This can lead to privilege escalation or data corruption.",
        acceptanceCriteria: [
          "Always use mktemp to create temporary files with unpredictable names.",
          "Use 'mktemp -d' for temporary directories.",
          "Set restrictive permissions on temp files and clean up on exit with trap.",
        ],
        evidence: evidence(hits, "shell-005"),
      });
    }
  }

  return findings;
}
