import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

export async function observabilityFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".ts", ".tsx", ".js", ".jsx", ".py", ".go", ".rs", ".java", ".kt", ".rb"]);
  if (files.length === 0) return [];

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    fileContents.set(file, await readFileContent(root, file));
  }

  const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|testdata|samples|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party)(?:[\\/]|$)/i;
  const TEST_RE = /(?:^|[\\/])(?:test|tests|__tests__|spec|specs)(?:[\\/]|$)|[._](?:test|spec|e2e)\.[^.]+$/i;

  function isTestOrFixture(file: string): boolean {
    return FIXTURE_RE.test(file) || TEST_RE.test(file);
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

  // --- Route and language detection helpers ---

  const ROUTE_RE = /\b(?:app\.(?:get|post|put|patch|delete|use|route)|router\.(?:get|post|put|patch|delete|use|route))\s*\(|@(?:app|router)\.(?:get|post|put|patch|delete|route)\b|\br\.(?:GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc)\b/i;
  // Files that contain analysis/detection code, not actual web servers
  const ANALYSIS_INDICATORS_RE = /walkSourceFiles|walkPythonFiles|FUNC_PATTERNS|ROUTE_PATTERNS|extractFunctions|CallGraph|buildCallGraph|codegraph|detectNoAllowlist|detectUnsafeFs|routePresence/i;
  const JS_TS_RE = /\.[jt]sx?$/;
  const PY_RE = /\.py$/;

  // DK-OBS-010: No request ID propagation
  const REQUEST_ID_RE = /\b(?:request[_-]?id|requestId|x-request-id|correlation[_-]?id|correlationId|req[_-]?id|reqId|trace[_-]?id|traceId|x-trace)\b/i;
  const noRequestIdFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestOrFixture(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!ROUTE_RE.test(content)) continue;
    if (REQUEST_ID_RE.test(content)) continue;
    noRequestIdFiles.set(file, ["file has routes but no request ID / correlation ID middleware detected"]);
  }
  if (noRequestIdFiles.size > 0) {
    findings.push({
      ruleId: "DK-OBS-010",
      title: "No request ID propagation in web server file",
      severity: "high",
      confidence: "medium",
      missingControls: ["requestIdPropagation"],
      consequence: "Without request IDs, debugging production issues means searching millions of logs with no way to correlate entries from a single user request. This makes incident response impossible at scale.",
      acceptanceCriteria: [
        "Generate a UUID for every incoming request and attach it to the response header.",
        "Propagate the request ID through all log entries for that request.",
        "Pass request ID to downstream services for distributed tracing.",
      ],
      evidence: evidence(noRequestIdFiles, "obs-010"),
    });
  }

  // DK-OBS-011: No structured logging (console.log/print instead of logger)
  const noStructuredLogFiles = new Map<string, string[]>();
  const JS_CONSOLE_RE = /\bconsole\.(log|error|warn|debug)\s*\(/g;
  const JS_LOGGER_RE = /\blogger\.\w+|winston|pino|bunyan|log4js|morgan|debug\(|logging\.\w+|log\.info|log\.error|log\.warn|slog|zap\.|logrus/;
  // JSON.stringify({level/msg/...}) pattern = structured logging even without a library
  const STRUCTURED_CONSOLE_RE = /console\.\w+\s*\(\s*JSON\.stringify\s*\(\s*\{[^}]*(?:level|msg|message|severity|timestamp)\b/;
  const PY_PRINT_RE = /\bprint\s*\(/g;
  const PY_LOGGER_RE = /\blogging\.\w+|logger\.\w+|structlog|loguru/;
  for (const [file, content] of fileContents) {
    if (isTestOrFixture(file)) continue;
    if (JS_TS_RE.test(file)) {
      const consoleMatches = content.match(JS_CONSOLE_RE) ?? [];
      if (consoleMatches.length >= 3 && !JS_LOGGER_RE.test(content) && !STRUCTURED_CONSOLE_RE.test(content)) {
        noStructuredLogFiles.set(file, [`${consoleMatches.length} console.* calls but no structured logger detected`]);
      }
    } else if (PY_RE.test(file)) {
      const printMatches = content.match(PY_PRINT_RE) ?? [];
      if (printMatches.length >= 3 && !PY_LOGGER_RE.test(content)) {
        noStructuredLogFiles.set(file, [`${printMatches.length} print() calls but no structured logger detected`]);
      }
    }
  }
  if (noStructuredLogFiles.size > 0) {
    findings.push({
      ruleId: "DK-OBS-011",
      title: "No structured logging: console.log/print used instead of logger",
      severity: "medium",
      confidence: "high",
      missingControls: ["structuredLogging"],
      consequence: "Console.log produces unstructured text that can't be searched, filtered, or aggregated. In production, logs need to be machine-parseable JSON with severity levels, timestamps, and context fields.",
      acceptanceCriteria: [
        "Replace console.log with a structured logger (winston, pino, bunyan, etc.).",
        "Log in JSON format with timestamp, level, message, and context fields.",
        "Use appropriate log levels: error for failures, warn for degraded state, info for business events, debug for development.",
      ],
      evidence: evidence(noStructuredLogFiles, "obs-011"),
    });
  }

  // DK-OBS-012: No metrics endpoint
  const METRICS_RE = /\b(?:prometheus|metrics|StatsD|opentelemetry|@opentelemetry|prom-client|collectDefaultMetrics|\/metrics|histogram|counter|gauge)\b/i;
  const noMetricsFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestOrFixture(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (!ROUTE_RE.test(content)) continue;
    if (METRICS_RE.test(content)) continue;
    noMetricsFiles.set(file, ["file has routes but no metrics collection or /metrics endpoint detected"]);
  }
  if (noMetricsFiles.size > 0) {
    findings.push({
      ruleId: "DK-OBS-012",
      title: "No metrics endpoint or metrics collection",
      severity: "medium",
      confidence: "high",
      missingControls: ["metricsCollection"],
      consequence: "Without metrics, you're flying blind in production. You can't detect latency spikes, error rate increases, or capacity issues until users complain. Metrics are the foundation of operational awareness.",
      acceptanceCriteria: [
        "Expose a /metrics endpoint for Prometheus scraping.",
        "Track request count, latency histogram, and error rate per endpoint.",
        "Add business metrics for key operations (orders, signups, payments).",
      ],
      evidence: evidence(noMetricsFiles, "obs-012"),
    });
  }

  return findings;
}
