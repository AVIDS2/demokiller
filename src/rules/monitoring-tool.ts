import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function monitoringToolFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "monitoring-tool") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx",".go",".py"]);
  if (files.length === 0) return [];

  const perFileContent: Map<string, string> = new Map();
  for (const f of files) {
    perFileContent.set(f, await readFileContent(root, f));
  }
  const allContent = [...perFileContent.values()].join("\n");

  // DK-MON-001: Unauthenticated metrics endpoint
  const mon001Pattern = /\/metrics|\/actuator|\/prometheus/gi;
  const mon001AuthPattern = /auth|token|ip.*allow|middleware|authenticate|authorize/gi;
  for (const [filePath, content] of perFileContent) {
    if (safeTest(mon001Pattern, content) && !safeTest(mon001AuthPattern, content)) {
      findings.push({
        ruleId: "DK-MON-001",
        title: "Unauthenticated metrics endpoint",
        severity: "high",
        confidence: "medium",
        missingControls: ["Authentication on metrics endpoint", "IP allowlisting", "Token-based access"],
        consequence: "Metrics endpoints are publicly accessible without authentication, exposing internal system details, performance data, and potentially sensitive labels to unauthorized users.",
        acceptanceCriteria: [
          "Add authentication middleware to /metrics, /actuator, and /prometheus endpoints",
          "Restrict access by IP allowlist or network policy",
          "Document required access controls for metrics endpoints"
        ],
        evidence: [{
          id: "mon-001-metrics-no-auth",
          detector: "pattern-match",
          location: { path: filePath },
          controls: [],
          signals: ["metrics endpoint found without authentication middleware"]
        }]
      });
      break; // one finding is enough
    }
  }

  // DK-MON-002: Sensitive data in health checks — require both patterns in the SAME file
  for (const [filePath, content] of perFileContent) {
    if (/\/health|\/healthz|\/readyz/i.test(content) && /env|secrets|db.*url|password|api.*key|process\.env/i.test(content)) {
      findings.push({
        ruleId: "DK-MON-002",
        title: "Sensitive data exposed in health check responses",
        severity: "high",
        confidence: "medium",
        missingControls: ["Sanitize health check responses", "Remove environment variables from output", "Separate liveness from readiness probes"],
        consequence: "Health check endpoints expose sensitive environment variables (database URLs, API keys, passwords) in their JSON responses, which can be accessed by anyone who can reach the endpoint.",
        acceptanceCriteria: [
          "Remove all environment variables and secrets from health check response bodies",
          "Return only status indicators (ok/degraded/down) in health checks",
          "Use separate endpoints for liveness (simple status) and readiness (dependency checks without leaking credentials)"
        ],
        evidence: [{
          id: "mon-002-health-leaks-secrets",
          detector: "pattern-match",
          location: { path: filePath },
          controls: [],
          signals: ["health endpoint exposes process.env variables in the same file"]
        }]
      });
      break;
    }
  }

  // DK-MON-003: Metric cardinality explosion — require metric library context, not just generic words
  const mon003Pattern = /new\s+Counter|Counter\(|\.inc\(|\.labels\(|new\s+Gauge|new\s+Histogram/gi;
  const mon003Labels = /user_id.*label|label.*user_id|\.labels\(.*user_id|session_id.*label|label.*session_id|\.labels\(.*session_id/gi;
  if (safeTest(mon003Pattern, allContent) && safeTest(mon003Labels, allContent)) {
    findings.push({
      ruleId: "DK-MON-003",
      title: "Metric cardinality explosion risk from high-cardinality labels",
      severity: "medium",
      confidence: "medium",
      missingControls: ["Label value sanitization", "Cardinality limits", "Use bounded label sets"],
      consequence: "Using high-cardinality values like user_id, request_id, or session_id as metric labels causes unbounded growth in time series, leading to memory exhaustion and storage overflow in the monitoring backend.",
      acceptanceCriteria: [
        "Remove or bound high-cardinality labels (user_id, request_id, session_id) from metric definitions",
        "Use aggregated labels (e.g., user_tier, request_type) instead of raw identifiers",
        "Configure cardinality limits in the metrics library or scraping configuration"
      ],
      evidence: [{
        id: "mon-003-high-cardinality-labels",
        detector: "pattern-match",
        location: { path: files[0] },
        controls: [],
        signals: ["metrics defined with high-cardinality labels such as user_id or session_id"]
      }]
    });
  }

  // DK-MON-004: Missing metric retention policy — require metric library context, not just the word "metrics"
  const mon004Pattern = /prometheus|prom-client|statsd|datadog|new\s+Histogram|new\s+Gauge|register\./gi;
  const mon004Retention = /retention|expire|ttl|window|maxAge|max_age/gi;
  if (safeTest(mon004Pattern, allContent) && !safeTest(mon004Retention, allContent)) {
    findings.push({
      ruleId: "DK-MON-004",
      title: "No metric retention policy configured",
      severity: "medium",
      confidence: "medium",
      missingControls: ["Metric retention configuration", "TTL on collected data", "Storage window limits"],
      consequence: "Without a retention policy, metrics accumulate indefinitely, consuming increasing amounts of storage and slowing down queries over time.",
      acceptanceCriteria: [
        "Configure a retention period for collected metrics (e.g., 30 days for raw, 1 year for aggregated)",
        "Set TTL or expiration on metric storage backend",
        "Document retention policy and storage projections"
      ],
      evidence: [{
        id: "mon-004-no-retention",
        detector: "pattern-match",
        location: { path: files[0] },
        controls: [],
        signals: ["metric collection found without any retention/expiration configuration"]
      }]
    });
  }

  return findings;
}
