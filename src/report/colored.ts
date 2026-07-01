import type { AnalysisReport, Finding } from "../types.js";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  bgRed: "\x1b[41m",
  bgGreen: "\x1b[42m",
  bgYellow: "\x1b[43m",
};

function colorize(text: string, ...codes: string[]): string {
  return codes.join("") + text + C.reset;
}

function severityColor(severity: string): string {
  switch (severity) {
    case "blocker": return C.red + C.bold;
    case "high": return C.red;
    case "medium": return C.yellow;
    case "advisory": return C.dim;
    default: return "";
  }
}

function verdictColor(verdict: string): string {
  switch (verdict) {
    case "Launch Blocked": return C.bgRed + C.bold;
    case "Demo": return C.bgYellow + C.bold;
    case "Production Candidate": return C.bgGreen + C.bold;
    default: return C.dim;
  }
}

function categorize(ruleId: string): string {
  const id = ruleId.toUpperCase();
  if (id.includes("SEC") || id.includes("CORS") || id.includes("CSP") || id.includes("INJ") || id.includes("SSRF") || id.includes("SECRET") || id.includes("XSS") || id.includes("TRAV")) return "Security";
  if (id.includes("AUTH") || id.includes("WEBHOOK")) return "Auth";
  if (id.includes("PERF") || id.includes("N+1") || id.includes("POOL") || id.includes("TIMEOUT")) return "Performance";
  if (id.includes("ERR") || id.includes("CATCH")) return "Error Handling";
  if (id.includes("OBS") || id.includes("LOG") || id.includes("HEALTH") || id.includes("SHUTDOWN")) return "Observability";
  if (id.includes("ENV") || id.includes("STATE")) return "Config";
  if (id.includes("AGENT") || id.includes("MCP") || id.includes("PROMPT")) return "Agent Safety";
  if (id.includes("TEST") || id.includes("CI") || id.includes("DEPLOY")) return "Testing & Deploy";
  if (id.includes("LIB") || id.includes("SDK") || id.includes("NPM")) return "Library";
  if (id.includes("PY-")) return "Python";
  if (id.includes("C-0")) return "C/C++";
  if (id.includes("TAINT")) return "Taint Analysis";
  if (id.includes("CLI")) return "CLI";
  return "Other";
}

export function renderColoredReport(report: AnalysisReport): string {
  const lines: string[] = [];
  const findings = report.findings;
  const blockers = findings.filter(f => f.severity === "blocker");
  const highs = findings.filter(f => f.severity === "high");
  const mediums = findings.filter(f => f.severity === "medium");
  const advisories = findings.filter(f => f.severity === "advisory");

  // Categorize findings by dimension
  const categories: Record<string, number> = {};
  for (const f of findings) {
    const cat = categorize(f.ruleId);
    categories[cat] = (categories[cat] || 0) + 1;
  }

  // Verdict banner
  lines.push("");
  lines.push(colorize(`  ${report.verdict}  `, verdictColor(report.verdict)));
  lines.push("");

  // Summary stats
  lines.push(colorize(`  Findings: ${findings.length} total`, C.bold));
  if (blockers.length > 0) lines.push(colorize(`    ${blockers.length} blocker(s)`, severityColor("blocker")));
  if (highs.length > 0) lines.push(colorize(`    ${highs.length} high`, severityColor("high")));
  if (mediums.length > 0) lines.push(colorize(`    ${mediums.length} medium`, severityColor("medium")));
  if (advisories.length > 0) lines.push(colorize(`    ${advisories.length} advisory`, severityColor("advisory")));

  // Category breakdown
  const catEntries = Object.entries(categories).sort((a, b) => b[1] - a[1]);
  if (catEntries.length > 1) {
    lines.push("");
    lines.push(colorize("  By category:", C.dim));
    for (const [cat, count] of catEntries) {
      lines.push(colorize(`    ${cat}: ${count}`, C.dim));
    }
  }
  lines.push("");

  // Phase 0 blockers
  if (blockers.length > 0) {
    lines.push(colorize("  Phase 0 — Launch Blockers", C.red + C.bold));
    lines.push(colorize("  Fix these before any production traffic.", C.red));
    lines.push("");
    for (const f of blockers) {
      const loc = f.evidence?.[0]?.location;
      const fileStr = loc ? `  → ${loc.path}${loc.line ? `:${loc.line}` : ""}` : "";
      lines.push(colorize(`  ${f.ruleId}`, C.red + C.bold) + ` ${f.title}`);
      if (fileStr) lines.push(colorize(fileStr, C.dim));
      lines.push(colorize(`    ${f.consequence}`, C.dim));
      lines.push("");
    }
  }

  // Phase 1 high
  if (highs.length > 0) {
    lines.push(colorize("  Phase 1 — Production Baseline", C.yellow + C.bold));
    lines.push("");
    for (const f of highs) {
      const loc = f.evidence?.[0]?.location;
      const fileStr = loc ? `  → ${loc.path}${loc.line ? `:${loc.line}` : ""}` : "";
      lines.push(colorize(`  ${f.ruleId}`, C.yellow) + ` ${f.title}`);
      if (fileStr) lines.push(colorize(fileStr, C.dim));
      lines.push("");
    }
  }

  // Phase 2 medium + advisory
  if (mediums.length + advisories.length > 0) {
    lines.push(colorize("  Phase 2 — Operational Confidence", C.cyan + C.bold));
    lines.push("");
    for (const f of [...mediums, ...advisories]) {
      const loc = f.evidence?.[0]?.location;
      const fileStr = loc ? `  → ${loc.path}${loc.line ? `:${loc.line}` : ""}` : "";
      lines.push(colorize(`  ${f.ruleId}`, f.severity === "medium" ? C.yellow : C.dim) + ` ${f.title}`);
      if (fileStr) lines.push(colorize(fileStr, C.dim));
      lines.push("");
    }
  }

  // No findings
  if (findings.length === 0) {
    lines.push(colorize("  No findings in supported scope.", C.green));
    lines.push("");
  }

  // Supported scope
  lines.push(colorize("  Supported scope:", C.dim));
  lines.push(colorize(`    ${report.supportedScope.slice(0, 10).join(", ")}${report.supportedScope.length > 10 ? "..." : ""}`, C.dim));
  lines.push("");

  return lines.join("\n");
}
