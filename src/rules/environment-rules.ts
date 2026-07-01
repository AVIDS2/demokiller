import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXTENSIONS = [
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php", ".swift", ".dart",
];

/** Test / fixture exclusion patterns applied to file paths. */
const TEST_PATH = /(?:test|spec|__test__|__mock__|\.test\.|\.spec\.|\/fixtures\/|\/mocks\/)/i;
const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|fixtures-risky|test-fixtures|__fixtures__|testdata|test_data|test-data|sample-data|samples|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party)(?:[\\/]|$)/i;
const DOC_PATH = /(?:\.example|\.sample|README|CHANGELOG|docker-compose\.example)/i;

function isTestFile(path: string): boolean {
  return TEST_PATH.test(path);
}

function isTestOrDocFile(path: string): boolean {
  return TEST_PATH.test(path) || DOC_PATH.test(path);
}

/** Compute Shannon entropy of a string. */
function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const freq = new Map<string, number>();
  for (const ch of s) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / s.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

/** Patterns that indicate env-var references or placeholder values — not real credentials. */
const PLACEHOLDER_PATTERN = /\$\{|process\.env|your[_-]?key|CHANGE_ME|placeholder|example|test[-_]?key|dummy|fake|mock|xxx|yyy|REPLACE/i;

export async function environmentFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, EXTENSIONS);
  if (files.length === 0) return [];

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (FIXTURE_RE.test(file)) continue;
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

  // ---------------------------------------------------------------
  // DK-ENV-002: Hardcoded localhost in non-test code
  // ---------------------------------------------------------------
  const localhostPattern = /localhost[:/]\d{1,5}\b|127\.0\.0\.1[:/]\d{1,5}\b/g;
  const serverBindPattern = /(?:listen\s*\([^)]*['"]localhost['"]|app\.listen\s*\()/;
  const clientUsagePattern = /\b(?:fetch|axios|http\.get|http\.request|request\s*\(|connect\s*\(|\.get\s*\(|\.post\s*\()/;
  const localhostFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    // Skip if the file only binds a server on localhost (that's expected)
    if (serverBindPattern.test(content) && !clientUsagePattern.test(content)) continue;
    const matches = content.match(localhostPattern) ?? [];
    if (matches.length > 0) localhostFiles.set(file, [...new Set(matches)]);
  }
  if (localhostFiles.size > 0) {
    findings.push({
      ruleId: "DK-ENV-002",
      title: "Hardcoded localhost in non-test code",
      severity: "high",
      confidence: "medium",
      missingControls: ["externalizedServiceHosts"],
      consequence: "Hardcoded localhost only works on the developer's machine. In production the database/cache/API is on a different host. This is the single most common 'works on my machine' failure.",
      acceptanceCriteria: [
        "Move host to environment variable. Use service discovery or config for all host references.",
      ],
      evidence: evidence(localhostFiles, "env-002"),
    });
  }

  // ---------------------------------------------------------------
  // DK-ENV-004: Hardcoded absolute OS-specific file paths
  // ---------------------------------------------------------------
  const absPathPattern = /"[A-Z]:\\[^"]*"|'\/home\/[^']*'|'\/Users\/[^']*'|"[A-Z]:\\Users\\[^"]*"/g;
  const absPathFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestOrDocFile(file)) continue;
    const matches = content.match(absPathPattern) ?? [];
    if (matches.length > 0) absPathFiles.set(file, [...new Set(matches)]);
  }
  if (absPathFiles.size > 0) {
    findings.push({
      ruleId: "DK-ENV-004",
      title: "Hardcoded absolute OS-specific file paths",
      severity: "blocker",
      confidence: "high",
      missingControls: ["portablePathHandling"],
      consequence: "Absolute paths encode a specific machine's filesystem layout. Breaks on every other developer's machine, CI runner, container, and production server.",
      acceptanceCriteria: [
        "Use path.join/path.resolve with relative paths or environment variables. Never hardcode user-specific or OS-specific paths.",
      ],
      evidence: evidence(absPathFiles, "env-004"),
    });
  }

  // ---------------------------------------------------------------
  // DK-ENV-010: Hardcoded timezone assumptions
  // ---------------------------------------------------------------
  const tzLocalDateMethods = /new Date\(\)\.getHours\(\)|new Date\(\)\.getMinutes\(\)|new Date\(\)\.getDay\(\)/g;
  const tzPythonDatetime = /datetime\.now\(\)|datetime\.utcnow\(\)/g;
  const tzMomentNoUtc = /moment\(\)(?!\.utc)/g;
  const tzFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    const hits: string[] = [];

    const localDateMatches = content.match(tzLocalDateMethods) ?? [];
    for (const m of localDateMatches) hits.push(m);

    const pyDatetimeMatches = content.match(tzPythonDatetime) ?? [];
    for (const m of pyDatetimeMatches) hits.push(m);

    const momentMatches = content.match(tzMomentNoUtc) ?? [];
    for (const m of momentMatches) hits.push(m);

    if (hits.length > 0) tzFiles.set(file, [...new Set(hits)]);
  }
  if (tzFiles.size > 0) {
    findings.push({
      ruleId: "DK-ENV-010",
      title: "Hardcoded timezone assumptions",
      severity: "high",
      confidence: "low",
      missingControls: ["timezoneAwareOperations"],
      consequence: "Production servers are UTC (or should be), users are global. Time bugs are the most subtle and destructive demo-grade failures.",
      acceptanceCriteria: [
        "Always use timezone-aware date operations. Store timestamps in UTC. Convert to local timezone only at display layer.",
      ],
      evidence: evidence(tzFiles, "env-010"),
    });
  }

  // ---------------------------------------------------------------
  // DK-ENV-016: High-entropy hardcoded credentials (generic)
  // Narrowed: removed overly broad identifiers (key, auth, token, private) that caused massive FPs
  // ---------------------------------------------------------------
  const credPattern = /(?:secret|password|credential|api_key|apikey|private_key)\s*[:=]\s*['"]([^'"]{20,})['"]/gi;
  const credExclude = /(?:endpoint|url|header|path|name|id|file|route|host|port|type|_name|_path|_url|_endpoint)/i;
  const credFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    const hits: string[] = [];
    for (const m of content.matchAll(credPattern)) {
      const identifier = m[0].slice(0, m[0].indexOf("=") > -1 ? m[0].indexOf("=") : m[0].indexOf(":")).trim();
      if (credExclude.test(identifier)) continue;
      const value = m[1];
      if (PLACEHOLDER_PATTERN.test(value)) continue;
      // Raised from 4.5 to 4.8 — reduces false positives on UUIDs, hex hashes, default configs
      if (shannonEntropy(value) > 4.8) {
        if (/^[0-9a-f]{32,}$/i.test(value)) continue;  // bare hex hash
        if (/^[0-9a-f]{8}-[0-9a-f]{4}-/.test(value)) continue;  // UUID
        if (/^v?\d+\.\d+/.test(value)) continue;  // version string
        hits.push(`high-entropy value near identifier '${identifier}'`);
      }
    }
    if (hits.length > 0) credFiles.set(file, hits);
  }
  if (credFiles.size > 0) {
    findings.push({
      ruleId: "DK-ENV-016",
      title: "High-entropy hardcoded credentials",
      severity: "high",
      confidence: "medium",
      missingControls: ["secretsManagement"],
      consequence: "Hardcoded credentials work on the developer's machine with their personal API key. In production: key gets rotated and app breaks, key leaks through git history, key has dev-level permissions.",
      acceptanceCriteria: [
        "Move all credentials to environment variables or a secrets manager. Never commit credentials to source control.",
      ],
      evidence: evidence(credFiles, "env-016"),
    });
  }

  // ---------------------------------------------------------------
  // DK-ENV-018: Hardcoded database connection strings
  // ---------------------------------------------------------------
  const dbConnPattern = /postgres(?:ql)?:\/\/[^\s'"`,]+|mysql:[^\s'"`,]+@[^\s'"`,]+|mongodb(?:\+srv)?:\/\/[^\s'"`,]+|redis:\/\/[^\s'"`,]+|amqp:\/\/[^\s'"`,]+|sqlite:\/\/[^\s'"`,]+/gi;
  const dbConnFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestOrDocFile(file)) continue;
    const matches = content.match(dbConnPattern) ?? [];
    if (matches.length > 0) dbConnFiles.set(file, [...new Set(matches)]);
  }
  if (dbConnFiles.size > 0) {
    findings.push({
      ruleId: "DK-ENV-018",
      title: "Hardcoded database connection strings",
      severity: "blocker",
      confidence: "high",
      missingControls: ["externalizedConnectionStrings"],
      consequence: "Connection strings encode host, port, credentials, and database name — all environment-specific. Hardcoding means the app can only connect to one specific database instance.",
      acceptanceCriteria: [
        "Load connection strings from environment variables. Use config files that are not committed to version control.",
      ],
      evidence: evidence(dbConnFiles, "env-018"),
    });
  }

  // ---------------------------------------------------------------
  // DK-STATE-021: Financial/counter field using float (precision loss)
  // ---------------------------------------------------------------
  const moneyFloatPattern = /(?:price|amount|total|cost|fee|balance|payment|salary|revenue|income|expense|money|credit|debit|charge|refund|discount|tax|tip|commission)\s*.*(?:float|Float|Float64|DOUBLE|REAL|NUMBER\b)/gi;
  const jsFloatColumn = /@Column\s*\(\s*["']float["']\s*\)|type:\s*["']float["']/g;
  const floatPrecisionFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    // Only look at schema/model/migration files
    if (!/(?:schema|model|migration|entity|entities)/i.test(file)) continue;
    const hits: string[] = [];

    for (const m of content.matchAll(moneyFloatPattern)) {
      hits.push(m[0].slice(0, 80));
    }

    // Check for @Column("float") or type: "float" near money-related names
    const lines = content.split(/\r?\n/);
    const moneyIdentifiers = /price|amount|total|cost|fee|balance|payment|salary|revenue|income|expense|money|credit|debit|charge|refund|discount|tax|tip|commission/i;
    for (let i = 0; i < lines.length; i++) {
      if (!jsFloatColumn.test(lines[i])) continue;
      // Look at surrounding lines (within 3 lines) for money-related field name
      const context = lines.slice(Math.max(0, i - 3), i + 4).join("\n");
      if (moneyIdentifiers.test(context)) {
        hits.push(lines[i].trim().slice(0, 80));
      }
    }

    if (hits.length > 0) floatPrecisionFiles.set(file, [...new Set(hits)]);
  }
  if (floatPrecisionFiles.size > 0) {
    findings.push({
      ruleId: "DK-STATE-021",
      title: "Financial/counter field using float (precision loss)",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["preciseFinancialTypes"],
      consequence: "Floating-point arithmetic loses precision: 0.1 + 0.2 = 0.30000000000000004. In financial systems this means real money is lost or created from nothing. 32-bit counters overflow at 2.1 billion.",
      acceptanceCriteria: [
        "Use DECIMAL/NUMERIC type for financial amounts. Use 64-bit integers (BigInt) for counters and IDs that may exceed 2^31.",
      ],
      evidence: evidence(floatPrecisionFiles, "state-021"),
    });
  }

  return findings;
}
