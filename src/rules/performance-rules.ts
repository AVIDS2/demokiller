import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

export async function performanceFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".py", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php"]);
  if (files.length === 0) return [];

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    fileContents.set(file, await readFileContent(root, file));
  }

  // Helpers
  const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|fixtures-risky|test-fixtures|__fixtures__|testdata|test_data|test-data|sample-data|samples|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party)(?:[\\/]|$)/i;
  const isTestFile = (f: string) => FIXTURE_RE.test(f) || /(?:test|spec|__test__|fixtures|mocks)[\\/]/i.test(f) || /(?:\.test|\.spec)\.[a-z]+$/i.test(f);

  function evidence(hits: Map<string, string[]>, ruleId: string) {
    return [...hits.entries()].map(([file, signals]) => ({
      id: `${ruleId}-${file}`,
      detector: "pattern-match",
      location: { path: file },
      controls: [],
      signals
    }));
  }

  // --- DK-PERF-009: Missing batch processing — await inside loop ---
  const jsTsExts = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
  const jsTsFiles = new Map<string, string>();
  const pyFiles = new Map<string, string>();
  const INFRA_RE = /src[/\\](?:rules|call-graph|python-call-graph|source-inspector|cli|inventory)[/\\.]|(?:src[/\\]cli\.ts$)/;
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    if (INFRA_RE.test(file)) continue;
    const lower = file.toLowerCase();
    if (jsTsExts.some(ext => lower.endsWith(ext))) jsTsFiles.set(file, content);
    else if (lower.endsWith(".py")) pyFiles.set(file, content);
  }

  // Check if a loop has a small bound (≤3 iterations) — not a batch problem
  const SMALL_LOOP_RE = /(?:for\s*\([^;]*;\s*\w+\s*(?:<|<=)\s*(?:[123]|MAX_RETRIES|RETRY_COUNT)\b|for\s+\w+\s+in\s+range\s*\(\s*(?:[123]|MAX_RETRIES|RETRY_COUNT)\b)/;
  // Check if the await line is inside a conditional (if/elif/else) — not sequential batch
  const IF_GUARD_RE = /^\s*(?:if|else\s+if|elif|else)\b|^\s*\}\s*else/;

  const awaitInLoopFiles = new Map<string, string[]>();
  for (const [file, content] of jsTsFiles) {
    const lines = content.split(/\r?\n/);
    const loopKeywords = /\b(?:for|while|forEach)\b/;
    const awaitKeyword = /\bawait\b/;
    const hits: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!awaitKeyword.test(lines[i])) continue;
      // Check preceding 5 lines for loop keyword
      const start = Math.max(0, i - 5);
      const preceding = lines.slice(start, i).join("\n");
      if (!loopKeywords.test(preceding)) continue;
      // Skip if the loop has a small iteration bound
      if (SMALL_LOOP_RE.test(preceding)) continue;
      // Skip if the await is inside an if/conditional block (early return, error check, etc.)
      if (IF_GUARD_RE.test(lines[i])) continue;
      hits.push(`line ${i + 1}: await inside loop — ${lines[i].trim().slice(0, 80)}`);
    }
    if (hits.length >= 2) awaitInLoopFiles.set(file, hits.slice(0, 10));
  }
  // Python: await inside for loop
  for (const [file, content] of pyFiles) {
    const lines = content.split(/\r?\n/);
    const hits: string[] = [];
    for (let i = 0; i < lines.length; i++) {
      if (!/\bawait\b/.test(lines[i])) continue;
      const start = Math.max(0, i - 5);
      const preceding = lines.slice(start, i).join("\n");
      if (!/\bfor\b/.test(preceding)) continue;
      if (SMALL_LOOP_RE.test(preceding)) continue;
      if (IF_GUARD_RE.test(lines[i])) continue;
      hits.push(`line ${i + 1}: await inside for loop — ${lines[i].trim().slice(0, 80)}`);
    }
    if (hits.length >= 2) awaitInLoopFiles.set(file, hits.slice(0, 10));
  }
  if (awaitInLoopFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-009",
      title: "Missing batch processing: await inside loop",
      severity: "high",
      confidence: "medium",
      missingControls: ["batchProcessing"],
      consequence: "Sending 5 emails one-by-one is fine. Sending 50,000 serially = 8 hours. Production batches inserts/emails/API calls. Each await in a loop adds a full round-trip latency.",
      acceptanceCriteria: [
        "Use Promise.all() to parallelize independent async operations.",
        "Use batch API endpoints instead of per-item calls.",
        "Collect items and process in bulk to reduce round-trip overhead.",
      ],
      evidence: evidence(awaitInLoopFiles, "perf-009"),
    });
  }

  // --- DK-PERF-010: No rate limiting on public endpoints ---
  const routeDefPattern = /(?:app|router|server)\s*\.\s*(?:get|post|put|delete|patch|all)\s*\(/g;
  const decoratorRoutePattern = /@(?:Get|Post|Put|Delete|Patch|RequestMapping)\s*\(/g;
  const rateLimitPattern = /rate[-_]?limit|throttle|rateLimit|RateLimit|limiter|express-rate-limit|rate_limiter|slowapi|django-ratelimit/gi;

  const noRateLimitFiles = new Map<string, string[]>();
  const ANALYSIS_INDICATORS_RE = /walkSourceFiles|walkPythonFiles|FUNC_PATTERNS|ROUTE_PATTERNS|extractFunctions|CallGraph|buildCallGraph|detectMcp|detectUnsafe|walkSourceFiles|codegraph/i;
  const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe|agent-mcp|security-hardening|error-handling|performance-rules|observability|deployment-rules|python-rules|environment-rules)/;
  const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file)) continue;
    if (ANALYSIS_INDICATORS_RE.test(content)) continue;
    if (/admin/i.test(file.split(/[/\\]/).pop() ?? "")) continue;
    const hasRoutes = routeDefPattern.test(content) || decoratorRoutePattern.test(content);
    if (!hasRoutes) continue;
    // Reset regex lastIndex
    routeDefPattern.lastIndex = 0;
    decoratorRoutePattern.lastIndex = 0;
    if (rateLimitPattern.test(content)) continue;
    // Count route definitions found
    const routeMatches = content.match(routeDefPattern) ?? [];
    const decoratorMatches = content.match(decoratorRoutePattern) ?? [];
    const count = routeMatches.length + decoratorMatches.length;
    noRateLimitFiles.set(file, [`${count} route definition(s) with no rate limiting in file`]);
  }
  if (noRateLimitFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-010",
      title: "No rate limiting on public endpoints",
      severity: "high",
      confidence: "high",
      missingControls: ["rateLimiting"],
      consequence: "Demo has 1 user. Production gets scraped, brute-forced, or DDoSed. Unprotected endpoints burn compute, DB, and money.",
      acceptanceCriteria: [
        "Add rate limiting middleware to all public API routes.",
        "Use sliding window or token bucket algorithms.",
        "Configure per-endpoint limits based on sensitivity.",
      ],
      evidence: evidence(noRateLimitFiles, "perf-010"),
    });
  }

  // --- DK-PERF-015: Regex built from user input (ReDoS risk) ---
  const newRegExpVar = /new\s+RegExp\s*\(\s*([a-zA-Z_$][\w$.]*)/g;
  const regExpCallVar = /\bRegExp\s*\(\s*([a-zA-Z_$][\w$.]*)/g;
  const pyReDynamic = /\bre\s*\.\s*(?:compile|match|search|findall|sub)\s*\(\s*([a-zA-Z_][\w.]*)/g;
  const userInputPattern = /(?:req\.body|req\.params|req\.query|request\.args|request\.form|request\.GET|request\.POST|params\[)/;

  const redosFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    if (/src[/\\](?:rules|call-graph|python-call-graph|source-inspector)[/\\.]/.test(file)) continue;
    const lower = file.toLowerCase();
    const hits: string[] = [];

    // JS/TS files: new RegExp(variable)
    if (jsTsExts.some(ext => lower.endsWith(ext))) {
      for (const m of content.matchAll(newRegExpVar)) {
        hits.push(`new RegExp(${m[1]}) — regex built from variable`);
      }
      // Avoid duplicate from RegExp() alias if new RegExp already matched
      if (hits.length === 0) {
        for (const m of content.matchAll(regExpCallVar)) {
          hits.push(`RegExp(${m[1]}) — regex built from variable`);
        }
      }
      // Extra flag if file also references user input
      if (hits.length > 0 && userInputPattern.test(content)) {
        hits.push("FILE CONTAINS USER INPUT REFERENCES — high ReDoS risk");
      }
    }

    // Python files: re.compile/match/etc with variable
    if (lower.endsWith(".py")) {
      for (const m of content.matchAll(pyReDynamic)) {
        hits.push(`re.${m[0].match(/(?:compile|match|search|findall|sub)/)?.[0]}(${m[1]}) — regex built from variable`);
      }
      if (hits.length > 0 && userInputPattern.test(content)) {
        hits.push("FILE CONTAINS USER INPUT REFERENCES — high ReDoS risk");
      }
    }

    if (hits.length > 0) redosFiles.set(file, hits.slice(0, 10));
  }
  if (redosFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-015",
      title: "Regex built from user input (ReDoS risk)",
      severity: "high",
      confidence: "medium",
      missingControls: ["regexInputValidation"],
      consequence: "Simple patterns compile fast. Evil patterns like '(a+)+$' take exponential time. Attackers can craft regex patterns that cause catastrophic backtracking, freezing the server.",
      acceptanceCriteria: [
        "Never construct regex from user input without validation.",
        "Use RE2 or similar linear-time regex engine.",
        "Validate and escape user input before using in regex.",
      ],
      evidence: evidence(redosFiles, "perf-015"),
    });
  }

  // --- DK-PERF-032: Blocking database transaction held across network call ---
  const transactionPattern = /(?:BEGIN\s+TRANSACTION|BEGIN|\.transaction|with\s+transaction|sequelize\.transaction|db\.transaction|startTransaction)\b/gi;
  const httpCallPattern = /(?:fetch\s*\(|axios\.|http\.|https\.|request\s*\(|\.get\s*\(\s*['"]http|\.post\s*\(\s*['"]http)/g;

  const txNetworkFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    const hasTx = transactionPattern.test(content);
    transactionPattern.lastIndex = 0;
    if (!hasTx) continue;
    const hasHttp = httpCallPattern.test(content);
    httpCallPattern.lastIndex = 0;
    if (!hasHttp) continue;
    const txMatches = content.match(transactionPattern) ?? [];
    transactionPattern.lastIndex = 0;
    const httpMatches = content.match(httpCallPattern) ?? [];
    txNetworkFiles.set(file, [
      `${txMatches.length} transaction scope(s) co-located with ${httpMatches.length} HTTP/network call(s)`
    ]);
  }
  if (txNetworkFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-032",
      title: "Blocking database transaction held across network call",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["transactionScopeIsolation"],
      consequence: "Holding a DB transaction while waiting for an external API (500ms) = holding a DB lock for 500ms. At 100 concurrent requests = deadlock city.",
      acceptanceCriteria: [
        "Never make network calls inside a database transaction.",
        "Commit the transaction first, then make the external call.",
        "Handle failure with a compensation pattern (e.g., saga).",
      ],
      evidence: evidence(txNetworkFiles, "perf-032"),
    });
  }

  // --- DK-PERF-048: Large payload deserialized without size limit ---
  const noLimitJson = /\bexpress\.json\(\s*\)/g;
  const noLimitUrlencoded = /\bexpress\.urlencoded\(\s*\)/g;
  const noLimitBodyParserJson = /\bbodyParser\.json\(\s*\)/g;
  const noLimitBodyParserUrlencoded = /\bbodyParser\.urlencoded\(\s*\)/g;
  const hasLimitOption = /\b(?:express\.json|express\.urlencoded|bodyParser\.json|bodyParser\.urlencoded)\s*\(\s*\{[^}]*limit\b/;
  const pyRawJson = /(?:await\s+)?request\.json\s*\(\)/g;

  const noSizeLimitFiles = new Map<string, string[]>();
  for (const [file, content] of fileContents) {
    if (isTestFile(file)) continue;
    const lower = file.toLowerCase();
    const hits: string[] = [];

    // JS/TS files
    if (jsTsExts.some(ext => lower.endsWith(ext))) {
      // Only flag if there are bare (no options) calls AND no calls with limit
      const bareJson = (content.match(noLimitJson) ?? []).length;
      const bareUrlencoded = (content.match(noLimitUrlencoded) ?? []).length;
      const bareBpJson = (content.match(noLimitBodyParserJson) ?? []).length;
      const bareBpUrlencoded = (content.match(noLimitBodyParserUrlencoded) ?? []).length;
      const totalBare = bareJson + bareUrlencoded + bareBpJson + bareBpUrlencoded;
      if (totalBare > 0 && !hasLimitOption.test(content)) {
        if (bareJson > 0) hits.push("express.json() without size limit");
        if (bareUrlencoded > 0) hits.push("express.urlencoded() without size limit");
        if (bareBpJson > 0) hits.push("bodyParser.json() without size limit");
        if (bareBpUrlencoded > 0) hits.push("bodyParser.urlencoded() without size limit");
      }
    }

    // Python files
    if (lower.endsWith(".py")) {
      for (const m of content.matchAll(pyRawJson)) {
        hits.push(`${m[0].trim()} — raw JSON parsing without size guard`);
      }
    }

    if (hits.length > 0) noSizeLimitFiles.set(file, hits);
  }
  if (noSizeLimitFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-048",
      title: "Large payload deserialized without size limit",
      severity: "high",
      confidence: "high",
      missingControls: ["payloadSizeLimit"],
      consequence: "Demo sends 1KB JSON. Attacker sends 100MB JSON body = server OOM. Production limits request body size.",
      acceptanceCriteria: [
        "Configure body size limits: express.json({limit: '1mb'}).",
        "Set nginx/cloudflare max body size.",
        "Validate payload size before processing.",
      ],
      evidence: evidence(noSizeLimitFiles, "perf-048"),
    });
  }

  return findings;
}
