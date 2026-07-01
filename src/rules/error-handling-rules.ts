import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const JS_TS_EXTS = [".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"];
const ALL_EXTS = [
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs",
  ".py", ".go", ".rs", ".java", ".kt", ".cs", ".rb", ".php",
];

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;

export async function errorHandlingFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, ALL_EXTS);
  if (files.length === 0) return [];

  // Cache file contents once to avoid redundant I/O
  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
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

  // ---------------------------------------------------------------------------
  // DK-ERR-002: Empty/silent catch blocks (swallowed exceptions)
  // ---------------------------------------------------------------------------
  const emptyCatchFiles = new Map<string, string[]>();

  // JS/TS/Java/C#/Rust/Kotlin/Go: empty catch, comment-only catch, catch-return
  const emptyCatchJS = /catch\s*\([^)]*\)\s*\{\s*(?:\/\/[^\n]*\s*)?\}/g;
  const returnOnlyCatch = /catch\s*\([^)]*\)\s*\{\s*return\s*;\s*\}/g;
  // Logging-only catch (no throw/re-throw/return error/res.status)
  const loggingCatch = /catch\s*\([^)]*\)\s*\{([^}]*)\}/g;
  const loggingCall = /(?:console\.\w+|logger\.\w+|log\.\w+|print|logging\.\w+)/;
  const rethrowPattern = /\b(?:throw|rethrow|res\.\w|response\.\w|return\s+(?:new\s+)?(?:Error|err))|return\b/i;
  const retryPattern = /\b(?:retry|retries|attempt|backoff|exponential|setTimeout.*Math\.pow|MAX_RETRIES|RETRY_COUNT)\b/i;

  // Python: except: pass or except with only comment
  const exceptPass = /except[^:]*:\s*\n\s*(?:pass|\.\.\.)\s*$/gm;
  const exceptCommentOnly = /except[^:]*:\s*\n\s*(?:#[^\n]*)?\s*$/gm;

  const jsTsExts = new Set(JS_TS_EXTS);
  const cStyleExts = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".java", ".kt", ".cs", ".go", ".rs", ".rb", ".php"]);

  for (const [file, content] of fileContents) {
    if (/src[/\\]rules[/\\]/.test(file)) continue;
    const hits: string[] = [];
    const ext = file.slice(file.lastIndexOf(".")).toLowerCase();

    if (cStyleExts.has(ext)) {
      // Empty or comment-only catch
      for (const m of content.matchAll(emptyCatchJS)) {
        hits.push(`empty/comment-only catch block: ${m[0].slice(0, 80)}`);
      }
      // Return-only catch
      for (const m of content.matchAll(returnOnlyCatch)) {
        hits.push(`catch block only returns: ${m[0].slice(0, 80)}`);
      }
      // Logging-only catch: find all catch blocks, check if they only log
      const catchBlockRe = /catch\s*(?:\([^)]*\))?\s*\{/g;
      let catchMatch: RegExpExecArray | null;
      while ((catchMatch = catchBlockRe.exec(content)) !== null) {
        // Find matching closing brace by counting nested braces
        let depth = 1;
        let pos = catchMatch.index + catchMatch[0].length;
        while (pos < content.length && depth > 0) {
          const ch = content[pos];
          if (ch === "{") depth++;
          else if (ch === "}") { depth--; if (depth === 0) break; }
          else if (ch === "'" || ch === '"' || ch === "`") {
            const quote = ch;
            pos++;
            while (pos < content.length && content[pos] !== quote) {
              if (content[pos] === "\\") pos++;
              pos++;
            }
          }
          pos++;
        }
        const body = content.slice(catchMatch.index + catchMatch[0].length, pos);
        if (loggingCall.test(body) && !rethrowPattern.test(body) && !retryPattern.test(body)) {
          hits.push(`catch block only logs without handling: ${body.trim().slice(0, 80)}`);
        }
      }
    }

    if (ext === ".py") {
      for (const m of content.matchAll(exceptPass)) {
        hits.push(`except: pass block: ${m[0].slice(0, 80)}`);
      }
      for (const m of content.matchAll(exceptCommentOnly)) {
        hits.push(`except with only comment: ${m[0].slice(0, 80)}`);
      }
    }

    if (hits.length > 0) emptyCatchFiles.set(file, hits.slice(0, 10));
  }

  if (emptyCatchFiles.size > 0) {
    findings.push({
      ruleId: "DK-ERR-002",
      title: "Empty or silent catch blocks swallow exceptions",
      severity: "high",
      confidence: "medium",
      missingControls: ["exceptionHandlingVisibility"],
      consequence: "Swallowing exceptions silently turns every failure into silent data corruption. The code appears to work while silently producing wrong results. Bugs become invisible and untraceable.",
      acceptanceCriteria: [
        "Every catch block must either: (1) re-throw, (2) return an error response, (3) apply a fallback, or (4) explicitly document why the error is intentionally ignored.",
      ],
      evidence: evidence(emptyCatchFiles, "err-002"),
    });
  }

  // ---------------------------------------------------------------------------
  // DK-ERR-006: Unhandled Promise rejection
  // ---------------------------------------------------------------------------
  const unhandledPromiseFiles = new Map<string, string[]>();

  // .then() at end of statement without .catch()
  const thenNoCatch = /\.then\s*\([^)]*\)\s*;?\s*$/gm;
  // function().then() without await
  const noAwaitThen = /(?<!await\s)(?<!return\s)\b\w+\([^)]*\)\s*\.then\s*\(/g;

  for (const [file, content] of fileContents) {
    const ext = file.slice(file.lastIndexOf(".")).toLowerCase();
    if (!jsTsExts.has(ext)) continue;
    // Skip rule files — they contain detection patterns in comments/regexes that look like real code
    if (/src[/\\]rules[/\\]/.test(file)) continue;

    const hits: string[] = [];
    for (const m of content.matchAll(thenNoCatch)) {
      // Look ahead in the remaining content for .catch or .finally in the same chain
      const after = content.slice(m.index! + m[0].length, m.index! + m[0].length + 200);
      if (/^\s*\.(?:catch|finally)\s*\(/.test(after)) continue;
      hits.push(`.then() without .catch(): ${m[0].slice(0, 80)}`);
    }
    for (const m of content.matchAll(noAwaitThen)) {
      // Check if the .then() chain continues with .catch() or .finally()
      // Find matching closing paren for .then( by counting nested parens
      const thenOpenIdx = m.index! + m[0].length - 1; // position of '(' in .then(
      let depth = 1;
      let pos = thenOpenIdx + 1;
      while (pos < content.length && depth > 0) {
        const ch = content[pos];
        if (ch === "(") depth++;
        else if (ch === ")") {
          depth--;
          if (depth === 0) break;
        }
        else if (ch === "'" || ch === '"' || ch === "`") {
          const quote = ch;
          pos++;
          while (pos < content.length && content[pos] !== quote) {
            if (content[pos] === "\\") pos++;
            pos++;
          }
        }
        pos++;
      }
      // pos is now at the closing ')' of .then(...)
      const afterClose = content.slice(pos + 1, pos + 1 + 100);
      if (/\.\s*(?:catch|finally)\s*\(/.test(afterClose)) continue;
      hits.push(`async call without await: ${m[0].slice(0, 80)}`);
    }

    if (hits.length > 0) unhandledPromiseFiles.set(file, hits.slice(0, 10));
  }

  if (unhandledPromiseFiles.size > 0) {
    findings.push({
      ruleId: "DK-ERR-006",
      title: "Unhandled Promise rejection",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["promiseErrorHandling"],
      consequence: "Unhandled rejections crash Node.js processes. Demo code often fires promises and forgets about them, working fine locally but crashing under real load.",
      acceptanceCriteria: [
        "Every Promise chain must have a .catch() handler.",
        "Every async function call should be awaited or have explicit error handling.",
      ],
      evidence: evidence(unhandledPromiseFiles, "err-006"),
    });
  }

  // ---------------------------------------------------------------------------
  // DK-ERR-010: Error handler returns stack trace to client
  // ---------------------------------------------------------------------------
  const stackTraceLeakFiles = new Map<string, string[]>();

  // JS/TS/Java: res.status(5xx).json({ error: err.message/stack }) patterns
  const leakJSPatterns = [
    // res.response.status(5xx).json/send/write with err details
    /(?:res|response)\s*\.\s*(?:status\s*\(\s*5\d{2}\s*\)\s*\.)?(?:json|send|write)\s*\([^)]*(?:err(?:or)?\.?(?:message|stack|toString)|e\.(?:message|stack|toString))\b/g,
    // res.status(5xx).json/send with err shorthand
    /(?:res|response)\s*\.\s*status\s*\(\s*5\d{2}\s*\)\s*\.\s*(?:json|send)\s*\(\s*(?:err|error|e)\s*\)/g,
  ];

  // Python: traceback/str(e)/repr(e) in HTTP response context
  const pyLeak = /(?:traceback\.format_exc|str\s*\(\s*e\s*\)|repr\s*\(\s*e\s*\))/g;
  const pyResponseContext = /(?:return\s+(?:Response|JSONResponse|jsonify|HttpResponse)|HTTPException)/;

  // Go: err.Error() in http.Error or JSON response context
  const goLeak = /(?:http\.Error|c\.JSON|json\.Marshal)\s*\([^)]*err\.Error\(\)/g;

  for (const [file, content] of fileContents) {
    const ext = file.slice(file.lastIndexOf(".")).toLowerCase();
    const hits: string[] = [];

    if (cStyleExts.has(ext)) {
      for (const pattern of leakJSPatterns) {
        for (const m of content.matchAll(pattern)) {
          // Exclude logging context (console.log, logger, etc.)
          const matchStr = m[0];
          if (/(?:console\.|logger\.|log\.|logging\.)/.test(matchStr)) continue;
          hits.push(`stack trace in response: ${matchStr.slice(0, 80)}`);
        }
      }
    }

    if (ext === ".py") {
      // Check if file has HTTP response context
      if (pyResponseContext.test(content)) {
        for (const m of content.matchAll(pyLeak)) {
          hits.push(`error detail in response: ${m[0].slice(0, 80)}`);
        }
      }
    }

    if (ext === ".go") {
      for (const m of content.matchAll(goLeak)) {
        hits.push(`err.Error() in HTTP response: ${m[0].slice(0, 80)}`);
      }
    }

    if (hits.length > 0) stackTraceLeakFiles.set(file, hits.slice(0, 10));
  }

  if (stackTraceLeakFiles.size > 0) {
    findings.push({
      ruleId: "DK-ERR-010",
      title: "Error handler returns stack trace to client",
      severity: "high",
      confidence: "high",
      missingControls: ["errorResponseSanitization"],
      consequence: "Returning stack traces to clients leaks internal architecture, file paths, database schema, dependency versions, and potentially credentials to attackers.",
      acceptanceCriteria: [
        "Return generic error messages to clients.",
        "Log full error details server-side.",
        "Use error codes instead of error messages in responses.",
      ],
      evidence: evidence(stackTraceLeakFiles, "err-010"),
    });
  }

  // ---------------------------------------------------------------------------
  // DK-PERF-006: Synchronous blocking call in async/event-loop context
  // ---------------------------------------------------------------------------
  const syncBlockFiles = new Map<string, string[]>();

  const jsSyncCalls = /readFileSync|writeFileSync|execSync|spawnSync|mkdirSync|readdirSync|unlinkSync|appendFileSync|copyFileSync|existsSync|statSync|accessSync|chmodSync/g;
  const pySyncCalls = /time\.sleep\s*\(|requests\.(?:get|post|put|delete|patch|head)\s*\(|urllib\.request\.urlopen/g;
  const jsAsyncKeyword = /\basync\s+(?:function|\(|[a-zA-Z_]\w*\s*(?:=|:))/;
  const pyAsyncKeyword = /\basync\s+(?:def|with|for)\b/;

  for (const [file, content] of fileContents) {
    if (/src[/\\](?:rules|call-graph|python-call-graph|source-inspector|cli|inventory)[/\\.]|(?:vscode-extension)/.test(file)) continue;
    const ext = file.slice(file.lastIndexOf(".")).toLowerCase();
    const hits: string[] = [];

    if (jsTsExts.has(ext)) {
      if (!jsAsyncKeyword.test(content)) continue;
      for (const m of content.matchAll(jsSyncCalls)) {
        hits.push(`sync blocking call in async context: ${m[0]}`);
      }
    }

    if (ext === ".py") {
      if (!pyAsyncKeyword.test(content)) continue;
      for (const m of content.matchAll(pySyncCalls)) {
        hits.push(`sync blocking call in async context: ${m[0].slice(0, 80)}`);
      }
    }

    if (hits.length > 0) syncBlockFiles.set(file, [...new Set(hits)].slice(0, 10));
  }

  if (syncBlockFiles.size > 0) {
    findings.push({
      ruleId: "DK-PERF-006",
      title: "Synchronous blocking call in async/event-loop context",
      severity: "high",
      confidence: "medium",
      missingControls: ["asyncIOCompliance"],
      consequence: "One request with a 50ms sync block is invisible. 100 concurrent requests each block the event loop for 50ms = 5 seconds total stall. Sync I/O in async code freezes all concurrent connections.",
      acceptanceCriteria: [
        "Use async equivalents: fs.promises.readFile, subprocess.run, aiohttp.",
        "Never mix sync I/O with async event loops.",
      ],
      evidence: evidence(syncBlockFiles, "perf-006"),
    });
  }

  return findings;
}
