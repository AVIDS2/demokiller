import { promises as fs } from "node:fs";
import path from "node:path";
import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";

// ─── File walking ────────────────────────────────────────────────

const SKIP_DIRS = new Set([
  "node_modules", ".next", "dist", "build", "target", "__pycache__",
  ".venv", "venv", "vendor", ".git", "out", "bin", "obj",
  "fixtures", "testdata", "samples", "e2e", ".worktrees", ".demokiller", ".claude",
]);

async function walkSourceFiles(root: string, dir = root): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const result: string[] = [];
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...(await walkSourceFiles(root, fullPath)));
    } else {
      const rel = path.relative(root, fullPath).replaceAll("\\", "/");
      if (/\.(ts|tsx|js|jsx|mts|mjs|py|go|rs)$/.test(rel)) {
        result.push(rel);
      }
    }
  }
  return result;
}

// ─── Detection patterns ─────────────────────────────────────────

interface RuleMatch {
  ruleId: string;
  file: string;
  line: number;
  signal: string;
}

// DK-AGENT-006: Tool allowlist not enforced
// Guard: file must be in an actual MCP/agent server context, not a utility or detection file
const MCP_CONTEXT_RE = /\bnew\s+(?:Server|McpServer)|@modelcontextprotocol|mcp-sdk|SSEServerTransport|StdioServerTransport|agent\s*(?:Loop|Run|Step|Execute)|openai\.chat|anthropic\.messages|ChatCompletion|langchain/i;
// Files that are detection/analysis utilities, not actual MCP servers
const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe|agent-mcp|security-hardening|error-handling|performance-rules|observability|deployment-rules|python-rules|environment-rules|baseline|benchmark|plugin|repository|config)/;
const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;
const FIXTURE_RE = /(?:^|[\\/])(?:fixtures|testdata|samples|test|tests|__tests__|spec|specs|__test__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;
function detectNoAllowlist(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  if (!MCP_CONTEXT_RE.test(text)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // MCP tool definitions without validation
    // Pattern: server.tool("name", handler) or .addTool / .registerTool without allowlist nearby
    if (/\.tool\s*\(\s*['"`]/.test(line) || /\.addTool\s*\(/.test(line) || /\.registerTool\s*\(/.test(line)) {
      // Check surrounding context for allowlist/validation
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 10)).join("\n");
      const hasAllowlist = /allowlist|allowedTools|permittedTools|toolWhitelist|TOOL_ALLOW|validateTool|isToolAllowed|toolFilter/i.test(context);
      if (!hasAllowlist) {
        matches.push({ ruleId: "DK-AGENT-006", file, line: i + 1, signal: "tool definition without allowlist validation" });
      }
    }

    // Dynamic tool loading without checks
    if (/tools\s*[=:]\s*\[/.test(line) && /tools\s*[=:]\s*\[\s*\.\.\./.test(line)) {
      matches.push({ ruleId: "DK-AGENT-006", file, line: i + 1, signal: "spread-based dynamic tool loading without validation" });
    }
  }
  return matches;
}

// DK-AGENT-007: Prompt injection via tool inputs
function detectPromptInjection(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  // Gate: require AI/LLM context — prevents false positives on non-AI projects (CMS, testing tools, etc.)
  if (!MCP_CONTEXT_RE.test(text)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Template literals with user input in prompt construction
    if (/\b(?:system|prompt|instruction)\w*\s*[=:]\s*`[^`]*\$\{/.test(line)) {
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 5)).join("\n");
      const hasSanitize = /sanitiz|escap|validat|schema|zod|joi|structur/i.test(context);
      if (!hasSanitize) {
        matches.push({ ruleId: "DK-AGENT-007", file, line: i + 1, signal: "template literal with interpolation in prompt construction" });
      }
    }

    // String concatenation in prompt construction
    if (/\b(?:system|prompt|instruction)\w*\s*[=:]\s*['"`].*\+\s*(?:user|input|param|arg|req\.)/i.test(line)) {
      matches.push({ ruleId: "DK-AGENT-007", file, line: i + 1, signal: "string concatenation with user input in prompt" });
    }

    // f-strings in Python prompt templates
    if (/\b(?:system|prompt|instruction)\w*\s*=\s*f['"]/.test(line) && /\{(?:user|input|param|arg|request)/i.test(line)) {
      matches.push({ ruleId: "DK-AGENT-007", file, line: i + 1, signal: "f-string with user input in prompt construction" });
    }

    // Content passed directly from request to messages
    if (/\bcontent\s*[=:]\s*(?:req\.body|request\.(?:body|json)|args|params)\b/i.test(line)) {
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 5)).join("\n");
      const hasRole = /role\s*[=:]\s*['"`]user['"`]/i.test(context) || /messages.*push|messages.*append/i.test(context);
      const hasSanitize = /sanitiz|escap|validat|schema|zod|joi/i.test(context);
      if (hasRole && !hasSanitize) {
        matches.push({ ruleId: "DK-AGENT-007", file, line: i + 1, signal: "user input passed to LLM messages without sanitization" });
      }
    }
  }
  return matches;
}

// DK-AGENT-008: Secret/context leak in agent responses
function detectSecretLeak(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  // Gate: require MCP/agent context — prevents false positives on non-AI web APIs
  if (!MCP_CONTEXT_RE.test(text)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Env vars directly exposed in responses or tool outputs
    if (/\breturn\b.*process\.env\b/i.test(line) || /\breturn\b.*os\.environ/i.test(line) || /\breturn\b.*os\.getenv/i.test(line)) {
      matches.push({ ruleId: "DK-AGENT-008", file, line: i + 1, signal: "env var directly returned in response" });
    }

    // Response objects containing env vars without redaction
    if (/(?:response|result|output|reply)\s*[=:]\s*\{[^}]*(?:process\.env|os\.environ|os\.getenv)/i.test(line)) {
      matches.push({ ruleId: "DK-AGENT-008", file, line: i + 1, signal: "env var included in response object" });
    }

    // Direct exposure of secrets in JSON response
    if (/(?:json|send|respond|reply)\s*\([^)]*(?:apiKey|api_key|secret|token|password|connectionString|database_url)\b/i.test(line)) {
      const context = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 3)).join("\n");
      const hasRedact = /redact|mask|omit|hidden|censor|scrub/i.test(context);
      if (!hasRedact) {
        matches.push({ ruleId: "DK-AGENT-008", file, line: i + 1, signal: "secret value returned in response without redaction" });
      }
    }

    // Database connection strings in tool output
    if (/(?:postgres|mysql|mongodb|redis):\/\/[^\s'"]*\$\{/i.test(line) || /(?:postgres|mysql|mongodb|redis):\/\/.*@/i.test(line)) {
      const context = lines.slice(Math.max(0, i - 2), Math.min(lines.length, i + 3)).join("\n");
      if (/(?:return|send|json|respond|output|log)/i.test(context)) {
        matches.push({ ruleId: "DK-AGENT-008", file, line: i + 1, signal: "database connection string in tool output" });
      }
    }
  }
  return matches;
}

// DK-AGENT-009: Unbounded agent loop
function detectUnboundedLoop(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // while(true) or while(True) in agent context
    if (/\bwhile\s*\(\s*(?:true|True|1)\s*\)/.test(line)) {
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 15)).join("\n");
      const isAgentLoop = /agent|llm|openai|anthropic|claude|completion|chat|step|iteration|loop/i.test(context);
      const hasLimit = /maxIterations|maxSteps|max_iters|max_turns|iteration.*limit|step.*limit|break|counter|count\s*[><=]/i.test(context);
      if (isAgentLoop && !hasLimit) {
        matches.push({ ruleId: "DK-AGENT-009", file, line: i + 1, signal: "while(true) in agent loop without max iteration limit" });
      }
    }

    // Recursive agent/step calls without depth limit
    if (/\b(?:runAgent|runStep|execute|process|handleStep|nextStep|agentLoop)\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, i - 15), Math.min(lines.length, i + 5)).join("\n");
      const isRecursive = context.includes(line.trim().split("(")[0]);
      const hasDepthCheck = /depth|maxDepth|max_depth|recursion.*limit|depth.*limit|maxRecursion/i.test(context);
      if (isRecursive && !hasDepthCheck) {
        matches.push({ ruleId: "DK-AGENT-009", file, line: i + 1, signal: "recursive agent call without depth limit" });
      }
    }

    // Agent config without maxIterations
    if (/\bagent\s*(?:Config|Options|Settings|Config)?\s*[=:]\s*\{/.test(line)) {
      const context = lines.slice(i, Math.min(lines.length, i + 15)).join("\n");
      const hasIterationLimit = /maxIterations|maxSteps|max_iters|max_turns|maxIterations/i.test(context);
      if (!hasIterationLimit && /llm|openai|anthropic|model|chat|completion/i.test(context)) {
        matches.push({ ruleId: "DK-AGENT-009", file, line: i + 1, signal: "agent config without maxIterations/maxSteps" });
      }
    }
  }
  return matches;
}

// DK-AGENT-010: Unsafe filesystem tool
// Guard: file must be an actual tool handler in MCP context
const TOOL_HANDLER_RE = /server\.tool\s*\(|\.addTool\s*\(|\.registerTool\s*\(|McpServer|handleTool|toolHandler/i;
function detectUnsafeFs(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  // Gate: require MCP context AND tool handler patterns
  if (!MCP_CONTEXT_RE.test(text)) return [];
  if (!TOOL_HANDLER_RE.test(text)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // fs.readFile/writeFile with user-controlled path in tool context
    if (/\bfs\.(?:readFile|writeFile|readFileSync|writeFileSync|readdir|mkdir|rm|unlink|access)\s*\(/.test(line) ||
        /\bfs\.promises\.(?:readFile|writeFile|readdir|mkdir|rm|unlink|access)\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, i - 10), Math.min(lines.length, i + 5)).join("\n");
      const isTool = /tool|handler|execute|call|request|param|input|user/i.test(context);
      const hasSandbox = /sandbox|allowlist|allowedDir|allowedPath|whitelist|chroot|path\.resolve.*startsWith|realpath|restricted|safepath|baseDir|allowedRoot/i.test(context);
      if (isTool && !hasSandbox) {
        matches.push({ ruleId: "DK-AGENT-010", file, line: i + 1, signal: "filesystem operation in tool handler without path sandboxing" });
      }
    }

    // path.join with user input without validation
    if (/path\.join\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, i - 8), Math.min(lines.length, i + 5)).join("\n");
      const isTool = /tool|handler|execute|request|param|input|user|args|body/i.test(context);
      const hasValidation = /resolve.*startsWith|allowlist|allowedDir|chroot|sanitize|normalize|realpath|restricted|safepath|traversal/i.test(context);
      if (isTool && !hasValidation) {
        matches.push({ ruleId: "DK-AGENT-010", file, line: i + 1, signal: "path.join in tool context without directory validation" });
      }
    }
  }
  return matches;
}

// DK-AGENT-011: MCP server authentication missing
function detectMcpNoAuth(text: string, file: string): RuleMatch[] {
  const matches: RuleMatch[] = [];
  if (DETECTION_UTIL_RE.test(file) || REPORT_UTIL_RE.test(file) || FIXTURE_RE.test(file)) return [];
  const lines = text.split("\n");

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Express/Fastify/Koa server with /mcp or /sse routes but no auth middleware
    if (/\b(?:app|server|router)\s*\.\s*(?:get|post|all|use)\s*\(\s*['"`]\/(?:mcp|sse|messages|rpc)['"`]/i.test(line)) {
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5)).join("\n");
      const hasAuth = /auth|bearer|apiKey|api_key|token|authenticate|authorize|middleware.*auth|requireAuth|isAuthenticated|checkAuth|verifyToken|validateKey/i.test(context);
      if (!hasAuth) {
        matches.push({ ruleId: "DK-AGENT-011", file, line: i + 1, signal: "MCP/SSE endpoint without authentication middleware" });
      }
    }

    // MCP server started without auth (new Server() or McpServer() without auth setup)
    if (/\bnew\s+(?:Server|McpServer)\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 20)).join("\n");
      const hasAuth = /auth|bearer|apiKey|api_key|token|authenticate|authorize|requireAuth|isAuthenticated|checkAuth|verifyToken|validateKey|authenticateConnection/i.test(context);
      const isHttpServer = /express|fastify|http\.createServer|app\.listen|server\.listen|SSEServerTransport|StdioServerTransport/i.test(context);
      if (!hasAuth && isHttpServer) {
        matches.push({ ruleId: "DK-AGENT-011", file, line: i + 1, signal: "MCP server started without authentication" });
      }
    }

    // HTTP server listening on MCP-related paths without auth
    if (/\blisten\s*\(/.test(line)) {
      const context = lines.slice(Math.max(0, i - 20), Math.min(lines.length, i + 5)).join("\n");
      const isMcpServer = /mcp|modelcontextprotocol|@modelcontextprotocol|McpServer|SSEServerTransport/i.test(context);
      const hasAuth = /auth|bearer|apiKey|api_key|token|authenticate|authorize|requireAuth|isAuthenticated|verifyToken/i.test(context);
      if (isMcpServer && !hasAuth) {
        matches.push({ ruleId: "DK-AGENT-011", file, line: i + 1, signal: "HTTP server with MCP without authentication" });
      }
    }
  }
  return matches;
}

// ─── Main export ─────────────────────────────────────────────────

export async function agentMcpFindings(root: string, _inventory: ProjectInventory): Promise<Finding[]> {
  const files = await walkSourceFiles(root);
  const allMatches: RuleMatch[] = [];

  for (const file of files) {
    let text: string;
    try {
      text = await fs.readFile(path.join(root, file), "utf8");
    } catch {
      continue;
    }

    allMatches.push(
      ...detectNoAllowlist(text, file),
      ...detectPromptInjection(text, file),
      ...detectSecretLeak(text, file),
      ...detectUnboundedLoop(text, file),
      ...detectUnsafeFs(text, file),
      ...detectMcpNoAuth(text, file),
    );
  }

  if (allMatches.length === 0) return [];

  // Group matches by ruleId
  const grouped = new Map<string, RuleMatch[]>();
  for (const m of allMatches) {
    const arr = grouped.get(m.ruleId) ?? [];
    arr.push(m);
    grouped.set(m.ruleId, arr);
  }

  const RULE_DEFS: Record<string, Omit<Finding, "ruleId" | "evidence">> = {
    "DK-AGENT-006": {
      title: "Tool allowlist not enforced in MCP/agent server",
      severity: "blocker",
      confidence: "high",
      missingControls: ["toolAllowlist"],
      consequence: "Without an explicit tool allowlist, any registered tool can be invoked by the agent or a malicious prompt, leading to unauthorized actions, data access, or system compromise.",
      acceptanceCriteria: [
        "Tool calls are validated against an explicit allowlist before execution.",
        "Only pre-approved tools are registered with the MCP server.",
        "Runtime tool filtering rejects unknown or unauthorized tool names.",
      ],
    },
    "DK-AGENT-007": {
      title: "Prompt injection via unsanitized tool inputs",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["inputSanitization"],
      consequence: "User-supplied data is interpolated directly into LLM prompts, allowing attackers to inject instructions that override system behavior, extract secrets, or cause unintended agent actions.",
      acceptanceCriteria: [
        "Tool inputs are validated and sanitized before inclusion in prompts.",
        "User input is passed as structured data, not interpolated into prompt templates.",
        "System prompts use message roles to separate instructions from user content.",
      ],
    },
    "DK-AGENT-008": {
      title: "Secret or context leak in agent/tool responses",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["outputRedaction"],
      consequence: "API keys, tokens, database credentials, or internal context can leak through agent tool outputs, exposing sensitive infrastructure to end users or attackers.",
      acceptanceCriteria: [
        "Sensitive values are redacted or omitted from tool outputs.",
        "Structured response schemas prevent accidental secret inclusion.",
        "Output scanning detects and blocks secret patterns before responses are sent.",
      ],
    },
    "DK-AGENT-009": {
      title: "Unbounded agent loop without iteration limit",
      severity: "high",
      confidence: "high",
      missingControls: ["iterationLimit"],
      consequence: "An agent loop without a maximum iteration count can run indefinitely, consuming API credits, CPU, and memory until the process crashes or the budget is exhausted.",
      acceptanceCriteria: [
        "Agent loops have an explicit maxIterations or maxSteps limit.",
        "A timeout is configured for the entire agent run.",
        "Recursive agent calls track depth and terminate at a configured maximum.",
      ],
    },
    "DK-AGENT-010": {
      title: "Unsafe filesystem tool without path sandboxing",
      severity: "blocker",
      confidence: "high",
      missingControls: ["pathSandboxing"],
      consequence: "A filesystem tool that accepts arbitrary paths allows an agent or attacker to read, write, or delete any file on the host system, including credentials, configuration, and system files.",
      acceptanceCriteria: [
        "File operations are restricted to an explicit allowlist of directories.",
        "Paths are resolved and validated with path.resolve + startsWith checks.",
        "Symlink traversal is prevented by using realpath before validation.",
      ],
    },
    "DK-AGENT-011": {
      title: "MCP server endpoints without authentication",
      severity: "blocker",
      confidence: "high",
      missingControls: ["endpointAuth"],
      consequence: "MCP server endpoints exposed without authentication allow any client to invoke tools, access resources, and execute agent actions without identity verification.",
      acceptanceCriteria: [
        "MCP server endpoints require authentication (API key, token, or session).",
        "Tool invocations are logged with caller identity.",
        "Sensitive tools require explicit authorization checks beyond initial authentication.",
      ],
    },
  };

  const findings: Finding[] = [];

  for (const [ruleId, matches] of grouped) {
    const def = RULE_DEFS[ruleId];
    if (!def) continue;

    findings.push({
      ...def,
      ruleId,
      evidence: matches.map((m, i) => ({
        id: `${ruleId.toLowerCase()}-${i}`,
        detector: "agent-mcp-scan",
        location: { path: m.file, line: m.line },
        controls: [],
        signals: [m.signal],
      })),
    });
  }

  return findings;
}
