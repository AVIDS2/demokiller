import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function apiGatewayFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "api-gateway") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx",".go",".py",".yml",".yaml"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-APIGW-001: No rate limiting — only fire if project has gateway-specific patterns (proxy middleware, route aggregation)
  const hasGatewayIndicators = /createProxyMiddleware|http-proxy-middleware|express-rate-limit|express-gateway|\bkong\b|app\.use\(\s*['"]\/(?:api\/v\d+|v\d+)/i.test(allContent);
  if (hasGatewayIndicators && !/(?:rate[\s_-]*limit|throttle|rateLimit|express-rate-limit)/i.test(allContent)) {
    findings.push({
      ruleId: "DK-APIGW-001",
      title: "No rate limiting detected on API gateway",
      severity: "high",
      confidence: "medium",
      missingControls: ["rate limiting", "throttling"],
      consequence: "The gateway is vulnerable to brute-force attacks, credential stuffing, and denial-of-service without any request rate enforcement.",
      acceptanceCriteria: [
        "Add a rate-limiting middleware (e.g., express-rate-limit, Kong rate-limit plugin, or equivalent) applied globally or per-route",
        "Configure sensible limits appropriate to the endpoint sensitivity (e.g., 100 req/min for public, 30 req/min for auth endpoints)",
      ],
      evidence: [{ id: "DK-APIGW-001-1", detector: "pattern-match", location: { path: files[0] }, controls: [], signals: ["express/listen found", "no rate-limit middleware found"] }],
    });
  }

  // DK-APIGW-002: Auth bypass
  if (/(?:proxy|route|app\.use|app\.get|app\.post)/.test(allContent) && !/(?:auth|jwt|bearer|token|session|requireAuth|passport)/i.test(allContent)) {
    findings.push({
      ruleId: "DK-APIGW-002",
      title: "Authentication bypass risk on API gateway routes",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["authentication", "authorization"],
      consequence: "Routes or proxy rules are exposed without any authentication layer, allowing unauthenticated access to backend services.",
      acceptanceCriteria: [
        "Add authentication middleware (JWT, OAuth, API key, or session-based) before route/proxy handlers",
        "Ensure all non-public routes require a valid credential and return 401/403 on failure",
      ],
      evidence: [{ id: "DK-APIGW-002-1", detector: "pattern-match", location: { path: files[0] }, controls: [], signals: ["proxy/route/use found", "no auth middleware found"] }],
    });
  }

  // DK-APIGW-003: No request size limit
  if (/express\.json\(\)/.test(allContent) && !/(?:limit|size|maxLength|"?\d+[kKmM][bB]?")/.test(allContent)) {
    findings.push({
      ruleId: "DK-APIGW-003",
      title: "No request body size limit configured",
      severity: "medium",
      confidence: "medium",
      missingControls: ["request size limit"],
      consequence: "The gateway accepts arbitrarily large request bodies, enabling memory exhaustion and payload-based denial-of-service attacks.",
      acceptanceCriteria: [
        "Set a `limit` option on body parser middleware (e.g., express.json({ limit: '1mb' }))",
        "Apply the same limit to all body-parsing middleware (urlencoded, multipart, etc.)",
      ],
      evidence: [{ id: "DK-APIGW-003-1", detector: "pattern-match", location: { path: files[0] }, controls: [], signals: ["express.json() found without size limit option"] }],
    });
  }

  // DK-APIGW-004: Backend SSRF via proxy — require `target` near proxy context (createProxyMiddleware, proxy setup)
  const lines = allContent.split("\n");
  const hasProxyTarget = lines.some(l =>
    /createProxyMiddleware|http-proxy|proxy/i.test(l) && /target/i.test(l)
  );
  if (hasProxyTarget && !/(?:allowlist|whitelist|validat.*url|allowedHosts|isAllowedHost)/i.test(allContent)) {
    findings.push({
      ruleId: "DK-APIGW-004",
      title: "Server-Side Request Forgery risk via proxy configuration",
      severity: "high",
      confidence: "medium",
      missingControls: ["target allowlist", "URL validation"],
      consequence: "The proxy forwards requests to arbitrary backend targets without validation, enabling SSRF attacks that can reach internal services and metadata endpoints.",
      acceptanceCriteria: [
        "Maintain an explicit allowlist of permitted proxy target hosts/IPs",
        "Validate and sanitize all user-influenced target URLs before proxying",
        "Block requests to RFC 1918, link-local, and cloud metadata addresses unless explicitly required",
      ],
      evidence: [{ id: "DK-APIGW-004-1", detector: "pattern-match", location: { path: files[0] }, controls: [], signals: ["createProxyMiddleware/proxy target found", "no target allowlist or URL validation found"] }],
    });
  }

  return findings;
}
