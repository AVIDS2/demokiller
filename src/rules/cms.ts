import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function cmsFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "cms") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx",".py",".php"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-CMS-001 (blocker,high): SQL/NoSQL injection - check query methods with user input without sanitiz/validat/escape/ORM
  {
    const hasSanitization = /sanitiz|validat|escape|parameterize|prepared/i.test(allContent);
    // Check each query method separately to avoid nested-paren regex issues
    const queryMethods = [
      /strapi\.db\.query\s*\(/,
      /\.query\s*\(/,
      /\.findMany\s*\(/,
      /\.findOne\s*\(/,
      /\.delete\s*\(/,
      /\.update\s*\(/,
      /\.create\s*\(/,
    ];
    const userInputPattern = /ctx\.query|ctx\.params|req\.body|req\.query|req\.params/;
    if (!hasSanitization) {
      for (const file of files) {
        const content = await readFileContent(root, file);
        const hasQueryMethod = queryMethods.some(re => re.test(content));
        const hasUserInput = userInputPattern.test(content);
        if (hasQueryMethod && hasUserInput) {
          findings.push({
            ruleId: "DK-CMS-001",
            title: "SQL/NoSQL injection risk: user input passed to database query without sanitization",
            severity: "blocker",
            confidence: "medium",
            missingControls: ["Input sanitization", "Input validation", "Query parameterization", "ORM-based query building"],
            consequence: "An attacker can manipulate database queries to extract, modify, or delete arbitrary data, potentially gaining full control of the application.",
            acceptanceCriteria: [
              "All database queries use parameterized statements or an ORM with built-in escaping",
              "User input is validated and sanitized before being used in any query context",
              "Input validation rejects unexpected characters and patterns"
            ],
            evidence: [{
              id: "DK-CMS-001-1",
              detector: "pattern-match",
              location: { path: file },
              controls: [],
              signals: ["User input from ctx.query/ctx.params/req.body found in same file as database query call", "No sanitization, validation, or escape functions detected in codebase"]
            }]
          });
        }
      }
    }
  }

  // DK-CMS-002 (high,medium): Unrestricted admin access - check admin/api routes without auth/role/permission check
  {
    const adminRoutePattern = /(?:router\.(?:get|post|put|delete|use)\s*\(\s*['"]\/admin|app\.(?:get|post|put|delete|use)\s*\(\s*['"]\/admin|isAdmin|adminOnly|admin.*(?:route|controller|policy)|strapi\.admin)/i;
    const hasAuthCheck = /auth|role|permission|middleware.*auth|isAuthenticated|protect|guard/i.test(allContent);
    if (adminRoutePattern.test(allContent) && !hasAuthCheck) {
      for (const file of files) {
        const content = await readFileContent(root, file);
        if (adminRoutePattern.test(content)) {
          findings.push({
            ruleId: "DK-CMS-002",
            title: "Admin routes accessible without authentication or authorization checks",
            severity: "high",
            confidence: "medium",
            missingControls: ["Authentication middleware", "Role-based access control", "Permission verification"],
            consequence: "Unauthorized users can access administrative endpoints, allowing them to modify content, users, and system configuration.",
            acceptanceCriteria: [
              "All admin routes are protected by authentication middleware",
              "Authorization checks verify the user has admin role or appropriate permissions",
              "Unauthorized access attempts return 401/403 responses"
            ],
            evidence: [{
              id: "DK-CMS-002-1",
              detector: "pattern-match",
              location: { path: file },
              controls: [],
              signals: ["Admin route or endpoint detected without accompanying auth middleware", "No authentication or role-based checks found in codebase"]
            }]
          });
        }
      }
    }
  }

  // DK-CMS-003 (medium,medium): File upload without validation - check upload/multer/formidable without mime.*check/type.*check/size.*limit/allowlist
  {
    const uploadPattern = /(?:multer|formidable|upload|fileUpload|multipart)/i;
    const hasUploadValidation = /mime.*check|type.*check|size.*limit|allowlist|allowedMime|fileFilter|limits\s*:/i.test(allContent);
    if (uploadPattern.test(allContent) && !hasUploadValidation) {
      for (const file of files) {
        const content = await readFileContent(root, file);
        if (uploadPattern.test(content)) {
          findings.push({
            ruleId: "DK-CMS-003",
            title: "File upload endpoint lacks MIME type validation, size limits, or allowlist",
            severity: "medium",
            confidence: "medium",
            missingControls: ["MIME type validation", "File size limits", "File extension allowlist", "File content inspection"],
            consequence: "Attackers can upload malicious files (web shells, executables, oversized files) to compromise the server or cause denial of service.",
            acceptanceCriteria: [
              "File uploads validate MIME type against an allowlist",
              "File size limits are enforced",
              "Uploaded files are stored outside the web root or with non-executable permissions",
              "File content is inspected, not just extension"
            ],
            evidence: [{
              id: "DK-CMS-003-1",
              detector: "pattern-match",
              location: { path: file },
              controls: [],
              signals: ["File upload mechanism detected (multer/formidable/upload)", "No MIME type validation, size limits, or allowlist found"]
            }]
          });
        }
      }
    }
  }

  return findings;
}
