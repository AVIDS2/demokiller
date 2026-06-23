import path from "node:path";
import { Project, SyntaxKind } from "ts-morph";

export interface RouteSourceEvidence {
  path: string;
  capabilities: string[];
  controls: string[];
  envVars: string[];
  line: number;
}

function pushUnique(target: string[], value: string) {
  if (!target.includes(value)) target.push(value);
}

export async function inspectRouteSource(
  root: string,
  relativePath: string,
): Promise<RouteSourceEvidence> {
  const project = new Project({ useInMemoryFileSystem: false });
  const sourceFile = project.addSourceFileAtPath(path.join(root, relativePath));
  const text = sourceFile.getFullText();
  const firstFunction = sourceFile.getFunctions()[0];
  const line = firstFunction?.getStartLineNumber() ?? 1;

  const capabilities: string[] = [];
  const controls: string[] = [];
  const envVars = Array.from(text.matchAll(/process\.env\.([A-Z0-9_]+)/g)).map(
    (match) => match[1],
  );

  if (text.includes("openai") || text.includes("OpenAI") || text.includes("chat.completions")) {
    pushUnique(capabilities, "callsOpenAI");
  }
  if (text.includes("stripe") || text.includes("Stripe")) {
    pushUnique(capabilities, "handlesPaymentProvider");
  }
  if (text.includes("prisma.") && text.match(/\.(delete|update|create|upsert)\s*\(/)) {
    pushUnique(capabilities, "mutatesDatabase");
  }
  if (text.includes("prisma.") && text.match(/\.(findFirst|findMany|findUnique)\s*\(/)) {
    pushUnique(capabilities, "readsDatabase");
  }
  if (
    text.match(/await\s+(request|req)\.json\s*\(/) ||
    text.match(/\b(request|req)\.body\b/)
  ) {
    pushUnique(capabilities, "consumesRequestBody");
  }

  if (text.match(/\bauth\s*\(/) || text.includes("getServerSession") || text.includes("currentUser")) {
    pushUnique(controls, "auth");
  }
  if (text.includes("role") || text.includes("isAdmin") || text.includes("permission")) {
    pushUnique(controls, "authorization");
  }
  if (text.includes("rateLimit") || text.includes("limiter")) {
    pushUnique(controls, "rateLimit");
  }
  if (text.includes("quota") || text.includes("usageLimit") || text.includes("monthlyLimit")) {
    pushUnique(controls, "quota");
  }
  if (text.includes("constructEvent") || text.includes("STRIPE_WEBHOOK_SECRET")) {
    pushUnique(controls, "signatureVerification");
  }
  if (text.includes("idempotency") || text.includes("event.id")) {
    pushUnique(controls, "idempotency");
  }
  if (
    sourceFile
      .getDescendantsOfKind(SyntaxKind.CallExpression)
      .some((call) => {
        const t = call.getText();
        return (
          t.startsWith("console.") ||
          t.startsWith("logger.") ||
          t.startsWith("log.") ||
          t.startsWith("auditLog") ||
          t.startsWith("structuredLog")
        );
      })
  ) {
    pushUnique(controls, "logging");
  }
  if (
    text.match(/\bimport\b.*\bfrom\b.*['"]zod['"]/) ||
    text.match(/\bimport\b.*\bfrom\b.*['"]yup['"]/) ||
    text.match(/\bimport\b.*\bfrom\b.*['"]joi['"]/) ||
    text.match(/\.parse\s*\(/) ||
    text.match(/\.safeParse\s*\(/) ||
    text.match(/\.validate\s*\(/)
  ) {
    pushUnique(controls, "inputValidation");
  }
  if (
    sourceFile.getDescendantsOfKind(SyntaxKind.TryStatement).length > 0 ||
    text.match(/\.catch\s*\(/) ||
    text.match(/error\s*[,)]/)
  ) {
    pushUnique(controls, "errorHandling");
  }
  if (
    text.includes("Access-Control-Allow-Origin") ||
    text.match(/\bcors\s*\(\s*\)/) ||
    text.match(/\bcors\s*\(\s*\{\s*\}\s*\)/) ||
    text.match(/origin:\s*['"]?\*['"]?/)
  ) {
    pushUnique(controls, "corsWildcard");
  }
  if (
    sourceFile
      .getDescendantsOfKind(SyntaxKind.CallExpression)
      .some((call) => {
        const t = call.getText();
        return t.startsWith("console.log") || t.startsWith("console.debug");
      })
  ) {
    pushUnique(controls, "debugStatements");
  }

  return { path: relativePath, capabilities, controls, envVars, line };
}
