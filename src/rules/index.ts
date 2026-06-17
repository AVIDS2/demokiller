import { buildInventory } from "../inventory.js";
import { inspectRouteSource } from "../source-inspector.js";
import type { Finding } from "../types.js";
import { adminMutationAuthRule } from "./admin-mutation-auth.js";
import { envContractRule } from "./env-contract.js";
import { migrationPostureRule } from "./migration-posture.js";
import { observabilityRule } from "./observability.js";
import { publicAiRouteRule } from "./public-ai-route.js";
import { webhookSafetyRule } from "./webhook-safety.js";

async function readDeclaredEnvVars(root: string, envExamplePath?: string): Promise<string[]> {
  if (!envExamplePath) return [];

  const { promises: fs } = await import("node:fs");
  const path = await import("node:path");
  const text = await fs.readFile(path.join(root, envExamplePath), "utf8");

  return text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith("#"))
    .map((line) => line.split("=", 1)[0])
    .filter((name) => name.length > 0);
}

export async function analyzeFindings(root: string): Promise<Finding[]> {
  const inventory = await buildInventory(root);
  const routeEvidence = await Promise.all(
    inventory.apiRoutes.map((route) => inspectRouteSource(root, route)),
  );
  const usedEnvVars = Array.from(new Set(routeEvidence.flatMap((route) => route.envVars)));
  const declaredEnvVars = await readDeclaredEnvVars(root, inventory.envExamplePath);

  return [
    ...routeEvidence.flatMap(publicAiRouteRule),
    ...routeEvidence.flatMap(adminMutationAuthRule),
    ...routeEvidence.flatMap(webhookSafetyRule),
    ...routeEvidence.flatMap(observabilityRule),
    ...envContractRule(inventory, usedEnvVars, declaredEnvVars),
    ...migrationPostureRule(inventory),
  ];
}
