import type { ProjectInventory } from "../inventory.js";
import type { Finding } from "../types.js";

export function envContractRule(
  inventory: ProjectInventory,
  usedEnvVars: string[],
  declaredEnvVars: string[],
): Finding[] {
  const declared = new Set(declaredEnvVars);
  const missing = usedEnvVars.filter((name) => !declared.has(name));
  if (!inventory.envExamplePath || missing.length === 0) return [];

  return [
    {
      ruleId: "DK-ENV-001",
      title: "Production environment contract is incomplete",
      severity: "high",
      confidence: "medium",
      asset: "production configuration",
      missingControls: ["envContract"],
      consequence:
        "Production deploys can fail or run with incomplete provider configuration because required variables are not documented.",
      acceptanceCriteria: [
        "Every required production environment variable appears in .env.example or another explicit env contract.",
        "Required variables are documented without secret values.",
      ],
      evidence: [
        {
          id: "env-usage",
          detector: "inventory",
          location: { path: inventory.envExamplePath },
          asset: "production configuration",
          controls: [],
          signals: missing.map((name) => `missing:${name}`),
        },
      ],
    },
  ];
}
