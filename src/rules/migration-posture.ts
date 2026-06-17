import type { ProjectInventory } from "../inventory.js";
import type { Finding } from "../types.js";

export function migrationPostureRule(inventory: ProjectInventory): Finding[] {
  if (!inventory.prismaSchemaPath || inventory.migrationPaths.length > 0) return [];

  return [
    {
      ruleId: "DK-DB-001",
      title: "Database schema exists without migration evidence",
      severity: "high",
      confidence: "medium",
      asset: "database schema",
      missingControls: ["migration"],
      consequence:
        "Schema changes cannot be reproduced, reviewed, or rolled forward consistently in production.",
      acceptanceCriteria: [
        "Database schema changes are represented by committed migration files.",
        "Deployment docs or scripts apply migrations before serving production traffic.",
      ],
      evidence: [
        {
          id: "prisma-schema",
          detector: "inventory",
          location: { path: inventory.prismaSchemaPath },
          asset: "database schema",
          controls: [],
          signals: ["prismaSchemaWithoutMigrations"],
        },
      ],
    },
  ];
}
