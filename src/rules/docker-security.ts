import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { promises as fs } from "node:fs";
import path from "node:path";

export async function dockerSecurityFindings(inventory: ProjectInventory): Promise<Finding[]> {
  if (!inventory.hasDockerfile) return [];

  let content: string;
  try {
    content = await fs.readFile(path.join(inventory.root, "Dockerfile"), "utf8");
  } catch {
    return [];
  }

  const issues: string[] = [];

  if (!content.match(/USER\s+\w+/) || content.match(/USER\s+root/)) {
    issues.push("Container runs as root user");
  }
  if (content.match(/EXPOSE\s+(9229|5858|debug)/)) {
    issues.push("Dockerfile exposes debug port");
  }
  if (content.match(/:\s*latest\b/)) {
    issues.push("Base image uses :latest tag (not pinned)");
  }
  if (!content.match(/HEALTHCHECK/)) {
    issues.push("No HEALTHCHECK instruction");
  }

  if (issues.length === 0) return [];

  return [
    {
      ruleId: "DK-DOCKER-001",
      title: `Dockerfile has ${issues.length} security issue(s)`,
      severity: "high",
      confidence: "medium",
      missingControls: ["dockerHardening"],
      consequence:
        "A misconfigured Docker container can be exploited to escape to the host, access internal services, or compromise the deployment environment.",
      acceptanceCriteria: [
        "Container runs as a non-root user (USER directive).",
        "Base images are pinned to specific versions, not :latest.",
        "Debug ports are not exposed in production.",
        "HEALTHCHECK instruction is present.",
      ],
      evidence: issues.map((issue, i) => ({
        id: `docker-${i}`,
        detector: "docker-check",
        location: { path: "Dockerfile" },
        controls: [],
        signals: [issue],
      })),
    },
  ];
}
