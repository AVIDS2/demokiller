import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function cicdPipelineFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "cicd-pipeline") return [];
  const files = await walkSourceFiles(root, [".yml",".yaml",".json"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-CICD-001: Secrets in pipeline - hardcoded passwords, secrets, tokens, api keys, credentials
  // Exclude ${{ secrets.X }} (GitHub secure ref) and $VAR references — only match literal hardcoded values
  const secretPatterns =
    /(?:password|secret|token|api[_-]?key|credentials)\s*[:=]\s*['"][^'"]+['"]/i.test(allContent);

  if (secretPatterns) {
    findings.push({
      ruleId: "DK-CICD-001",
      title: "Secrets in pipeline configuration",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["secretManagement"],
      consequence: "Hardcoded secrets in pipeline files are committed to version control, exposing credentials to anyone with repository access. Secret rotation requires code changes and risks accidental exposure in build logs.",
      acceptanceCriteria: [
        "Secrets are stored in the CI platform's secret manager (GitHub Actions secrets, GitLab CI variables, etc.).",
        "Pipeline files reference secrets via environment variable bindings, not hardcoded values.",
        "Secret values are never committed to version control.",
      ],
      evidence: [{
        id: "cicd-scan",
        detector: "pattern-match",
        location: { path: "." },
        controls: [],
        signals: ["hardcoded secret or credential value found in pipeline configuration"],
      }],
    });
  }

  // DK-CICD-002: Unpinned actions - uses: owner/repo@main or @master
  const unpinnedActions =
    /uses:\s*\S+\/\S+@(?:main|master)\b/.test(allContent) ||
    /uses:\s*["']\S+\/\S+@(?:main|master)\b["']/.test(allContent);

  if (unpinnedActions) {
    findings.push({
      ruleId: "DK-CICD-002",
      title: "Unpinned GitHub Actions using mutable branch references",
      severity: "high",
      confidence: "medium",
      missingControls: ["actionPinning"],
      consequence: "Actions pinned to mutable branches (main, master) can be silently updated by the action author. A compromised or buggy upstream action will affect all pipeline runs without any change to the repository.",
      acceptanceCriteria: [
        "All third-party actions are pinned to a specific version tag (e.g., @v3) or a full commit SHA.",
        "Dependabot or Renovate is configured to update action pins automatically.",
        "Action versions are reviewed before updating.",
      ],
      evidence: [{
        id: "cicd-scan",
        detector: "pattern-match",
        location: { path: "." },
        controls: [],
        signals: ["action pinned to @main or @master branch instead of a version tag or SHA"],
      }],
    });
  }

  // DK-CICD-003: No artifact signing - publish/deploy/release in step names or action refs (not comments)
  // Require publish/deploy/release in YAML "name:" or "uses:" context; exclude comments (# ...)
  const lines = allContent.split("\n");
  const hasPublishStep =
    lines.some(l => /^\s*(?:name|uses)\s*[:=]/i.test(l) && /\b(?:publish|deploy|release|push)\b/i.test(l)) &&
    !lines.some(l => /\b(?:sign|gpg|cosign|sigstore|provenance|sbom)\b/i.test(l));

  if (hasPublishStep) {
    findings.push({
      ruleId: "DK-CICD-003",
      title: "Artifact publishing without signing or provenance attestation",
      severity: "medium",
      confidence: "medium",
      missingControls: ["artifactSigning"],
      consequence: "Published artifacts lack cryptographic signatures or provenance attestations. Downstream consumers cannot verify artifact integrity or origin, making supply-chain attacks undetectable.",
      acceptanceCriteria: [
        "Published artifacts are signed with cosign, GPG, or an equivalent signing mechanism.",
        "Build provenance or SBOM is generated and attached to each release.",
        "Consumer-side verification is documented or enforced.",
      ],
      evidence: [{
        id: "cicd-scan",
        detector: "pattern-match",
        location: { path: "." },
        controls: [],
        signals: ["publish/deploy/release step found without signing, provenance, or SBOM"],
      }],
    });
  }

  return findings;
}
