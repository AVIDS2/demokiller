import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function mlPipelineFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "ml-pipeline") return [];
  const files = await walkSourceFiles(root, [".py",".ipynb"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-ML-001: Unvalidated data ingestion
  const dataIngestionPattern = /(?:read_csv|load_data|DataLoader)\s*\(/g;
  const validationPattern = /(?:validat|sanitiz|schema.*check)/i;
  if (safeTest(dataIngestionPattern, allContent) && !validationPattern.test(allContent)) {
    for (const file of files) {
      const content = await readFileContent(root, file);
      if (safeTest(dataIngestionPattern, content)) {
        findings.push({
          ruleId: "DK-ML-001",
          title: "Unvalidated data ingestion",
          severity: "high",
          confidence: "medium",
          missingControls: ["Data validation on ingestion", "Schema enforcement", "Input sanitization"],
          consequence: "Training on malformed or adversarial data can degrade model performance and introduce silent biases.",
          acceptanceCriteria: [
            "All data ingestion points must validate incoming data against a schema.",
            "Data quality checks must run before training begins."
          ],
          evidence: [{
            id: "DK-ML-001-ev1",
            detector: "pattern-match",
            location: { path: file },
            controls: [],
            signals: ["read_csv/load_data/DataLoader found without validation pattern"]
          }]
        });
      }
    }
  }

  // DK-ML-002: Unsafe model deserialization
  const unsafeDeserPattern = /(?:pickle\.load|torch\.load|joblib\.load|load_model)\s*\(/g;
  const deserFilenamePattern = /(?:^|\s|\/)(?:[\w.-]+\.(?:pkl|h5|pt))\b/m;
  const safeLoadPattern = /(?:safe_load|verify.*hash|torch\.load.*map_location|RestrictedUnpickler)/i;
  for (const file of files) {
    const content = await readFileContent(root, file);
    const hasUnsafeDeser = safeTest(unsafeDeserPattern, content) || deserFilenamePattern.test(content);
    const hasSafeLoader = /torch\.load.*map_location|safe_load|RestrictedUnpickler/i.test(content);
    if (hasUnsafeDeser && !hasSafeLoader) {
      findings.push({
        ruleId: "DK-ML-002",
        title: "Unsafe model deserialization",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["Safe deserialization", "Model integrity verification", "Hash verification"],
        consequence: "Deserializing untrusted model files with pickle/torch.load can lead to arbitrary code execution.",
        acceptanceCriteria: [
          "Model files must be loaded using safe deserialization methods.",
          "Model integrity must be verified via checksum/hash before loading."
        ],
        evidence: [{
          id: "DK-ML-002-ev1",
          detector: "pattern-match",
          location: { path: file },
          controls: [],
          signals: ["pickle.load/torch.load/joblib.load found without safe_load or hash verification"]
        }]
      });
    }
  }

  // DK-ML-003: No experiment tracking
  const trainingPattern = /\.(?:model|fit)\s*\(/g;
  const trackingPattern = /(?:mlflow|wandb|tensorboard|experiment|version.*model)/i;
  if (safeTest(trainingPattern, allContent) && !trackingPattern.test(allContent)) {
    for (const file of files) {
      const content = await readFileContent(root, file);
      if (safeTest(trainingPattern, content)) {
        findings.push({
          ruleId: "DK-ML-003",
          title: "No experiment tracking",
          severity: "medium",
          confidence: "medium",
          missingControls: ["Experiment tracking", "Model versioning", "Training metrics logging"],
          consequence: "Without experiment tracking, it is impossible to reproduce results or compare model versions.",
          acceptanceCriteria: [
            "Training runs must be tracked with an experiment tracking tool (MLflow, W&B, TensorBoard, etc.).",
            "Model artifacts must be versioned and stored in a model registry."
          ],
          evidence: [{
            id: "DK-ML-003-ev1",
            detector: "pattern-match",
            location: { path: file },
            controls: [],
            signals: [".model/.fit found without experiment tracking framework"]
          }]
        });
      }
    }
  }

  // DK-ML-004: Hardcoded credentials
  const hardcodedCredPattern = /(?:api_key|secret|password|token)\s*=\s*["'][^"']+["']/gi;
  const credMatches = allContent.match(hardcodedCredPattern);
  if (credMatches && credMatches.length > 0) {
    for (const file of files) {
      const content = await readFileContent(root, file);
      const fileMatches = content.match(hardcodedCredPattern);
      if (fileMatches && fileMatches.length > 0) {
        findings.push({
          ruleId: "DK-ML-004",
          title: "Hardcoded credentials in ML pipeline code",
          severity: "high",
          confidence: "medium",
          missingControls: ["Secrets management", "Environment variable usage", "Credential rotation"],
          consequence: "Hardcoded secrets in source code can be leaked through version control, leading to unauthorized access.",
          acceptanceCriteria: [
            "Secrets must be loaded from environment variables or a secrets manager.",
            "No credentials or API keys must appear in source code."
          ],
          evidence: [{
            id: "DK-ML-004-ev1",
            detector: "pattern-match",
            location: { path: file },
            controls: [],
            signals: [`Found ${fileMatches.length} hardcoded credential(s): ${fileMatches.map(m => m.split("=")[0].trim()).join(", ")}`]
          }]
        });
      }
    }
  }

  return findings;
}
