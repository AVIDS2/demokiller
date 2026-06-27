import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function iotEmbeddedFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "iot-embedded") return [];
  const files = await walkSourceFiles(root, [".c",".cpp",".h",".hpp",".ino",".py",".ts",".js"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-IOT-001 (blocker,high): Hardcoded credentials
  // Check password/api_key/token/secret/wifi_pass with hardcoded string values (NOT ssid — it is publicly broadcast)
  const credentialPattern = /(password|api_key|token|secret|wifi_pass)\s*=\s*["'][^"']+["']/gi;
  const credentialFiles = new Map<string, string[]>();
  for (const file of files) {
    const content = await readFileContent(root, file);
    const matches = content.match(credentialPattern);
    if (matches) {
      credentialFiles.set(file, matches);
    }
  }
  if (credentialFiles.size > 0) {
    findings.push({
      ruleId: "DK-IOT-001",
      title: "Hardcoded credentials detected in source code",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["Credential rotation mechanism", "Secure key storage (e.g., NVS, TPM, secure enclave)", "Environment-variable or compile-time injection"],
      consequence: "Credentials exposed in version control or firmware binary can be extracted by attackers, leading to unauthorized device access or network compromise.",
      acceptanceCriteria: [
        "No plaintext credentials in source code",
        "Credentials loaded from secure storage or environment at runtime",
        "Default/placeholder values documented as non-production"
      ],
      evidence: [...credentialFiles.entries()].map(([file, signals]) => ({
        id: `iot-001-${file}`,
        detector: "pattern-match",
        location: { path: file },
        controls: [],
        signals
      }))
    });
  }

  // DK-IOT-002 (high,medium): Insecure transport
  // Check http:// URLs (not https://) — exclude localhost and 127.0.0.1
  const insecureUrlPattern = /["']http:\/\/(?!localhost|127\.0\.0\.1)[^"']+["']/gi;
  const insecureUrlFiles = new Map<string, string[]>();
  for (const file of files) {
    const content = await readFileContent(root, file);
    const matches = content.match(insecureUrlPattern);
    if (matches) {
      insecureUrlFiles.set(file, matches);
    }
  }
  if (insecureUrlFiles.size > 0) {
    findings.push({
      ruleId: "DK-IOT-002",
      title: "Insecure transport - HTTP used instead of HTTPS",
      severity: "high",
      confidence: "medium",
      missingControls: ["TLS/HTTPS for all network communications", "Certificate validation", "Secure transport layer"],
      consequence: "Data transmitted over HTTP can be intercepted, modified, or replayed by attackers on the network (MITM attacks).",
      acceptanceCriteria: [
        "All API/server URLs use https:// protocol",
        "Certificate pinning implemented where feasible",
        "HTTP fallback disabled or restricted to local-only endpoints"
      ],
      evidence: [...insecureUrlFiles.entries()].map(([file, signals]) => ({
        id: `iot-002-${file}`,
        detector: "pattern-match",
        location: { path: file },
        controls: [],
        signals
      }))
    });
  }

  // DK-IOT-003 (high,medium): No secure boot / firmware signing
  // Check OTA/firmware operations without sign/verify/hash/checksum/signature
  const otaPattern = /(ota[_-]?update|firmware[_-]?(?:update|upload|download)|OTA\s+FOTA)\b/i;
  const signingPattern = /(sign|verify|hash|checksum|signature|digest)/i;
  const otaFiles = new Map<string, string[]>();
  for (const file of files) {
    const content = await readFileContent(root, file);
    const otaMatches = content.match(otaPattern);
    if (otaMatches && !signingPattern.test(content)) {
      otaFiles.set(file, [otaMatches[0]]);
    }
  }
  if (otaFiles.size > 0) {
    findings.push({
      ruleId: "DK-IOT-003",
      title: "OTA/firmware update without signing or verification",
      severity: "high",
      confidence: "medium",
      missingControls: ["Firmware signature verification", "Secure boot chain", "Update integrity checks (hash/checksum)"],
      consequence: "Unsigned firmware updates can be replaced by malicious payloads, allowing complete device takeover.",
      acceptanceCriteria: [
        "Firmware images signed with a verified key before deployment",
        "Device verifies signature before applying updates",
        "Secure boot chain prevents execution of unsigned code"
      ],
      evidence: [...otaFiles.entries()].map(([file, signals]) => ({
        id: `iot-003-${file}`,
        detector: "pattern-match",
        location: { path: file },
        controls: [],
        signals
      }))
    });
  }

  // DK-IOT-004 (medium,medium): No input bounds checking
  // Check read/scanf/gets/recv without bounds/length/size/limit validation
  const unsafeInputPattern = /(scanf\s*\(\s*%s|gets\s*\(|recv\s*\([^)]+\))/gi;
  const boundsPattern = /(bounds|length|size|limit|max_len|bufsize|sizeof|strncpy|snprintf|fgets)/i;
  const unsafeInputFiles = new Map<string, string[]>();
  for (const file of files) {
    const content = await readFileContent(root, file);
    const unsafeMatches = content.match(unsafeInputPattern);
    if (unsafeMatches && !boundsPattern.test(content)) {
      unsafeInputFiles.set(file, unsafeMatches);
    }
  }
  if (unsafeInputFiles.size > 0) {
    findings.push({
      ruleId: "DK-IOT-004",
      title: "Unsafe input operations without bounds checking",
      severity: "medium",
      confidence: "medium",
      missingControls: ["Buffer size limits on input operations", "Safe input functions (fgets, strncpy, snprintf)", "Input validation and sanitization"],
      consequence: "Unbounded input operations can cause buffer overflows, leading to crashes, data corruption, or remote code execution on the device.",
      acceptanceCriteria: [
        "All input operations use bounded variants (fgets instead of gets, snprintf instead of sprintf)",
        "Buffer sizes validated before use",
        "Input length checked against maximum expected values"
      ],
      evidence: [...unsafeInputFiles.entries()].map(([file, signals]) => ({
        id: `iot-004-${file}`,
        detector: "pattern-match",
        location: { path: file },
        controls: [],
        signals
      }))
    });
  }

  return findings;
}
