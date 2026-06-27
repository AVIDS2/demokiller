import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { promises as fs } from "node:fs";
import path from "node:path";

// ─── File scanner ──────────────────────────────────────────────

const SKIP_DIRS = new Set([
  "node_modules", ".next", "dist", "build", "target", "__pycache__",
  ".venv", "venv", "vendor", ".git", "out", "bin", "obj",
]);

const MOBILE_EXTS = [
  ".ts", ".tsx", ".js", ".jsx", ".mts", ".mjs",
  ".dart", ".swift", ".kt", ".kts", ".java", ".m", ".mm",
];

async function walkSourceFiles(root: string, dir = root): Promise<string[]> {
  const entries = await fs.readdir(dir, { withFileTypes: true });
  const result: string[] = [];

  for (const entry of entries) {
    if (SKIP_DIRS.has(entry.name)) continue;
    const fullPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      result.push(...(await walkSourceFiles(root, fullPath)));
    } else {
      const rel = path.relative(root, fullPath).replaceAll("\\", "/");
      if (MOBILE_EXTS.some((ext) => rel.endsWith(ext))) {
        result.push(rel);
      }
    }
  }
  return result;
}

async function readFile(root: string, relPath: string): Promise<string> {
  try {
    return await fs.readFile(path.join(root, relPath), "utf8");
  } catch {
    return "";
  }
}

// ─── Mobile app type detection ────────────────────────────────

function isMobileProject(inventory: ProjectInventory): boolean {
  if (inventory.projectKind === "mobile-app") return true;
  const deps = { ...inventory.packageJson.dependencies, ...inventory.packageJson.devDependencies };
  return Object.keys(deps).some((d) =>
    d === "react-native" || d === "@capacitor/core" || d === "@capacitor/cli" ||
    d.includes("react-native")
  );
}

// ─── DK-MOB-001: Insecure local data storage ─────────────────

const INSECURE_STORAGE_PATTERNS = [
  // AsyncStorage usage (React Native)
  /AsyncStorage\s*\.\s*(setItem|mergeItem)\s*\(/,
  /@react-native-async-storage\/async-storage/,
  // SharedPreferences without Encrypted prefix
  /SharedPreferences\b(?!Encrypted)/,
  /getSharedPreferences\s*\(/,
  // NSUserDefaults for sensitive data
  /NSUserDefaults\s+(standardUserDefaults|defaults)\b/,
  // Flutter SharedPreferences for tokens/secrets
  /SharedPreferences\.getInstance\s*\(/,
];

const SENSITIVE_DATA_PATTERNS = [
  /token/i, /secret/i, /password/i, /credential/i, /auth/i, /key/i, /session/i, /jwt/i,
];

const SECURE_STORAGE_INDICATORS = [
  /react-native-keychain/,
  /flutter_secure_storage/,
  /EncryptedSharedPreferences/,
  /Keychain\b/,
  /AndroidKeystore/,
  /SecAccessControl/,
  /kSecAttrAccessible/,
  /KeychainItemWrapper/,
];

async function checkInsecureStorage(root: string, files: string[]): Promise<Finding[]> {
  const evidence: Finding["evidence"] = [];
  let hasSecureStorage = false;

  for (const file of files) {
    const content = await readFile(root, file);
    if (!content) continue;

    // Check if project uses secure storage (sanitizer)
    for (const pattern of SECURE_STORAGE_INDICATORS) {
      if (pattern.test(content)) {
        hasSecureStorage = true;
        break;
      }
    }

    // Check for insecure storage with sensitive data
    for (const storagePattern of INSECURE_STORAGE_PATTERNS) {
      const matches = content.match(storagePattern);
      if (!matches) continue;

      // Check if nearby code involves sensitive data
      const hasSensitiveContext = SENSITIVE_DATA_PATTERNS.some((p) => p.test(content));
      if (!hasSensitiveContext) continue;

      // Find line number
      const lines = content.split("\n");
      const lineNum = lines.findIndex((l) => storagePattern.test(l)) + 1;

      evidence.push({
        id: `storage-${evidence.length}`,
        detector: "mobile-storage-check",
        location: { path: file, line: lineNum || undefined },
        controls: hasSecureStorage ? ["secureStorage"] : [],
        signals: [`Insecure storage: ${matches[0].trim()}`],
      });
    }
  }

  if (evidence.length === 0) return [];

  return [
    {
      ruleId: "DK-MOB-001",
      title: "Sensitive data stored in insecure local storage",
      severity: "blocker",
      confidence: hasSecureStorage ? "medium" : "high",
      missingControls: ["encryptedLocalStorage"],
      consequence:
        "Sensitive data (tokens, credentials, session data) stored in plain-text local storage can be extracted through device backup, rooted/jailbroken devices, or physical access. AsyncStorage, SharedPreferences, and NSUserDefaults are not encrypted by default.",
      acceptanceCriteria: [
        "Sensitive data is stored in platform secure storage (Keychain, Android Keystore, flutter_secure_storage, react-native-keychain).",
        "Plain-text AsyncStorage/SharedPreferences is not used for tokens, secrets, or credentials.",
        "Data at rest is encrypted with platform-provided encryption APIs.",
      ],
      evidence,
    },
  ];
}

// ─── DK-MOB-002: Deep link / URL scheme validation missing ───

const DEEP_LINK_PATTERNS = [
  /Linking\s*\.\s*addEventListener/,
  /Linking\s*\.\s*(getInitialURL|openURL|canOpenURL)/,
  /useURL\s*\(/,
  /useDeepLinking/,
  /DeepLinking/,
  /<Linking\s/,
  /app\.links?\./i,
  /universalLinks?/i,
  /url\s*scheme/i,
  /<intent-filter>/,
  /<data\s+android:scheme/,
];

const URL_VALIDATION_PATTERNS = [
  /validate.*[Uu][Rr][Ll]/,
  /sanitize.*[Uu][Rr][Ll]/,
  /allowlist/,
  /whitelist/,
  /allowedRoutes|allowedPaths|validRoutes/,
  /parse.*[Uu][Rr][Ll].*valid/,
  /\.startsWith\s*\(\s*['"]https?:/,
  /new\s+URL\s*\(/,
];

async function checkDeepLinkValidation(root: string, files: string[]): Promise<Finding[]> {
  const evidence: Finding["evidence"] = [];
  let hasValidation = false;

  for (const file of files) {
    const content = await readFile(root, file);
    if (!content) continue;

    // Check for validation patterns (sanitizer)
    for (const pattern of URL_VALIDATION_PATTERNS) {
      if (pattern.test(content)) {
        hasValidation = true;
        break;
      }
    }

    // Check for deep link handling without validation
    for (const pattern of DEEP_LINK_PATTERNS) {
      const matches = content.match(pattern);
      if (!matches) continue;

      // Only flag if validation is missing in this file
      const fileHasValidation = URL_VALIDATION_PATTERNS.some((p) => p.test(content));
      if (fileHasValidation) continue;

      const lines = content.split("\n");
      const lineNum = lines.findIndex((l) => pattern.test(l)) + 1;

      evidence.push({
        id: `deeplink-${evidence.length}`,
        detector: "mobile-deeplink-check",
        location: { path: file, line: lineNum || undefined },
        controls: [],
        signals: [`Deep link handling: ${matches[0].trim()}`],
      });
    }
  }

  if (evidence.length === 0) return [];

  return [
    {
      ruleId: "DK-MOB-002",
      title: "Deep link / URL scheme handling without input validation",
      severity: "high",
      confidence: hasValidation ? "medium" : "high",
      missingControls: ["deepLinkValidation"],
      consequence:
        "Unvalidated deep links can be exploited for phishing, unauthorized navigation, or injection attacks. Malicious apps can craft URL schemes to redirect users to attacker-controlled content or trigger unintended actions.",
      acceptanceCriteria: [
        "Deep link parameters are validated against an allowlist of accepted paths.",
        "URL scheme parameters are sanitized before use in navigation or data operations.",
        "Parameterized routing is used instead of direct URL-to-action mapping.",
      ],
      evidence,
    },
  ];
}

// ─── DK-MOB-003: Network security config missing ─────────────

const HTTP_URL_PATTERN = /(?:=|:)\s*['"`](http:\/\/[^'"`\s]+)['"`]/g;
const HTTPS_ENFORCEMENT = [
  /https:\/\//i,
  /App Transport Security/i,
  /NSAppTransportSecurity/,
  /network_security_config/,
  /cleartextTrafficPermitted\s*=\s*false/i,
];

const CERT_PINNING_PATTERNS = [
  /ssl.?pin/i,
  /certificate.?pin/i,
  /trust.?manager/i,
  /ServerTrustPolicy/,
  /SSLPinning/,
  /CertificatePinner/,
  /OkHttp.*CertificatePinner/,
  /TSPublicKeyHash/,
  /pin-set/,
];

async function checkNetworkSecurity(root: string, files: string[]): Promise<Finding[]> {
  const evidence: Finding["evidence"] = [];
  let hasCertPinning = false;
  let hasHttpsEnforcement = false;

  // Check AndroidManifest.xml and Info.plist separately
  for (const manifestFile of ["android/app/src/main/AndroidManifest.xml", "android/app/src/debug/AndroidManifest.xml"]) {
    const content = await readFile(root, manifestFile);
    if (content.includes("usesCleartextTraffic")) {
      if (content.includes('android:usesCleartextTraffic="true"')) {
        evidence.push({
          id: `manifest-${evidence.length}`,
          detector: "mobile-network-check",
          location: { path: manifestFile },
          controls: [],
          signals: ["Cleartext traffic explicitly allowed in AndroidManifest.xml"],
        });
      }
    }
  }

  for (const file of files) {
    const content = await readFile(root, file);
    if (!content) continue;

    // Check for cert pinning (sanitizer)
    for (const pattern of CERT_PINNING_PATTERNS) {
      if (pattern.test(content)) {
        hasCertPinning = true;
        break;
      }
    }

    // Check for HTTPS enforcement (sanitizer)
    for (const pattern of HTTPS_ENFORCEMENT) {
      if (pattern.test(content)) {
        hasHttpsEnforcement = true;
        break;
      }
    }

    // Check for HTTP URLs (risk)
    let match;
    const httpPattern = /(?:=|:|fetch\(|axios\.\w+\(|request\(|http\.\w+\()\s*['"`](http:\/\/[^'"`\s]+)['"`]/g;
    while ((match = httpPattern.exec(content)) !== null) {
      const url = match[1];
      // Skip localhost / 127.0.0.1 for dev
      if (/localhost|127\.0\.0\.1|10\.0\.\d+\.\d+/.test(url)) continue;

      const lineNum = content.substring(0, match.index).split("\n").length;
      evidence.push({
        id: `http-url-${evidence.length}`,
        detector: "mobile-network-check",
        location: { path: file, line: lineNum },
        controls: hasHttpsEnforcement ? ["httpsEnforcement"] : [],
        signals: [`HTTP URL: ${url}`],
      });
    }
  }

  if (evidence.length === 0) return [];

  return [
    {
      ruleId: "DK-MOB-003",
      title: "Network security configuration issues detected",
      severity: "high",
      confidence: hasCertPinning || hasHttpsEnforcement ? "medium" : "high",
      missingControls: ["networkSecurityConfig"],
      consequence:
        "Using HTTP URLs or lacking certificate pinning makes the app vulnerable to man-in-the-middle attacks. Attackers on the same network can intercept, modify, or replay API requests, exposing user data and authentication tokens.",
      acceptanceCriteria: [
        "All API calls use HTTPS, not plain HTTP.",
        "Certificate pinning is implemented for sensitive endpoints.",
        "Cleartext traffic is disabled in network_security_config.xml.",
      ],
      evidence,
    },
  ];
}

// ─── DK-MOB-004: Excessive permissions requested ─────────────

const DANGEROUS_PERMISSIONS = [
  { permission: "CAMERA", usage: /\b(camera|Camera|takePicture|CameraRoll)\b/ },
  { permission: "LOCATION", usage: /\b(geolocation|Geolocation|location|Location|getCurrentPosition|watchPosition)\b/ },
  { permission: "CONTACTS", usage: /\b(contacts|Contacts|addressBook|getContacts)\b/ },
  { permission: "RECORD_AUDIO", usage: /\b(microphone|audio|AudioRecorder|record|Voice)\b/ },
  { permission: "READ_EXTERNAL_STORAGE", usage: /\b(readFile|FileSystem|storage|gallery|CameraRoll)\b/ },
  { permission: "WRITE_EXTERNAL_STORAGE", usage: /\b(writeFile|FileSystem|saveFile|download)\b/ },
];

async function checkExcessivePermissions(root: string, files: string[]): Promise<Finding[]> {
  const evidence: Finding["evidence"] = [];
  const requestedPermissions: string[] = [];

  // Check AndroidManifest.xml for declared permissions
  for (const manifestFile of [
    "android/app/src/main/AndroidManifest.xml",
    "app/src/main/AndroidManifest.xml",
  ]) {
    const content = await readFile(root, manifestFile);
    if (!content) continue;

    for (const { permission } of DANGEROUS_PERMISSIONS) {
      const permPattern = new RegExp(`android\\.permission\\.${permission}`, "i");
      if (permPattern.test(content)) {
        requestedPermissions.push(permission);
      }
    }
  }

  // Check Info.plist for iOS usage descriptions
  for (const plistFile of ["ios/*/Info.plist", "ios/Info.plist"]) {
    // We check directly known plist locations
  }
  const plistPaths = [
    "ios/DemoKiller/Info.plist",
    "ios/App/App/Info.plist",
    "ios/Runner/Info.plist",
  ];
  for (const plistPath of plistPaths) {
    const content = await readFile(root, plistPath);
    if (!content) continue;
    const usageDescs = content.match(/NS\w+UsageDescription/g) ?? [];
    for (const desc of usageDescs) {
      const permName = desc.replace("NS", "").replace("UsageDescription", "").toUpperCase();
      if (!requestedPermissions.includes(permName)) {
        requestedPermissions.push(permName);
      }
    }
  }

  // Now collect all source file content to check for actual usage
  const allContent: string[] = [];
  for (const file of files) {
    const content = await readFile(root, file);
    if (content) allContent.push(content);
  }
  const combinedSource = allContent.join("\n");

  // Check each requested permission for actual usage in code
  for (const perm of requestedPermissions) {
    const entry = DANGEROUS_PERMISSIONS.find((p) => p.permission === perm);
    if (!entry) continue;

    const hasUsage = entry.usage.test(combinedSource);
    if (!hasUsage) {
      evidence.push({
        id: `perm-${evidence.length}`,
        detector: "mobile-permission-check",
        location: { path: "AndroidManifest.xml" },
        controls: [],
        signals: [`Permission ${perm} requested but no corresponding usage found in source code`],
      });
    }
  }

  if (evidence.length === 0) return [];

  return [
    {
      ruleId: "DK-MOB-004",
      title: "Excessive or unused permissions requested",
      severity: "medium",
      confidence: "medium",
      missingControls: ["permissionMinimization"],
      consequence:
        "Requesting permissions without corresponding code usage raises app store review flags, reduces user trust, and violates the principle of least privilege. Unused permissions expand the attack surface if the app is compromised.",
      acceptanceCriteria: [
        "Only permissions with corresponding feature usage in source code are declared.",
        "Runtime permission requests are implemented for dangerous permissions.",
        "Permission rationale is shown to the user before requesting access.",
      ],
      evidence,
    },
  ];
}

// ─── Main export ───────────────────────────────────────────────

export async function mobileAppFindings(
  root: string,
  inventory: ProjectInventory,
): Promise<Finding[]> {
  if (!isMobileProject(inventory)) return [];

  const files = await walkSourceFiles(root);

  const results: Finding[] = [];

  results.push(...(await checkInsecureStorage(root, files)));
  results.push(...(await checkDeepLinkValidation(root, files)));
  results.push(...(await checkNetworkSecurity(root, files)));
  results.push(...(await checkExcessivePermissions(root, files)));

  return results;
}
