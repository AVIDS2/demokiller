import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent } from "./rule-helpers.js";

const EXCLUDE_RE = /(?:^|[\\/])(?:test|tests|spec|specs|__test__|__tests__|fixtures|mocks|__mocks__|example|examples|demo|demos|bench|benchmark|benchmarks|docs|doc|vendor|third_party|node_modules|\.git)(?:[\\/]|$)/i;

const REPORT_UTIL_RE = /(?:src[/\\]report[/\\]|src[/\\]rules[/\\]|src[/\\]taint-analysis|src[/\\]source-inspector)/;

const DETECTION_UTIL_RE = /(?:source-inspector|call-graph|python-call-graph|rule-helpers|taint-analysis|inventory|project-kind|walkSourceFiles|detectMcp|detectUnsafe)/;

function evidence(hits: Map<string, string[]>, ruleId: string) {
  return [...hits.entries()].map(([file, signals]) => ({
    id: `${ruleId}-${file}`,
    detector: "pattern-match",
    location: { path: file },
    controls: [],
    signals
  }));
}

function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  const len = s.length;
  for (const count of freq.values()) {
    const p = count / len;
    h -= p * Math.log2(p);
  }
  return h;
}

export async function swiftFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  const files = await walkSourceFiles(root, [".swift"]);
  if (files.length === 0) return [];

  const fileContents = new Map<string, string>();
  for (const file of files) {
    if (EXCLUDE_RE.test(file)) continue;
    if (REPORT_UTIL_RE.test(file)) continue;
    if (DETECTION_UTIL_RE.test(file)) continue;
    fileContents.set(file, await readFileContent(root, file));
  }

  // DK-SW-001: Force unwrap (!) — excessive force unwraps per file
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const lines = content.split(/\r?\n/);
      let forceUnwrapCount = 0;
      const examples: string[] = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (/^\s*\/\//.test(line)) continue;
        // Match force unwrap: identifier! but not !=, !=, !in, !is, or type declarations
        const forceUnwraps = line.match(/\w+!(?:\s|[.,;\)\]\}]|$)/g) ?? [];
        // Also match optional chaining force: someVar!.method
        const forceUnwrapCall = line.match(/\w+!\./g) ?? [];
        const total = forceUnwraps.length + forceUnwrapCall.length;
        forceUnwrapCount += total;
        if (total > 0 && examples.length < 3) {
          examples.push(`line ${i + 1}: ${line.trim().slice(0, 80)}`);
        }
      }
      if (forceUnwrapCount > 3) {
        hits.set(file, [`${forceUnwrapCount} force unwraps (!) in file`, ...examples]);
      }
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-001",
        title: "Excessive force unwrap: more than 3 force unwraps (!) per file",
        severity: "high",
        confidence: "medium",
        missingControls: ["nullSafety"],
        consequence: "Force unwraps (!) crash the app at runtime if the value is nil. Excessive force unwraps indicate fragile code that will crash on unexpected nil values, especially with user-generated data or network responses.",
        acceptanceCriteria: [
          "Use optional binding (if let, guard let) instead of force unwrap.",
          "Use nil-coalescing operator (??) with a safe default value.",
          "Use optional chaining (?.) for chained access to optional properties.",
        ],
        evidence: evidence(hits, "sw-001"),
      });
    }
  }

  // DK-SW-002: Password/token stored in UserDefaults instead of Keychain
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // UserDefaults.set for sensitive keys
      const udSensitive = /UserDefaults\s*(?:\.standard)?\s*\.\s*set\s*\([^)]*(?:password|token|secret|key|credential|auth|session|pin|biometric)/gi;
      for (const m of content.matchAll(udSensitive)) {
        matches.push(`${m[0].trim().slice(0, 60)} — sensitive data stored in UserDefaults`);
      }
      // @AppStorage for sensitive data
      const appStorageSensitive = /@AppStorage\s*\(\s*["'][^"']*(?:password|token|secret|key|credential|auth|session|pin)[^"']*["']\s*\)/gi;
      for (const m of content.matchAll(appStorageSensitive)) {
        matches.push(`${m[0].trim().slice(0, 60)} — sensitive data stored via @AppStorage`);
      }
      // Check if Keychain is used as mitigation
      if (matches.length > 0 && /Keychain|SecItem|kSecClass/.test(content)) {
        matches.length = 0; // Has Keychain usage, likely secure
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-002",
        title: "Sensitive data in UserDefaults: passwords/tokens not stored in Keychain",
        severity: "high",
        confidence: "medium",
        missingControls: ["secureStorage"],
        consequence: "UserDefaults stores data in an unencrypted plist file that is accessible via device backup or jailbreak. Passwords and tokens stored in UserDefaults can be extracted by anyone with physical access to the device.",
        acceptanceCriteria: [
          "Use the iOS Keychain (Security framework) to store passwords, tokens, and credentials.",
          "Use SecItemAdd/SecItemCopyMatching with kSecClassGenericPassword.",
          "Never store sensitive data in UserDefaults or @AppStorage.",
        ],
        evidence: evidence(hits, "sw-002"),
      });
    }
  }

  // DK-SW-003: Insecure URL loading — http:// instead of https://
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // http:// URLs in URL constructors or string literals
      const httpUrls = content.match(/["']http:\/\/[^"']+["']/g) ?? [];
      for (const url of httpUrls) {
        // Skip localhost and 127.0.0.1
        if (/localhost|127\.0\.0\.1|0\.0\.0\.0/.test(url)) continue;
        matches.push(`${url.slice(0, 60)} — insecure HTTP URL`);
      }
      // URL(string: "http://...")
      const urlInit = /URL\s*\(\s*string:\s*["']http:\/\//g;
      for (const m of content.matchAll(urlInit)) {
        if (/localhost|127\.0\.0\.1/.test(m[0])) continue;
        matches.push(`${m[0].trim().slice(0, 60)} — URL initialized with HTTP`);
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-003",
        title: "Insecure URL loading: HTTP URLs instead of HTTPS",
        severity: "high",
        confidence: "medium",
        missingControls: ["httpsEnforcement"],
        consequence: "Loading URLs over HTTP allows man-in-the-middle attacks to intercept and modify data in transit. Credentials, API tokens, and sensitive user data sent over HTTP can be intercepted by network attackers.",
        acceptanceCriteria: [
          "Use HTTPS for all URLs: URL(string: \"https://...\").",
          "Add NSAppTransportSecurity to Info.plist with NSAllowsArbitraryLoads = NO.",
          "If HTTP is required for development, use exception domains with specific hosts.",
        ],
        evidence: evidence(hits, "sw-003"),
      });
    }
  }

  // DK-SW-004: App Transport Security disabled
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      if (!/Info\.plist/.test(file) && !/NSAppTransportSecurity/.test(content)) continue;
      const matches: string[] = [];
      // NSAllowsArbitraryLoads = true in Info.plist
      if (/NSAllowsArbitraryLoads\s*(?:<\/key>|>\s*<true)/.test(content)) {
        matches.push("NSAllowsArbitraryLoads = YES — all HTTP connections allowed");
      }
      // Also check in Swift code
      if (/NSAllowsArbitraryLoads/.test(content) && !/Info\.plist/.test(file)) {
        matches.push("NSAllowsArbitraryLoads referenced in code — ATS may be disabled");
      }
      if (matches.length > 0) hits.set(file, matches);
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-004",
        title: "App Transport Security disabled: NSAllowsArbitraryLoads = YES",
        severity: "high",
        confidence: "high",
        missingControls: ["appTransportSecurity"],
        consequence: "Disabling App Transport Security allows all HTTP connections without TLS, making the app vulnerable to man-in-the-middle attacks. Apple may reject the app from the App Store without a valid justification.",
        acceptanceCriteria: [
          "Remove NSAllowsArbitraryLoads or set it to NO in Info.plist.",
          "Use exception domains for specific hosts that require HTTP.",
          "Ensure all API endpoints use HTTPS with valid TLS certificates.",
        ],
        evidence: evidence(hits, "sw-004"),
      });
    }
  }

  // DK-SW-005: Hardcoded secret
  {
    const hits = new Map<string, string[]>();
    const secretAssignRe = /\b(?:let|var)\s+\w*(?:token|secret|password|apikey|api_key|apiKey|passwd|credential|auth_key|authKey)\w*\s*(?::\s*\w+\s*)?=\s*"([^"]{16,})"/gi;
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      for (const m of content.matchAll(secretAssignRe)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`high-entropy secret (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      // Also check for hardcoded API keys
      const apiKeyAssign = /\b(?:let|var)\s+\w*apiKey\w*\s*(?::\s*\w+\s*)?=\s*"([A-Za-z0-9+/=_\-]{20,})"/gi;
      for (const m of content.matchAll(apiKeyAssign)) {
        const val = m[1];
        if (val && shannonEntropy(val) > 4.5 && !/example|placeholder|test|dummy|xxx|changeme/i.test(val)) {
          matches.push(`hardcoded API key (len=${val.length}, entropy=${shannonEntropy(val).toFixed(1)})`);
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 5));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-005",
        title: "Hardcoded secret: high-entropy string in secret-named variable",
        severity: "blocker",
        confidence: "medium",
        missingControls: ["secretManagement"],
        consequence: "Hardcoded secrets in Swift source code are trivially extracted from the compiled binary using strings or reverse engineering tools. This leads to credential compromise and unauthorized API access.",
        acceptanceCriteria: [
          "Load secrets from environment variables or a secure configuration service.",
          "Use the iOS Keychain for storing API keys and tokens at rest.",
          "Never commit secrets to source control — use .gitignore and secret scanning.",
        ],
        evidence: evidence(hits, "sw-005"),
      });
    }
  }

  // DK-SW-006: Missing input validation — URL parameters used without validation
  {
    const hits = new Map<string, string[]>();
    for (const [file, content] of fileContents) {
      const matches: string[] = [];
      // URL query parameters accessed without validation
      const urlComponents = /URLComponents\s*\(|\.queryItems|\.query\b/g;
      const urlCompMatches = content.match(urlComponents) ?? [];
      if (urlCompMatches.length > 0) {
        // Check if values are validated
        if (!/guard\s+let|if\s+let.*valid|isEmpty|contains|range|whitelist|allowed/i.test(content)) {
          matches.push("URL query parameters accessed without validation (guard let, isEmpty, etc.)");
        }
      }
      // Deep link / URL scheme handling without validation
      if (/openURL|open\s*\(\s*url|handleOpenURL|scene.*openURL/.test(content)) {
        if (!/guard|validate|allowed|whitelist|scheme.*==/i.test(content)) {
          matches.push("URL opened without validation of scheme or host");
        }
      }
      if (matches.length > 0) hits.set(file, matches.slice(0, 3));
    }
    if (hits.size > 0) {
      findings.push({
        ruleId: "DK-SW-006",
        title: "Missing input validation: URL parameters or deep links without validation",
        severity: "medium",
        confidence: "low",
        missingControls: ["inputValidation"],
        consequence: "Processing URL parameters or deep links without validation allows attackers to inject unexpected values, trigger unintended actions, or exploit URL scheme vulnerabilities.",
        acceptanceCriteria: [
          "Validate all URL parameters with guard let and type checking before use.",
          "Whitelist allowed URL schemes and hosts for deep link handling.",
          "Sanitize and validate user input from URL query parameters before displaying or processing.",
        ],
        evidence: evidence(hits, "sw-006"),
      });
    }
  }

  return findings;
}
