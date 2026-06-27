import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function browserExtensionFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "browser-extension") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx",".json"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-EXT-001: Overly broad permissions without optional_permissions/activeTab
  // Match "tabs" only in manifest permission declarations, not generic code
  const hasBroadPermissions =
    /["<]all_urls[">]/i.test(allContent) ||
    /"permissions"\s*:\s*\[[^\]]*"tabs"/.test(allContent) ||
    /\bwebRequest\b/.test(allContent) ||
    /\bdebugger\b/.test(allContent);

  const hasPermissionMitigation =
    /\boptional_permissions\b/i.test(allContent) ||
    /\boptionalPermissions\b/i.test(allContent) ||
    /\bactiveTab\b/i.test(allContent);

  if (hasBroadPermissions && !hasPermissionMitigation) {
    findings.push({
      ruleId: "DK-EXT-001",
      title: "Overly broad permissions declared without optional_permissions or activeTab",
      severity: "high",
      confidence: "medium",
      missingControls: ["optionalPermissions", "activeTab"],
      consequence: "The extension requests broad host permissions (<all_urls>, tabs, webRequest, debugger) at install time with no option for the user to grant them on-demand. This violates the principle of least privilege, triggers stricter Chrome Web Store review, increases the attack surface if the extension is compromised, and deters security-conscious users from installing.",
      acceptanceCriteria: [
        "Broad host permissions are moved to optional_permissions and requested at runtime via chrome.permissions.request.",
        "activeTab is used instead of <all_urls> where the extension only needs access to the active tab.",
        "Sensitive permissions (tabs, webRequest, debugger) are declared as optional and justified in store listing.",
        "The extension degrades gracefully when optional permissions are not granted.",
      ],
      evidence: [{ id: "ext-scan", detector: "project-scan", location: { path: "." }, controls: [], signals: ["broad permissions detected without optional_permissions or activeTab"] }],
    });
  }

  // DK-EXT-002: Content script injection without CSP/sandbox
  const hasContentScripts =
    /\bcontent_scripts\b/i.test(allContent) ||
    /\bcontentScripts\b/i.test(allContent) ||
    /\binject\b.*\bjs\b|\bjs\b.*\binject\b/i.test(allContent) ||
    /chrome\.scripting\.executeScript/i.test(allContent);

  const hasCSP =
    /\bcontent_security_policy\b/i.test(allContent) ||
    /\bcontentSecurityPolicy\b/i.test(allContent) ||
    /\bsandbox\b/i.test(allContent) ||
    /\bCSP\b/.test(allContent);

  if (hasContentScripts && !hasCSP) {
    findings.push({
      ruleId: "DK-EXT-002",
      title: "Content script injection without CSP or sandbox policy",
      severity: "high",
      confidence: "medium",
      missingControls: ["contentSecurityPolicy", "sandbox"],
      consequence: "Content scripts injected into web pages without a defined Content Security Policy or sandbox are vulnerable to injection attacks from the host page. If the content script interacts with the DOM and the host page contains malicious content, the extension's privileged context can be exploited to exfiltrate data or perform unauthorized actions on behalf of the user.",
      acceptanceCriteria: [
        "A strict content_security_policy is declared in manifest.json that disallows unsafe-inline and unsafe-eval.",
        "Content scripts run in an isolated world and do not share mutable state with the host page.",
        "The sandbox page is used for any eval-like or dynamic code execution needs.",
        "Content script DOM interactions are sanitized against injection from the host page.",
      ],
      evidence: [{ id: "ext-scan", detector: "project-scan", location: { path: "." }, controls: [], signals: ["content script injection detected without CSP or sandbox declaration"] }],
    });
  }

  // DK-EXT-003: eval/innerHTML/dangerous DOM manipulation
  // Per-file scan: skip lines that are comments (start with // or *)
  const evalSignals: string[] = [];
  const dangerChecks: [RegExp, string][] = [
    [/\beval\s*\(/, "eval() call detected"],
    [/new\s+Function\s*\(/, "new Function() call detected"],
    [/\.innerHTML\s*[=+]/, "innerHTML assignment detected"],
    [/\.outerHTML\s*[=+]/, "outerHTML assignment detected"],
    [/document\.write\s*\(/, "document.write() call detected"],
  ];

  // Scan each file line-by-line, skipping comment lines
  for (const file of files) {
    const content = await readFileContent(root, file);
    const lines = content.split("\n");
    for (const line of lines) {
      const trimmed = line.trimStart();
      // Skip single-line comments and block-comment continuation lines
      if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
      for (const [re, label] of dangerChecks) {
        if (re.test(line) && !evalSignals.includes(label)) {
          evalSignals.push(label);
        }
      }
    }
  }

  if (evalSignals.length > 0) {
    findings.push({
      ruleId: "DK-EXT-003",
      title: "Dangerous code execution or DOM manipulation (eval/innerHTML/document.write)",
      severity: "blocker",
      confidence: "medium",
      missingControls: ["safeDomApi", "sanitization"],
      consequence: "Using eval(), new Function(), innerHTML, outerHTML, or document.write() in a browser extension creates a direct code injection vector. An attacker who can control any input to these calls — whether from the host page, extension storage, or network responses — can execute arbitrary JavaScript in the extension's privileged context, bypassing the web page's origin restrictions and accessing extension APIs, user data, and browser state.",
      acceptanceCriteria: [
        "All eval() and new Function() calls are removed; static analysis or sandboxed alternatives are used instead.",
        "innerHTML assignments are replaced with textContent, createElement, or a sanitization library (e.g., DOMPurify).",
        "document.write() is replaced with DOM manipulation APIs.",
        "All user-controlled or network-sourced data is sanitized before insertion into the DOM.",
      ],
      evidence: evalSignals.map((signal, i) => ({
        id: `ext-eval-${i}`,
        detector: "pattern-scan",
        location: { path: "." },
        controls: [],
        signals: [signal],
      })),
    });
  }

  return findings;
}
