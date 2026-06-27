import type { Finding } from "../types.js";
import type { ProjectInventory } from "../inventory.js";
import { walkSourceFiles, readFileContent, safeTest } from "./rule-helpers.js";

export async function wasmModuleFindings(root: string, inventory: ProjectInventory): Promise<Finding[]> {
  const findings: Finding[] = [];
  if (inventory.projectKind !== "wasm-module") return [];
  const files = await walkSourceFiles(root, [".ts",".tsx",".js",".jsx",".rs",".wat"]);
  if (files.length === 0) return [];
  const allContent = (await Promise.all(files.map(f => readFileContent(root, f)))).join("\n");

  // DK-WASM-001: Memory safety - check unsafe/ptr::read/ptr::write/mem::transmute without bounds check/null check
  // Skip lines that are comments (// or /* or *)
  const unsafeRe = /^\s*(?:\/\/|[*]|\/\*)/ ;
  const unsafeKeywordsRe = /\b(unsafe|ptr::read|ptr::write|mem::transmute)\b/;
  const boundsRe = /\b(bounds.*check|null.*check)\b/gi;
  const boundsMatches = allContent.match(boundsRe);
  if (!boundsMatches || boundsMatches.length === 0) {
    const affectedFiles: string[] = [];
    for (const f of files) {
      const content = await readFileContent(root, f);
      const lines = content.split("\n");
      const hasUnsafe = lines.some(line => !unsafeRe.test(line) && unsafeKeywordsRe.test(line));
      if (hasUnsafe) affectedFiles.push(f);
    }
    for (const f of affectedFiles) {
      findings.push({
        ruleId: "DK-WASM-001",
        title: "Unsafe memory operations without bounds checking",
        severity: "high",
        confidence: "medium",
        missingControls: ["bounds-checking", "null-checking", "memory-safety-validation"],
        consequence: "Out-of-bounds reads/writes or undefined behavior in WASM execution context can cause memory corruption or security vulnerabilities",
        acceptanceCriteria: [
          "All unsafe blocks must include explicit bounds checks",
          "Pointer dereferences must be preceded by null checks",
          "transmute usage must validate source and target type compatibility"
        ],
        evidence: [{
          id: "DK-WASM-001-1",
          detector: "pattern-match",
          location: { path: f },
          controls: [],
          signals: ["unsafe block found without bounds or null checks"]
        }]
      });
    }
  }

  // DK-WASM-002: Input validation - check exported WASM functions without validation
  const exportFnRe = /#\[wasm_bindgen\]\s*(?:pub\s+)?fn|pub\s+fn\s+\w+\s*\([^)]*(?:JsValue|js_sys|wasm_bindgen)[^)]*\)/g;
  const validationRe = /\b(validat|sanitiz|check.*len)\b/gi;
  const exportMatches = allContent.match(exportFnRe);
  const validationMatches = allContent.match(validationRe);
  if (exportMatches && (!validationMatches || validationMatches.length === 0)) {
    const affectedFiles: string[] = [];
    for (const f of files) {
      const content = await readFileContent(root, f);
      if (exportFnRe.test(content)) affectedFiles.push(f);
      exportFnRe.lastIndex = 0;
    }
    for (const f of affectedFiles) {
      findings.push({
        ruleId: "DK-WASM-002",
        title: "Exported WASM function accepts string input without validation",
        severity: "high",
        confidence: "medium",
        missingControls: ["input-validation", "input-sanitization", "length-checking"],
        consequence: "Unvalidated string inputs to exported WASM functions can lead to buffer overflows, injection attacks, or denial of service",
        acceptanceCriteria: [
          "All exported functions must validate input length before processing",
          "String inputs must be sanitized before use in operations",
          "Input bounds must be checked against expected maximum sizes"
        ],
        evidence: [{
          id: "DK-WASM-002-1",
          detector: "pattern-match",
          location: { path: f },
          controls: [],
          signals: ["exported function accepts &str/JsValue/String without validation keywords"]
        }]
      });
    }
  }

  // DK-WASM-003: Panic handling - check unwrap/expect/panic without catch_unwind/set_panic_hook
  // Skip test files entirely
  const nonTestFiles = files.filter(f => !/test|spec/i.test(f));
  const panicRe = /\b(unwrap\(\)|expect\(|panic!)\b/g;
  const catchRe = /\b(catch_unwind|set_panic_hook)\b/g;
  const panicMatches = nonTestFiles.length > 0 ? allContent.match(panicRe) : null;
  const catchMatches = nonTestFiles.length > 0 ? allContent.match(catchRe) : null;
  if (panicMatches && (!catchMatches || catchMatches.length === 0)) {
    const affectedFiles: string[] = [];
    for (const f of nonTestFiles) {
      const content = await readFileContent(root, f);
      if (panicRe.test(content)) affectedFiles.push(f);
      panicRe.lastIndex = 0;
    }
    for (const f of affectedFiles) {
      findings.push({
        ruleId: "DK-WASM-003",
        title: "Uncaught panics in WASM module",
        severity: "medium",
        confidence: "medium",
        missingControls: ["panic-hook", "catch-unwind", "error-propagation"],
        consequence: "Uncaught panics in WASM modules cause unrecoverable traps that crash the host runtime without useful error information",
        acceptanceCriteria: [
          "WASM module must set a panic hook for error reporting",
          "All fallible operations must use catch_unwind or proper Result-based error handling",
          "unwrap/expect calls must be replaced with proper error propagation"
        ],
        evidence: [{
          id: "DK-WASM-003-1",
          detector: "pattern-match",
          location: { path: f },
          controls: [],
          signals: ["unwrap/expect/panic! found without catch_unwind or set_panic_hook"]
        }]
      });
    }
  }

  return findings;
}
