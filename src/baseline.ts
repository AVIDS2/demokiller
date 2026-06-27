import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import type { Finding } from "./types.js";

export interface BaselineEntry {
  ruleId: string;
  path: string;
  fingerprint: string; // hash of ruleId + path + title
}

/**
 * Build a stable fingerprint for a finding.
 * hash(ruleId + ":" + path + ":" + title)
 */
export function buildFingerprint(ruleId: string, path: string, title: string): string {
  return createHash("sha256").update(`${ruleId}:${path}:${title}`).digest("hex").slice(0, 16);
}

/**
 * Derive the primary path from a finding (first evidence location, or "" if none).
 */
function findingPath(finding: Finding): string {
  return finding.evidence[0]?.location?.path ?? "";
}

/**
 * Load a baseline file. Returns an empty array if the file does not exist or is invalid.
 */
export async function loadBaseline(baselinePath: string): Promise<BaselineEntry[]> {
  try {
    const text = await fs.readFile(baselinePath, "utf8");
    const parsed = JSON.parse(text) as BaselineEntry[];
    if (!Array.isArray(parsed)) return [];
    return parsed;
  } catch {
    return [];
  }
}

/**
 * Save findings as a baseline file (sorted by fingerprint for determinism).
 */
export async function saveBaseline(findings: Finding[], baselinePath: string): Promise<void> {
  const entries: BaselineEntry[] = findings.map((f) => {
    const p = findingPath(f);
    return {
      ruleId: f.ruleId,
      path: p,
      fingerprint: buildFingerprint(f.ruleId, p, f.title),
    };
  });

  entries.sort((a, b) => a.fingerprint.localeCompare(b.fingerprint));

  const json = JSON.stringify(entries, null, 2) + "\n";
  await fs.writeFile(baselinePath, json, "utf8");
}

/**
 * Compare current findings against a baseline:
 *   - newFindings:      not in baseline
 *   - fixedFindings:    in baseline but absent from current (resolved)
 *   - existingFindings: in both (should be suppressed in output)
 */
export function diffFindings(
  current: Finding[],
  baseline: BaselineEntry[],
): {
  newFindings: Finding[];
  fixedFindings: BaselineEntry[];
  existingFindings: Finding[];
} {
  const baselineByFingerprint = new Map<string, BaselineEntry>();
  for (const entry of baseline) {
    baselineByFingerprint.set(entry.fingerprint, entry);
  }

  const newFindings: Finding[] = [];
  const existingFindings: Finding[] = [];
  const matchedBaselineFingerprints = new Set<string>();

  for (const finding of current) {
    const p = findingPath(finding);
    const fp = buildFingerprint(finding.ruleId, p, finding.title);

    if (baselineByFingerprint.has(fp)) {
      existingFindings.push(finding);
      matchedBaselineFingerprints.add(fp);
    } else {
      newFindings.push(finding);
    }
  }

  const fixedFindings: BaselineEntry[] = [];
  for (const [fp, entry] of baselineByFingerprint) {
    if (!matchedBaselineFingerprints.has(fp)) {
      fixedFindings.push(entry);
    }
  }

  return { newFindings, fixedFindings, existingFindings };
}
