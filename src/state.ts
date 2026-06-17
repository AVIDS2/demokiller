import type { AnalysisReport } from "./types.js";

export interface RecheckDiff {
  previousVerdict: string;
  currentVerdict: string;
  resolvedRuleIds: string[];
  newRuleIds: string[];
  remainingRuleIds: string[];
}

export function diffSnapshots(previous: AnalysisReport, current: AnalysisReport): RecheckDiff {
  const previousIds = new Set(previous.findings.map((finding) => finding.ruleId));
  const currentIds = new Set(current.findings.map((finding) => finding.ruleId));

  return {
    previousVerdict: previous.verdict,
    currentVerdict: current.verdict,
    resolvedRuleIds: [...previousIds].filter((id) => !currentIds.has(id)),
    newRuleIds: [...currentIds].filter((id) => !previousIds.has(id)),
    remainingRuleIds: [...currentIds].filter((id) => previousIds.has(id)),
  };
}
