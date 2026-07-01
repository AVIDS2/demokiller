#!/usr/bin/env python3
"""Aggregate benchmark results into a report."""
import json, csv, os, sys
from pathlib import Path
from collections import Counter, defaultdict

RESULTS_DIR = Path(__file__).parent / "results"
REPORT_FILE = Path(__file__).parent / "report.md"

def main():
    summary_csv = RESULTS_DIR / "summary.csv"
    if not summary_csv.exists():
        print("No summary.csv found. Run benchmarks first.")
        return

    rows = []
    with open(summary_csv) as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)

    if not rows:
        print("No results found.")
        return

    # Overall stats
    total = len(rows)
    ok = [r for r in rows if r.get("status") == "ok"]
    errors = [r for r in rows if r.get("status") != "ok"]

    verdicts = Counter(r.get("verdict", "unknown") for r in ok)
    domain_counts = Counter(r.get("domain", "unknown") for r in rows)
    lang_counts = Counter(r.get("language", "unknown") for r in rows)

    # Per-domain breakdown
    domain_verdicts = defaultdict(lambda: Counter())
    for r in ok:
        domain_verdicts[r.get("domain", "unknown")][r.get("verdict", "unknown")] += 1

    # Top triggered rules
    rule_counts = Counter()
    for fname in RESULTS_DIR.glob("*.json"):
        if fname.name == "summary.csv":
            continue
        try:
            data = json.loads(fname.read_text())
            for f in data.get("top_findings", []):
                rule_counts[f.get("ruleId", "unknown")] += 1
        except:
            pass

    # False positive candidates: rules that fire on >70% of projects
    high_freq_rules = [(r, c) for r, c in rule_counts.most_common(20) if c > len(ok) * 0.3]

    # Build report
    lines = []
    lines.append("# Demo Killer Benchmark Report\n")
    lines.append(f"**Date**: {__import__('datetime').date.today()}\n")
    lines.append(f"**Projects analyzed**: {total} ({len(ok)} OK, {len(errors)} errors)\n")
    lines.append("## Verdicts\n")
    lines.append("| Verdict | Count | % |")
    lines.append("|---------|-------|---|")
    for v in ["Production Ready", "Minor Issues", "Hardening Required", "Launch Blocked"]:
        c = verdicts.get(v, 0)
        pct = f"{c/len(ok)*100:.1f}" if ok else "0"
        lines.append(f"| {v} | {c} | {pct}% |")
    if errors:
        lines.append(f"\n*{len(errors)} projects failed (clone timeout, analysis timeout, or parse error)*\n")

    lines.append("\n## By Domain\n")
    lines.append("| Domain | Total | Ready | Minor | Hardening | Blocked |")
    lines.append("|--------|-------|-------|-------|-----------|---------|")
    for domain, _ in domain_counts.most_common():
        dv = domain_verdicts.get(domain, {})
        lines.append(f"| {domain} | {domain_counts[domain]} | {dv.get('Production Ready', 0)} | {dv.get('Minor Issues', 0)} | {dv.get('Hardening Required', 0)} | {dv.get('Launch Blocked', 0)} |")

    lines.append("\n## By Language\n")
    lines.append("| Language | Projects |")
    lines.append("|----------|----------|")
    for lang, c in lang_counts.most_common():
        lines.append(f"| {lang} | {c} |")

    lines.append("\n## Most Triggered Rules (Top 20)\n")
    lines.append("| Rule ID | Times Triggered | % of Projects |")
    lines.append("|---------|----------------|---------------|")
    for rule, count in rule_counts.most_common(20):
        pct = f"{count/len(ok)*100:.1f}" if ok else "0"
        lines.append(f"| {rule} | {count} | {pct}% |")

    if high_freq_rules:
        lines.append("\n## False Positive Candidates\n")
        lines.append("*Rules triggering on >30% of projects — may need tightening:*\n")
        for rule, count in high_freq_rules:
            lines.append(f"- **{rule}**: {count}/{len(ok)} projects ({count/len(ok)*100:.0f}%)")

    lines.append("\n## Individual Results\n")
    lines.append("| Project | Domain | Lang | B | H | M | Verdict | Time |")
    lines.append("|---------|--------|------|---|---|---|---------|------|")
    for r in sorted(ok, key=lambda x: x.get("domain", "")):
        lines.append(f"| {r['name']} | {r.get('domain','')} | {r.get('language','')} | {r.get('blockers','')} | {r.get('highs','')} | {r.get('mediums','')} | {r.get('verdict','')} | {r.get('duration_s','')}s |")

    report = "\n".join(lines)
    REPORT_FILE.write_text(report, encoding="utf-8")
    print(f"Report written to {REPORT_FILE}")
    print(f"\nSummary: {total} projects, {verdicts.get('Production Ready',0)} ready, {verdicts.get('Launch Blocked',0)} blocked")

if __name__ == "__main__":
    main()
