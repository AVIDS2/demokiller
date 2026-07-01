#!/usr/bin/env bash
# Benchmark runner: clone → analyze → delete, one project at a time
# Usage: bash benchmarks/run-benchmark.sh [max_projects]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LIST_FILE="$SCRIPT_DIR/diverse-projects.json"
RESULTS_DIR="$SCRIPT_DIR/results"
TMP_DIR="$SCRIPT_DIR/.tmp-clone"
MAX_PROJECTS="${1:-999}"

mkdir -p "$RESULTS_DIR"

if [ ! -f "$LIST_FILE" ]; then
  echo "ERROR: $LIST_FILE not found"
  exit 1
fi

TOTAL=$(python3 -c "import json; print(len(json.load(open('$LIST_FILE'))))" 2>/dev/null || python -c "import json; print(len(json.load(open('$LIST_FILE'))))")
echo "=== Demo Killer Benchmark ==="
echo "Projects: $TOTAL (max: $MAX_PROJECTS)"
echo "Results:  $RESULTS_DIR"
echo ""

PASS=0
FAIL=0
ERROR=0
SKIP=0
COUNT=0

# Summary CSV
SUMMARY="$RESULTS_DIR/summary.csv"
echo "name,domain,language,blockers,highs,mediums,advisories,total,verdict,duration_s,status" > "$SUMMARY"

# Read project list and iterate
python3 -c "
import json, sys
projects = json.load(open('$LIST_FILE'))
for i, p in enumerate(projects):
    print(f\"{i}|{p['name']}|{p['repo']}|{p.get('domain','unknown')}|{p.get('language','unknown')}\")
" 2>/dev/null || python -c "
import json, sys
projects = json.load(open('$LIST_FILE'))
for i, p in enumerate(projects):
    print(f\"{i}|{p['name']}|{p['repo']}|{p.get('domain','unknown')}|{p.get('language','unknown')}\")
" | while IFS='|' read -r IDX NAME REPO DOMAIN LANG; do
  COUNT=$((COUNT + 1))
  if [ "$COUNT" -gt "$MAX_PROJECTS" ]; then
    break
  fi

  RESULT_FILE="$RESULTS_DIR/${NAME}.json"

  # Skip if already analyzed
  if [ -f "$RESULT_FILE" ]; then
    echo "[$COUNT/$TOTAL] SKIP $NAME (already analyzed)"
    SKIP=$((SKIP + 1))
    continue
  fi

  echo -n "[$COUNT/$TOTAL] $NAME ($DOMAIN, $LANG)... "
  START_TIME=$(date +%s)

  # Clean clone dir
  rm -rf "$TMP_DIR"

  # Shallow clone with 30s timeout
  if ! timeout 30 git clone --depth 1 --single-branch "$REPO" "$TMP_DIR" 2>/dev/null; then
    echo "CLONE_FAILED"
    echo "{\"name\":\"$NAME\",\"domain\":\"$DOMAIN\",\"language\":\"$LANG\",\"status\":\"clone_failed\"}" > "$RESULT_FILE"
    echo "$NAME,$DOMAIN,$LANG,,,,,,,$(( $(date +%s) - START_TIME )),clone_failed" >> "$SUMMARY"
    rm -rf "$TMP_DIR"
    ERROR=$((ERROR + 1))
    continue
  fi

  CLONE_TIME=$(($(date +%s) - START_TIME))

  # Run Demo Killer with 60s timeout
  ANALYSIS_START=$(date +%s)
  if timeout 60 node "$PROJECT_ROOT/dist/src/cli.js" inspect "$TMP_DIR" --json 2>/dev/null > "$RESULT_FILE.raw"; then
    ANALYSIS_TIME=$(($(date +%s) - ANALYSIS_START))

    # Parse results
    STATS=$(python3 -c "
import json, sys
try:
    data = json.load(open('$RESULT_FILE.raw'))
    findings = data.get('findings', [])
    blockers = len([f for f in findings if f.get('severity') == 'blocker'])
    highs = len([f for f in findings if f.get('severity') == 'high'])
    mediums = len([f for f in findings if f.get('severity') == 'medium'])
    advisories = len([f for f in findings if f.get('severity') == 'advisory'])
    total = len(findings)
    if blockers > 0: verdict = 'Launch Blocked'
    elif highs > 0: verdict = 'Hardening Required'
    elif mediums > 0: verdict = 'Minor Issues'
    else: verdict = 'Production Ready'
    # Save structured result
    json.dump({
        'name': '$NAME', 'domain': '$DOMAIN', 'language': '$LANG',
        'blockers': blockers, 'highs': highs, 'mediums': mediums,
        'advisories': advisories, 'total': total, 'verdict': verdict,
        'clone_time': $CLONE_TIME, 'analysis_time': $ANALYSIS_TIME,
        'top_findings': [{'ruleId': f.get('ruleId'), 'severity': f.get('severity'), 'title': f.get('title')} for f in findings[:10]]
    }, open('$RESULT_FILE', 'w'), indent=2)
    print(f'{blockers},{highs},{mediums},{advisories},{total},{verdict},{CLONE_TIME + ANALYSIS_TIME}')
except Exception as e:
    print(f'PARSE_ERROR: {e}', file=sys.stderr)
    print(',,,,,parse_error,' + str($CLONE_TIME + $ANALYSIS_TIME))
" 2>/dev/null) || STATS=",,,,,script_error,0"

    IFS=',' read -r B H M A T V DUR <<< "$STATS"
    echo "B=$B H=$H M=$M → $V (${DUR}s)"
    echo "$NAME,$DOMAIN,$LANG,$B,$H,$M,$A,$T,$V,$DUR,ok" >> "$SUMMARY"

    if [ "$B" != "0" ] && [ "$B" != "" ]; then
      FAIL=$((FAIL + 1))
    else
      PASS=$((PASS + 1))
    fi

    # Clean up raw file
    rm -f "$RESULT_FILE.raw"
  else
    ANALYSIS_TIME=$(($(date +%s) - ANALYSIS_START))
    echo "ANALYSIS_TIMEOUT (${ANALYSIS_TIME}s)"
    echo "{\"name\":\"$NAME\",\"domain\":\"$DOMAIN\",\"language\":\"$LANG\",\"status\":\"analysis_timeout\"}" > "$RESULT_FILE"
    echo "$NAME,$DOMAIN,$LANG,,,,,,,${ANALYSIS_TIME},timeout" >> "$SUMMARY"
    rm -f "$RESULT_FILE.raw"
    ERROR=$((ERROR + 1))
  fi

  # Delete clone immediately
  rm -rf "$TMP_DIR"

  # Brief pause to avoid rate limiting
  sleep 1
done

# Final summary
echo ""
echo "=== BENCHMARK COMPLETE ==="
echo "Results in: $RESULTS_DIR/"
echo "Summary:    $SUMMARY"
