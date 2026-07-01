#!/usr/bin/env python3
"""Benchmark runner: hybrid download (tarball → git clone fallback) → analyze → delete."""
import json, subprocess, shutil, time, csv, sys, os, tempfile, tarfile
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading

SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
LIST_FILE = SCRIPT_DIR / "diverse-projects.json"
RESULTS_DIR = SCRIPT_DIR / "results"
CLI_JS = PROJECT_ROOT / "dist" / "src" / "cli.js"

write_lock = threading.Lock()


def download_tarball(repo: str, dest: Path) -> bool:
    """Download and extract a GitHub repo tarball. Returns True on success."""
    slug = repo.replace("https://github.com/", "").replace("http://github.com/", "").replace(".git", "").strip("/")
    tarball_path = dest / "_dk_repo.tar.gz"

    for branch in ("main", "master"):
        url = f"https://github.com/{slug}/archive/refs/heads/{branch}.tar.gz"
        try:
            subprocess.run(
                ["curl", "-sSfL", "--connect-timeout", "8", "--max-time", "15", "-o", str(tarball_path), url],
                capture_output=True, timeout=20, check=True
            )
            if tarball_path.exists() and tarball_path.stat().st_size > 500:
                break
        except Exception:
            tarball_path.unlink(missing_ok=True)
            continue
    else:
        return False

    try:
        with tarfile.open(tarball_path, "r:gz") as tar:
            tar.extractall(dest, filter="data")
    except Exception:
        tarball_path.unlink(missing_ok=True)
        return False
    tarball_path.unlink(missing_ok=True)

    # GitHub tarballs extract to {repo}-{hash}/ — move contents up
    entries = [e for e in dest.iterdir() if e.is_dir()]
    if len(entries) == 1:
        inner = entries[0]
        for item in inner.iterdir():
            shutil.move(str(item), str(dest / item.name))
        try:
            inner.rmdir()
        except OSError:
            pass

    # Verify we actually got source files
    try:
        top_files = list(dest.iterdir())
        if len(top_files) < 2:
            return False
    except Exception:
        return False

    return True


def git_clone(repo: str, dest: Path) -> bool:
    """Shallow git clone. Returns True on success."""
    try:
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", repo, str(dest)],
            capture_output=True, timeout=40, encoding="utf-8", errors="replace"
        )
        return proc.returncode == 0
    except Exception:
        return False


def download_project(repo: str, dest: Path) -> str:
    """Try git clone first (fast), then tarball fallback. Returns method name or 'failed'."""
    # Strategy 1: git clone (fast, works from China)
    if git_clone(repo, dest):
        return "git"

    # Clean up failed git clone artifacts
    for item in list(dest.iterdir()):
        if item.is_dir():
            shutil.rmtree(item, ignore_errors=True)
        else:
            item.unlink(missing_ok=True)

    # Strategy 2: tarball with short timeout (15s max)
    if download_tarball(repo, dest):
        return "tarball"

    return "failed"


def analyze_one(proj, total):
    """Analyze a single project. Returns (name, row_data, print_line)."""
    name = proj["name"]
    repo = proj["repo"]
    domain = proj.get("domain", "unknown")
    lang = proj.get("language", "unknown")
    result_file = RESULTS_DIR / f"{name}.json"

    if result_file.exists():
        return (name, None, None)

    start = time.time()
    tmp_dir = Path(tempfile.mkdtemp(prefix=f"dk-{name}-", dir=str(SCRIPT_DIR)))

    method = download_project(repo, tmp_dir)
    if method == "failed":
        elapsed = time.time() - start
        result_file.write_text(json.dumps({"name": name, "domain": domain, "language": lang, "status": "download_failed"}), encoding="utf-8")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return (name, [name, domain, lang, "", "", "", "", "", "", f"{elapsed:.0f}", "download_failed"], f"DOWNLOAD_FAILED ({elapsed:.0f}s)")

    download_time = time.time() - start
    analysis_start = time.time()
    try:
        proc = subprocess.run(
            ["node", str(CLI_JS), "inspect", str(tmp_dir), "--json"],
            capture_output=True, timeout=90, text=True, encoding="utf-8", errors="replace"
        )
        raw_output = proc.stdout or ""
    except subprocess.TimeoutExpired:
        elapsed = time.time() - start
        result_file.write_text(json.dumps({"name": name, "domain": domain, "language": lang, "status": "timeout"}), encoding="utf-8")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return (name, [name, domain, lang, "", "", "", "", "", "", f"{elapsed:.0f}", "timeout"], f"ANALYSIS_TIMEOUT ({elapsed:.0f}s)")

    analysis_time = time.time() - analysis_start
    total_time = time.time() - start

    try:
        data = json.loads(raw_output)
        findings = data.get("findings", [])
        blockers = sum(1 for f in findings if f.get("severity") == "blocker")
        highs = sum(1 for f in findings if f.get("severity") == "high")
        mediums = sum(1 for f in findings if f.get("severity") == "medium")
        advisories = sum(1 for f in findings if f.get("severity") == "advisory")
        count = len(findings)

        if blockers > 0: verdict = "Launch Blocked"
        elif highs > 0: verdict = "Hardening Required"
        elif mediums > 0: verdict = "Minor Issues"
        else: verdict = "Production Ready"

        result_data = {
            "name": name, "domain": domain, "language": lang,
            "blockers": blockers, "highs": highs, "mediums": mediums,
            "advisories": advisories, "total": count, "verdict": verdict,
            "download_time": round(download_time), "analysis_time": round(analysis_time),
            "method": method,
            "top_findings": [
                {"ruleId": f.get("ruleId"), "severity": f.get("severity"), "title": f.get("title")}
                for f in findings[:15]
            ]
        }
        result_file.write_text(json.dumps(result_data, indent=2, ensure_ascii=False), encoding="utf-8")
        line = f"B={blockers} H={highs} M={mediums} -> {verdict} [{method}] ({total_time:.0f}s)"
        row = [name, domain, lang, blockers, highs, mediums, advisories, count, verdict, f"{total_time:.0f}", "ok"]
    except Exception as e:
        elapsed = time.time() - start
        result_file.write_text(json.dumps({"name": name, "domain": domain, "language": lang, "status": "parse_error", "raw": (raw_output or "")[:500]}), encoding="utf-8")
        line = f"PARSE_ERROR: {e} ({elapsed:.0f}s)"
        row = [name, domain, lang, "", "", "", "", "", "", f"{elapsed:.0f}", "parse_error"]

    shutil.rmtree(tmp_dir, ignore_errors=True)
    return (name, row, line)


def run_benchmark(max_projects=999, workers=6):
    RESULTS_DIR.mkdir(exist_ok=True)
    with open(LIST_FILE, "r", encoding="utf-8") as f:
        projects = json.load(f)

    total = min(len(projects), max_projects)
    print(f"=== Demo Killer Benchmark (hybrid x{workers}) ===")
    print(f"Projects: {total} / {len(projects)}")
    print(f"Results:  {RESULTS_DIR}\n")

    summary_rows = []
    done_count = 0
    skipped = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(analyze_one, proj, total): proj for proj in projects[:total]}
        for future in as_completed(futures):
            name, row, line = future.result()
            if row is None and line is None:
                skipped += 1
                continue
            done_count += 1
            with write_lock:
                summary_rows.append(row)
            print(f"[{done_count}] {name}: {line}", flush=True)

    summary_path = RESULTS_DIR / "summary.csv"
    with open(summary_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "domain", "language", "blockers", "highs", "mediums", "advisories", "total", "verdict", "duration_s", "status"])
        writer.writerows(summary_rows)

    print(f"\n=== DONE ===")
    print(f"Results: {RESULTS_DIR}")
    print(f"Summary: {summary_path}")
    print(f"Skipped: {skipped} (already done)")
    print(f"Analyzed: {done_count}")

    ok_rows = [r for r in summary_rows if r[-1] == "ok"]
    if ok_rows:
        verdicts = {}
        for r in ok_rows:
            v = r[8]
            verdicts[v] = verdicts.get(v, 0) + 1
        print(f"\nVerdicts:")
        for v, c in sorted(verdicts.items()):
            print(f"  {v}: {c}")

if __name__ == "__main__":
    max_proj = int(sys.argv[1]) if len(sys.argv) > 1 else 999
    workers = int(sys.argv[2]) if len(sys.argv) > 2 else 6
    run_benchmark(max_proj, workers)
