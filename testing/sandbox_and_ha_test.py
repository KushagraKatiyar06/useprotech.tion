"""
UseProtection — Integrated Sandbox + Hybrid Analysis Tester
============================================================
Usage:
    python sandbox_and_ha_test.py [path/to/malware]

Steps:
    1. Build the Docker sandbox image from sandbox/Dockerfile
    2. Run the malware inside the container, capture full static+dynamic analysis
    3. Submit the file to Hybrid Analysis API (or search by hash if already known)
    4. Poll HA until analysis completes, then pull every available data endpoint
    5. Write combined JSON report to testing/report_<sha256[:8]>.json

Requirements:
    pip install requests python-dotenv
    Docker must be running (docker info)
"""

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import requests
from dotenv import load_dotenv

# ── Config ────────────────────────────────────────────────────────────────────

REPO_ROOT    = Path(__file__).parent.parent
SANDBOX_DIR  = REPO_ROOT / "sandbox"
TESTING_DIR  = Path(__file__).parent

# Load .env from agents/ first (has HA key), then root .env
load_dotenv(REPO_ROOT / "agents" / ".env")
load_dotenv(REPO_ROOT / ".env", override=False)

HA_KEY    = os.environ.get("HYBRID_ANALYSIS_API_KEY", "")
HA_BASE   = "https://www.hybrid-analysis.com/api/v2"
HA_HDRS   = {
    "api-key":    HA_KEY,
    "User-Agent": "Falcon Sandbox",
    "Accept":     "application/json",
}

# Default malware sample if none given
DEFAULT_SAMPLE = TESTING_DIR / "6108674530.JS.malicious"

# Hybrid Analysis environment IDs
# 110 = Windows 7 32-bit, 120 = Windows 7 64-bit, 300 = Linux (Ubuntu 16.04)
HA_ENV_ID = 110

# ── Helpers ───────────────────────────────────────────────────────────────────

def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def sha256_of_safe(path: Path) -> str | None:
    """Returns sha256 or None if the file is blocked (e.g. Windows Defender quarantine)."""
    try:
        return sha256_of(path)
    except PermissionError:
        return None


def log(msg: str) -> None:
    print(f"[*] {msg}", flush=True)


def err(msg: str) -> None:
    print(f"[!] {msg}", flush=True)


def ha_get(path: str, params: dict = None) -> dict | None:
    try:
        r = requests.get(f"{HA_BASE}{path}", headers=HA_HDRS, params=params, timeout=30)
        if r.status_code == 200:
            return r.json()
        err(f"GET {path} → {r.status_code}: {r.text[:200]}")
        return None
    except Exception as e:
        err(f"GET {path} failed: {e}")
        return None


def ha_post(path: str, data: dict = None, files=None, json_body: dict = None) -> dict | None:
    try:
        r = requests.post(
            f"{HA_BASE}{path}",
            headers=HA_HDRS,
            data=data,
            files=files,
            json=json_body,
            timeout=60,
        )
        if r.status_code in (200, 201):
            return r.json()
        err(f"POST {path} → {r.status_code}: {r.text[:300]}")
        return None
    except Exception as e:
        err(f"POST {path} failed: {e}")
        return None


# ── Step 1 — Docker sandbox ───────────────────────────────────────────────────

IMAGE_NAME = "useprotection-sandbox"

def build_docker_image() -> bool:
    log(f"Building Docker image '{IMAGE_NAME}' from {SANDBOX_DIR} ...")
    result = subprocess.run(
        ["docker", "build", "-t", IMAGE_NAME, str(SANDBOX_DIR)],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        err("docker build failed:\n" + result.stderr[-1000:])
        return False
    log("Image built successfully.")
    return True


def run_docker_sandbox(sample_path: Path) -> dict:
    """
    Runs analyze.py inside the sandbox container against the sample.
    The file is volume-mounted as /analysis/sample<ext>.
    Returns the parsed JSON output from analyze.py.
    """
    suffix   = sample_path.suffix or ".bin"
    dest     = f"/analysis/sample{suffix}"
    abs_path = str(sample_path.resolve())

    log(f"Running sandbox analysis on: {sample_path.name}")

    result = subprocess.run(
        [
            "docker", "run", "--rm",
            "--network", "none",            # no outbound network
            "--memory", "512m",
            "--cpus",   "1",
            "-v", f"{abs_path}:{dest}:ro",  # mount sample read-only
            IMAGE_NAME,
            dest,                           # passed to analyze.py as argv[1]
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    sandbox_output = {
        "stdout_raw": result.stdout,
        "stderr_raw": result.stderr,
        "exit_code":  result.returncode,
        "parsed":     {},
    }

    if result.returncode != 0:
        err(f"Container exited with code {result.returncode}")
        err(result.stderr[-500:])

    # analyze.py writes JSON to stdout
    try:
        sandbox_output["parsed"] = json.loads(result.stdout)
        log("Sandbox JSON parsed successfully.")
    except json.JSONDecodeError:
        err("Could not parse sandbox JSON output — keeping raw stdout.")

    return sandbox_output


# ── Step 2 — Hybrid Analysis ──────────────────────────────────────────────────

def ha_search_hash(sha256: str) -> dict | None:
    log(f"Searching HA for hash: {sha256[:16]}...")
    result = ha_post("/search/hash", data={"hash": sha256})
    return result


def ha_submit_file(sample_path: Path) -> dict | None:
    log(f"Submitting {sample_path.name} to Hybrid Analysis (env {HA_ENV_ID})...")
    with open(sample_path, "rb") as fh:
        result = ha_post(
            "/submit/file",
            data={"environment_id": HA_ENV_ID},
            files={"file": (sample_path.name, fh, "application/octet-stream")},
        )
    return result


def ha_poll_state(job_id: str, max_wait: int = 600) -> str:
    """
    Polls /report/{job_id}/state until analysis is done or timeout.
    Returns final state string.
    """
    log(f"Polling HA job {job_id} (max {max_wait}s)...")
    start = time.time()
    while time.time() - start < max_wait:
        data = ha_get(f"/report/{job_id}/state")
        if data:
            state = data.get("state", "unknown")
            log(f"  State: {state}")
            if state in ("SUCCESS", "ERROR"):
                return state
        time.sleep(15)
    return "TIMEOUT"


def ha_pull_all_data(identifier: str) -> dict:
    """
    identifier is either a sha256 (for hash lookups) or a job_id (UUID).
    Pulls every available endpoint and returns a combined dict.
    """
    log(f"Pulling all available HA data for: {identifier[:24]}...")
    collected = {}

    endpoints = {
        "overview":          f"/overview/{identifier}",
        "summary":           f"/report/{identifier}/summary",
        "file_analysis":     f"/report/{identifier}/file/analysis",
        "network":           f"/report/{identifier}/file/network",
        "process_list":      f"/report/{identifier}/process_list",
        "dropped_files":     f"/report/{identifier}/dropped-files",
        "mitre_attck":       f"/report/{identifier}/mitre-attck",
        "certificates":      f"/report/{identifier}/certificates",
        "hybrid_analysis":   f"/report/{identifier}/hybrid-analysis",
    }

    for key, path in endpoints.items():
        data = ha_get(path)
        if data:
            collected[key] = data
            log(f"  ✓ {key}")
        else:
            log(f"  - {key} (not available)")

    return collected


def ha_search_terms(sample_path: Path) -> dict:
    """
    Extract IOCs from file and run term/URL/domain searches against HA.
    Skips gracefully if file is unreadable (Windows Defender quarantine).
    """
    import re
    log("Running HA term searches from file IOCs...")

    try:
        text = sample_path.read_text(errors="ignore")
    except PermissionError:
        err(f"Cannot read {sample_path.name} for IOC extraction (file is blocked). Skipping term searches.")
        return {}

    urls    = list(set(re.findall(r'https?://[^\s\'"<>|)]{4,}', text)))[:5]
    domains = list(set(re.findall(
        r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|ru|cn|info|biz|io|cc)\b', text
    )))[:5]

    results = {}

    for url in urls:
        data = ha_post("/search/terms", json_body={"url": url})
        if data:
            results[f"url:{url[:60]}"] = data

    for domain in domains:
        data = ha_post("/search/terms", json_body={"domain": domain})
        if data:
            results[f"domain:{domain}"] = data

    return results


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    # Resolve sample path
    sample_path = Path(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_SAMPLE
    if not sample_path.exists():
        err(f"Sample not found: {sample_path}")
        sys.exit(1)

    if not HA_KEY:
        err("HYBRID_ANALYSIS_API_KEY not set in .env — HA steps will be skipped.")

    sha256 = sha256_of_safe(sample_path)
    file_blocked = sha256 is None
    if file_blocked:
        print()
        err("=" * 58)
        err("FILE BLOCKED BY WINDOWS DEFENDER")
        err("=" * 58)
        err(f"  {sample_path.resolve()}")
        err("")
        err("Windows Defender has quarantined this file and is blocking")
        err("all read access. To run this script you must first add an")
        err("exclusion in Windows Security:")
        err("")
        err("  1. Open: Windows Security")
        err("  2. Go to: Virus & threat protection")
        err("  3. Under 'Virus & threat protection settings' > Exclusions")
        err("  4. Add an exclusion > Folder")
        err(f"  5. Add: {sample_path.parent.resolve()}")
        err("")
        err("Then re-run this script.")
        sys.exit(1)

    log(f"Sample: {sample_path.name}")
    log(f"SHA256: {sha256}")
    print()

    report = {
        "sample":        str(sample_path.name),
        "sha256":        sha256,
        "file_blocked":  file_blocked,
        "sandbox":       {},
        "hybrid_analysis": {},
    }

    # ── Docker sandbox ────────────────────────────────────────────────────────
    print("=" * 60)
    print("PHASE 1 — LOCAL DOCKER SANDBOX")
    print("=" * 60)

    # Check Docker is available
    check = subprocess.run(["docker", "info"], capture_output=True)
    if check.returncode != 0:
        err("Docker is not running or not installed — skipping sandbox phase.")
    else:
        if not build_docker_image():
            err("Skipping sandbox run due to build failure.")
        else:
            report["sandbox"] = run_docker_sandbox(sample_path)

    print()

    # ── Hybrid Analysis ───────────────────────────────────────────────────────
    print("=" * 60)
    print("PHASE 2 — HYBRID ANALYSIS API")
    print("=" * 60)

    if not HA_KEY:
        log("Skipping HA (no key).")
    else:
        ha_data = {}

        # Always search by hash first — works even on free tier for known malware
        hash_result = ha_search_hash(sha256)
        if hash_result:
            ha_data["hash_search"] = hash_result
            # If HA already has reports for this hash, extract the job ID
            reports = hash_result if isinstance(hash_result, list) else [hash_result]
            for rep in reports:
                job_id = rep.get("job_id") or rep.get("id") or rep.get("sha256")
                if job_id:
                    log(f"Found existing HA report — pulling full data for job {job_id[:24]}...")
                    ha_data["report_data"] = ha_pull_all_data(job_id)
                    break
            else:
                # No existing report — try sha256 endpoint directly
                ha_data["report_data"] = ha_pull_all_data(sha256)

        else:
            log("Hash not found in HA database — attempting fresh submission...")
            submission = ha_submit_file(sample_path)
            if submission:
                ha_data["submission"] = submission
                job_id = submission.get("job_id") or submission.get("id")
                if job_id:
                    state = ha_poll_state(job_id)
                    ha_data["final_state"] = state
                    if state == "SUCCESS":
                        ha_data["report_data"] = ha_pull_all_data(job_id)
                    else:
                        err(f"Analysis ended in state: {state}")
                        ha_data["report_data"] = ha_pull_all_data(job_id)
            else:
                err("Submission failed — API tier may not allow file submission.")
                log("Pulling any available HA data by hash anyway...")
                ha_data["report_data"] = ha_pull_all_data(sha256)

        # IOC-based term searches
        ha_data["term_searches"] = ha_search_terms(sample_path)

        report["hybrid_analysis"] = ha_data

    # ── Write report ──────────────────────────────────────────────────────────
    print()
    print("=" * 60)
    print("PHASE 3 — SAVING REPORT")
    print("=" * 60)

    out_path = TESTING_DIR / f"report_{sha256[:8]}.json"
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)
    log(f"Report saved to: {out_path}")

    # Print summary
    print()
    print("─" * 60)
    print("SUMMARY")
    print("─" * 60)

    sandbox_parsed = report["sandbox"].get("parsed", {})
    if sandbox_parsed:
        print(f"  Threat level     : {sandbox_parsed.get('threat_level', 'N/A')}")
        print(f"  Is obfuscated    : {sandbox_parsed.get('is_obfuscated', 'N/A')}")
        print(f"  Entropy          : {sandbox_parsed.get('entropy', 'N/A')}")
        print(f"  Behaviors        : {len(sandbox_parsed.get('behaviors', []))}")
        print(f"  Dangerous funcs  : {len(sandbox_parsed.get('dangerous_functions', []))}")
        print(f"  MITRE techniques : {len(sandbox_parsed.get('mitre_techniques', []))}")
        print(f"  URLs found       : {len(sandbox_parsed.get('urls_found', []))}")
        print(f"  IPs found        : {len(sandbox_parsed.get('ips_found', []))}")
    else:
        print("  Sandbox: no output (Docker not available or build failed)")

    ha_report = report["hybrid_analysis"].get("report_data", {})
    available_keys = [k for k, v in ha_report.items() if v]
    print(f"  HA data sections : {available_keys or 'none'}")

    print()
    print(f"Full report: {out_path}")


if __name__ == "__main__":
    main()
