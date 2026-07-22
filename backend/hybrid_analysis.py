"""
Hybrid Analysis (CrowdStrike Falcon Sandbox) API integration.
Free tier: unlimited public lookups, 200 submissions/day.
Sign up at: https://hybrid-analysis.com → Profile → API Key
"""

import os
import json
import time
import hashlib
import requests
from pathlib import Path

BASE_URL = "https://www.hybrid-analysis.com/api/v2"

HEADERS = {
    "User-Agent": "Falcon Sandbox",
    "Accept":     "application/json",
}


def _auth(api_key: str) -> dict:
    return {**HEADERS, "api-key": api_key}


# ── Hash lookup (instant — no submission needed for known samples) ─────────────

def lookup_by_hash(sha256: str, api_key: str) -> dict | None:
    """Search for existing analysis by SHA256. Returns None if not found."""
    try:
        r = requests.post(
            f"{BASE_URL}/search/hash",
            headers=_auth(api_key),
            data={"hash": sha256},
            timeout=15,
        )
        if r.status_code != 200:
            return None
        results = r.json()
        if not results:
            return None
        # Pick the most detailed report (highest threat_score)
        best = max(results, key=lambda x: x.get("threat_score") or 0)
        return _normalize(best)
    except Exception as e:
        print(f"HA lookup error: {e}")
        return None


# ── File submission (for new/unknown samples) ──────────────────────────────────

def submit_file(filepath: str, api_key: str, environment_id: int = 300) -> str | None:
    """
    Submit file for analysis. Returns job_id to poll.
    environment_id: 300 = Windows 10 64-bit, 200 = Windows 7 64-bit
    """
    try:
        with open(filepath, "rb") as f:
            r = requests.post(
                f"{BASE_URL}/submit/file",
                headers=_auth(api_key),
                files={"file": (Path(filepath).name, f, "application/octet-stream")},
                data={"environment_id": environment_id},
                timeout=60,
            )
        if r.status_code not in (200, 201):
            print(f"HA submit error {r.status_code}: {r.text[:200]}")
            return None
        return r.json().get("job_id") or r.json().get("sha256")
    except Exception as e:
        print(f"HA submit exception: {e}")
        return None


def poll_report(job_id: str, api_key: str, max_wait: int = 120) -> dict | None:
    """Poll until analysis completes or timeout."""
    deadline = time.time() + max_wait
    while time.time() < deadline:
        try:
            r = requests.get(
                f"{BASE_URL}/report/{job_id}/summary",
                headers=_auth(api_key),
                timeout=15,
            )
            if r.status_code == 200:
                data = r.json()
                state = data.get("state", "")
                if state in ("SUCCESS", "ERROR"):
                    return _normalize(data) if state == "SUCCESS" else None
            time.sleep(10)
        except Exception:
            time.sleep(10)
    return None


# ── Full analysis entry point ──────────────────────────────────────────────────

def analyze(filepath: str, api_key: str) -> dict | None:
    """
    1. Hash the file and look up existing results (instant).
    2. If not found, submit for fresh sandbox run and poll.
    """
    sha256 = _sha256(filepath)
    print(f"HA: looking up {sha256[:16]}...")

    result = lookup_by_hash(sha256, api_key)
    if result:
        print("HA: found existing report")
        result["source"] = "hash_lookup"
        return result

    print("HA: not found — submitting for analysis...")
    job_id = submit_file(filepath, api_key)
    if not job_id:
        return None

    result = poll_report(job_id, api_key)
    if result:
        result["source"] = "fresh_submission"
    return result


# ── Normalize HA report into our schema ───────────────────────────────────────

def _normalize(raw: dict) -> dict:
    """Convert HA API response into the shape our frontend/Claude expects."""

    # Process tree
    processes = []
    for proc in raw.get("processes", []) or []:
        processes.append({
            "name":       proc.get("name", ""),
            "pid":        proc.get("pid"),
            "parent_pid": proc.get("parent_pid"),
            "cmd":        proc.get("command_line", "")[:500],
            "color":      _proc_color(proc),
        })

    # Network connections
    network = []
    for conn in raw.get("network", {}).get("tcp", []) or []:
        network.append({
            "dst":      conn.get("ip_destination", ""),
            "port":     conn.get("port_destination"),
            "protocol": "TCP",
        })
    for req in raw.get("network", {}).get("http", []) or []:
        network.append({
            "dst":      req.get("request_url", ""),
            "port":     req.get("port", 80),
            "protocol": "HTTP",
            "method":   req.get("request_method", ""),
        })
    for dns in raw.get("network", {}).get("dns", []) or []:
        network.append({
            "dst":      dns.get("host", ""),
            "port":     53,
            "protocol": "DNS",
        })

    # File operations
    file_ops = []
    for f in raw.get("file_accesses", []) or []:
        file_ops.append({
            "op":   f.get("type", ""),
            "path": f.get("path", ""),
        })

    # Registry
    registry = []
    for reg in raw.get("registry", []) or []:
        registry.append({
            "op":  reg.get("type", ""),
            "key": reg.get("key", ""),
        })

    # MITRE ATT&CK
    mitre = []
    for t in raw.get("mitre_attcks", []) or []:
        mitre.append({
            "id":     t.get("attck_id", ""),
            "name":   t.get("attck_id_wiki", ""),
            "tactic": t.get("tactic", ""),
        })

    # Signatures / threat indicators
    signatures = []
    for sig in raw.get("signatures", []) or []:
        signatures.append({
            "name":        sig.get("name", ""),
            "threat_level": sig.get("threat_level_human", ""),
            "description": sig.get("description", ""),
        })

    # Dropped files
    dropped = [f.get("filename", "") for f in raw.get("dropped_files", []) or []]

    return {
        "verdict":       raw.get("verdict", ""),
        "threat_score":  raw.get("threat_score"),
        "threat_level":  raw.get("threat_level_human", ""),
        # NOTE: previously "A or B if C else D" parsed as "(A or B) if C else D",
        # which discarded vx_family whenever classifications was empty. Fixed
        # with explicit parens so vx_family is used first when present.
        "malware_family": raw.get("vx_family", "") or (raw.get("classifications", [""])[0] if raw.get("classifications") else ""),
        "sandbox_env":   raw.get("environment_description", ""),
        "processes":     processes,
        "network":       network,
        "file_ops":      file_ops[:30],
        "registry":      registry[:20],
        "mitre":         mitre,
        "signatures":    signatures[:20],
        "dropped_files": dropped[:15],
        "screenshots":   raw.get("screenshots_available", False),
        "sha256":        raw.get("sha256", ""),
    }


def _proc_color(proc: dict) -> str:
    name = (proc.get("name") or "").lower()
    if any(x in name for x in ["powershell", "cmd", "wscript", "cscript", "mshta"]):
        return "red"
    if any(x in name for x in ["svchost", "explorer", "lsass"]):
        return "yellow"
    return "green"


def _sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()
