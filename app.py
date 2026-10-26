"""UseProtection — FastAPI backend.

Serves the Next.js static export from frontend/out/ and exposes the
analysis API used by the pipeline.

Routes
------
GET  /                     → frontend/out/index.html  (landing page)
GET  /dashboard            → frontend/out/dashboard/index.html
GET  /_next/*              → Next.js JS/CSS chunks
GET  /favicon.ico          → favicon (if present)

POST /upload               → accept multipart file, start analysis job
                             returns {job_id, filename}
WS   /ws/{job_id}          → stream analysis progress events as JSON
                             until {event: "done"} or {event: "error"}

Analysis event schema (WebSocket messages)
------------------------------------------
{event: "sandbox_static_analysis", status: "running"|"complete", message?, data?}
                             # Stage 0, tool-based (strings/pefile/exiftool/
                             # binwalk/YARA/.NET) — runs before the AI pipeline
{event: "static_analysis_step", status: "running", message, step, total}
                             # fired once per real sub-step inside the above,
                             # purely for live progress; step/total are
                             # 1-indexed ints (e.g. step=3, total=7)
{event: "pipeline_start",   status: "running",            message,  data}
{event: "ingestion",        status: "running"|"complete", message?, data?}
{event: "static_analysis",  status: "running"|"complete", message?, data?}
                             # the AI classification AGENT — distinct from
                             # "sandbox_static_analysis" above
{event: "mitre_mapping",    status: "running"|"complete", message?, data?}
{event: "remediation",      status: "running"|"complete", message?, data?}
{event: "report",           status: "running"|"complete", message?, data?}
{event: "done",             status: "complete",           data: full_result}
{event: "error",            status: "error",              message: str}
"""
import asyncio
import concurrent.futures
import hashlib
import json
import os
import queue
import re
import sys
import tempfile
import threading
import time
import types as _types
import uuid
from datetime import datetime
from pathlib import Path

# Debug prints throughout this app and agents/pipeline.py use arrows/em-dashes/
# emoji. On Windows, stdout defaults to the system codepage (cp1252) rather
# than UTF-8, which can't encode those characters — the first such print()
# raises UnicodeEncodeError and kills whatever background thread called it
# (e.g. the whole analysis pipeline, mid-run). Force UTF-8 everywhere instead.
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Form, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

# ── Environment ──────────────────────────────────────────────────────────────
# Load root .env first, then agents/.env so the Anthropic key is available
# regardless of which file the developer put it in.
load_dotenv()
_agents_env = Path(__file__).parent / "agents" / ".env"
if _agents_env.exists():
    load_dotenv(_agents_env, override=False)

from sandbox.analyze import analyze_file                           # noqa: E402
from agents.pipeline import run_pipeline, enrich_with_virustotal   # noqa: E402

# ── Optional e2b + Gemini (adaptive sandbox) ──────────────────────────────────

_E2B_AVAILABLE = False
_ask_gemini_for_patch = None
_ask_gemini_to_diagnose = None
_run_once = None
_TAG_RULES: list = []
_BASE_MOCK = "console.log('[SYSTEM] Bare sandbox started.');\n"
_MAX_ITER = 5
_STUCK_THRESH = 3
_RUN_TIMEOUT = 45

try:
    _testing_dir = str(Path(__file__).parent / "testing")
    if _testing_dir not in sys.path:
        sys.path.insert(0, _testing_dir)
    from e2b_adaptive_sandbox import (          # type: ignore[import]
        ask_gemini_for_patch as _ask_gemini_for_patch,
        ask_gemini_to_diagnose as _ask_gemini_to_diagnose,
        run_once as _run_once,
        BASE_WINDOWS_MOCK_CATCHALL_ONLY as _BASE_MOCK,
        TAG_RULES as _TAG_RULES,
        MAX_ITERATIONS as _MAX_ITER,
        STUCK_THRESHOLD as _STUCK_THRESH,
        RUN_TIMEOUT as _RUN_TIMEOUT,
    )
    from e2b_code_interpreter import Sandbox as _E2BSandbox  # type: ignore[import]
    _E2B_AVAILABLE = True
    print("[app] e2b adaptive sandbox available")
except Exception as _e2b_import_err:
    print(f"[app] e2b sandbox not available: {_e2b_import_err}")


class _SandboxControl:
    """Per-adaptive-run human-in-the-loop state. One of these is created in
    /sandbox/start, before the background thread starts, so it always exists
    by the time the frontend could possibly call the control endpoints."""
    def __init__(self) -> None:
        self.request_control = False        # one-shot: pause on the *next* failure
        self.end_requested = False
        self.resume_event = threading.Event()
        self.guidance: str | None = None


_sandbox_controls: dict[str, _SandboxControl] = {}

def _is_rate_limit_error(text: str) -> bool:
    """Loose match for throttling/quota errors across providers (VT's plain
    HTTP 429, Gemini's `429 RESOURCE_EXHAUSTED` ClientError text, etc.) so
    both sandboxes can flag the same condition the same way in the logs."""
    t = text.lower()
    return any(marker in t for marker in (
        "429", "resource_exhausted", "rate limit", "rate-limit",
        "quota exceeded", "too many requests",
    ))


# ── VirusTotal integration ────────────────────────────────────────────────────
_VT_API_KEY = os.getenv("VT_API_KEY", "")
_VT_HEADERS = {"x-apikey": _VT_API_KEY} if _VT_API_KEY else {}

# Keys that identify a VirusTotal behaviour_summary JSON payload
_VT_SIGNATURE_KEYS = frozenset({
    "mitre_attack_techniques", "verdict_labels", "dns_lookups",
    "ip_traffic", "processes_created", "registry_keys_set",
})


def _is_vt_log(content: bytes) -> bool:
    """Return True if the uploaded bytes look like a VT behaviour_summary JSON."""
    try:
        parsed = json.loads(content)
        data = parsed.get("data", {})
        return isinstance(data, dict) and bool(_VT_SIGNATURE_KEYS & data.keys())
    except Exception:
        return False


def _enrich_vt_raw(vt_raw: dict) -> dict:
    """Extract enrichment fields from a raw VT behaviour_summary dict.

    Mirrors pipeline.enrich_with_virustotal() but takes the parsed dict
    directly so we don't need to write a temp file.
    """
    data = vt_raw.get("data", {})

    seen_ids: set = set()
    mitre: list = []
    for t in data.get("mitre_attack_techniques", []):
        tid = t.get("id", "")
        if tid and tid not in seen_ids:
            seen_ids.add(tid)
            mitre.append({
                "id":          tid,
                "description": t.get("signature_description", ""),
                "severity":    t.get("severity", ""),
            })

    processes = [p[:300] + ("…" if len(p) > 300 else "") for p in data.get("processes_created", [])]

    return {
        "verdict_labels":    data.get("verdict_labels", []),
        "mitre_techniques":  mitre,
        "dns_hostnames":     [e["hostname"] for e in data.get("dns_lookups", []) if "hostname" in e],
        "files_dropped":     data.get("files_dropped", []),
        "ip_addresses":      list({e["destination_ip"] for e in data.get("ip_traffic", []) if "destination_ip" in e}),
        "processes_created": processes,
        "registry_keys_set": [e["key"] for e in data.get("registry_keys_set", []) if "key" in e],
    }


def _fetch_vt_behavior(filepath: str, original_name: str, emit,
                        skip_event: "threading.Event | None" = None) -> dict | None:
    """Upload file to VirusTotal, poll for completion, return raw behaviour_summary.

    Emits {"event": "virustotal", ...} progress events throughout.
    Returns the raw parsed JSON dict, or None if unavailable/skipped.

    skip_event, if given, is checked between every poll — set it (via
    POST /jobs/{job_id}/skip-virustotal) to abandon a slow poll early and let
    the rest of the pipeline continue without VT enrichment. Waits use
    Event.wait(seconds) instead of time.sleep(seconds) so a skip takes effect
    immediately rather than only after the current wait finishes.
    """
    def _skipped() -> bool:
        if skip_event is not None and skip_event.is_set():
            emit({"event": "virustotal", "status": "skipped",
                  "message": "Skipped by user"})
            return True
        return False

    def _wait(seconds: float) -> bool:
        """Sleep up to `seconds`, waking early if skipped. Returns True if
        skipped — and, unlike _skipped() above, also emits the "skipped"
        status itself, since every call site just does `if _wait(n): return
        None` and would otherwise leave the frontend's node stuck on
        "running" forever with no signal that the backend moved on.
        """
        if skip_event is None:
            time.sleep(seconds)
            return False
        if skip_event.wait(seconds):
            emit({"event": "virustotal", "status": "skipped",
                  "message": "Skipped by user"})
            return True
        return False

    if not _VT_API_KEY:
        emit({"event": "virustotal", "status": "skipped",
              "message": "VT_API_KEY not configured — skipping VirusTotal enrichment"})
        return None

    if _skipped():
        return None

    try:
        # 0. VirusTotal aggregates submissions from everyone — a sample
        # doesn't have to be obscure to already be fully known; well-known
        # or previously-analyzed files are extremely common. Check for an
        # existing report by hash first: it's instant when present, and
        # re-uploading an already-known file can outright fail with a 409
        # "AlreadySubmittedError" instead of just being slow.
        with open(filepath, "rb") as fh:
            sha256 = hashlib.sha256(fh.read()).hexdigest()
        emit({"event": "virustotal", "status": "running",
              "message": f"Checking for an existing VT report ({sha256[:16]}...)..."})
        if _skipped():
            return None
        try:
            existing = requests.get(
                f"https://www.virustotal.com/api/v3/files/{sha256}/behaviour_summary",
                headers=_VT_HEADERS, timeout=30,
            )
            if existing.status_code == 200:
                emit({"event": "virustotal", "status": "complete",
                      "message": f"Existing report found — SHA256 {sha256[:16]}..."})
                return existing.json()
            if existing.status_code == 429:
                emit({"event": "virustotal", "status": "running",
                      "message": "[RATE LIMIT] VirusTotal throttled (429) on report lookup — continuing to fresh upload..."})
        except requests.RequestException:
            pass  # fall through to a fresh upload+scan below

        if _skipped():
            return None

        # 1. Upload specimen (no existing report — submit for a fresh scan)
        emit({"event": "virustotal", "status": "running",
              "message": "No existing report — uploading specimen to VirusTotal..."})
        with open(filepath, "rb") as fh:
            up = requests.post(
                "https://www.virustotal.com/api/v3/files",
                headers=_VT_HEADERS,
                files={"file": (original_name, fh)},
                timeout=120,
            )
        if up.status_code == 429:
            emit({"event": "virustotal", "status": "error",
                  "message": "[RATE LIMIT] VirusTotal API rate limit hit on upload (429) — try again later or check your API tier."})
            return None
        if up.status_code != 200:
            emit({"event": "virustotal", "status": "error",
                  "message": f"VT upload failed ({up.status_code}): {up.text[:120]}"})
            return None

        analysis_id = up.json()["data"]["id"]
        emit({"event": "virustotal", "status": "running",
              "message": f"Upload accepted — analysis ID {analysis_id[:16]}..."})

        # 2. Poll for AV scan completion (max ~10 min)
        file_hash: str | None = None
        for attempt in range(20):
            if _wait(30):
                return None
            check = requests.get(
                f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                headers=_VT_HEADERS, timeout=30,
            )
            if check.status_code == 429:
                emit({"event": "virustotal", "status": "running",
                      "message": f"[RATE LIMIT] VirusTotal throttled (429) during scan poll (attempt {attempt + 1}/20) — backing off..."})
                continue
            attrs  = check.json()["data"]["attributes"]
            status = attrs.get("status", "")
            emit({"event": "virustotal", "status": "running",
                  "message": f"AV scan status: {status} (poll {attempt + 1}/20)"})
            if status == "completed":
                file_hash = check.json().get("meta", {}).get("file_info", {}).get("sha256")
                break

        if not file_hash:
            emit({"event": "virustotal", "status": "error",
                  "message": "AV scan did not complete in time"})
            return None

        # 3. Wait for sandbox detonation then poll behaviour
        emit({"event": "virustotal", "status": "running",
              "message": "Waiting for sandbox detonation (60 s)..."})
        if _wait(60):
            return None

        behavior_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"
        for attempt in range(6):
            br = requests.get(behavior_url, headers=_VT_HEADERS, timeout=30)
            if br.status_code == 200:
                emit({"event": "virustotal", "status": "complete",
                      "message": f"Behavior log fetched — SHA256 {file_hash[:16]}..."})
                return br.json()
            if br.status_code == 429:
                emit({"event": "virustotal", "status": "running",
                      "message": f"[RATE LIMIT] VirusTotal throttled (429) fetching behavior log (attempt {attempt + 1}/6) — retrying in 60 s..."})
            else:
                emit({"event": "virustotal", "status": "running",
                      "message": f"Behavior logs not ready yet (attempt {attempt + 1}/6) — retrying in 60 s..."})
            if _wait(60):
                return None

        emit({"event": "virustotal", "status": "error",
              "message": "Behavior logs unavailable after all retries"})
        return None

    except Exception as exc:
        prefix = "[RATE LIMIT] " if _is_rate_limit_error(str(exc)) else ""
        emit({"event": "virustotal", "status": "error",
              "message": f"{prefix}VirusTotal error: {exc}"})
        return None


def _build_pipeline_input_from_vt(vt_raw: dict, original_name: str, content: bytes) -> dict:
    """Build pipeline metadata dict from a VT behaviour_summary JSON."""
    data = vt_raw.get("data", {})
    size_kb = round(len(content) / 1024, 2)
    sha256 = hashlib.sha256(content).hexdigest()

    indicators: list[str] = []
    for e in data.get("dns_lookups", []):
        if h := e.get("hostname"):
            indicators.append(h)
    for e in data.get("ip_traffic", []):
        if ip := e.get("destination_ip"):
            indicators.append(ip)
    for e in data.get("registry_keys_set", []):
        if k := e.get("key"):
            indicators.append(k)
    for p in data.get("processes_created", [])[:5]:
        indicators.append(str(p)[:120])

    return {
        "file_name":      original_name,
        "file_type":      "VT Behavior Log",
        "file_size_kb":   size_kb,
        "sha256":         sha256,
        "raw_indicators": list(dict.fromkeys(indicators))[:30],
    }


# ── Frontend paths ────────────────────────────────────────────────────────────
_OUT = Path(__file__).parent / "frontend" / "out"

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="UseProtection API", docs_url="/api/docs")

# CORS — origins from env var (comma-separated) so production can lock to the
# Cloudflare Pages domain without a code change.
# Local default: "*" (open). Railway: set ALLOWED_ORIGINS=https://your-app.pages.dev
_raw_origins = os.getenv("ALLOWED_ORIGINS", "*")
_ALLOWED_ORIGINS: list[str] = (
    ["*"] if _raw_origins.strip() == "*"
    else [o.strip() for o in _raw_origins.split(",") if o.strip()]
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=False,   # no auth cookies — wildcard-safe
    allow_methods=["*"],
    allow_headers=["*"],
)

# Serve Next.js static chunks (_next/static/…)
if (_OUT / "_next").exists():
    app.mount("/_next", StaticFiles(directory=str(_OUT / "_next")), name="nextjs-chunks")

# ── In-memory job registries ──────────────────────────────────────────────────
_jobs: dict[str, queue.Queue] = {}
_sandbox_jobs: dict[str, queue.Queue] = {}
# filepath kept after main analysis so sandbox can use it (cleaned up by sandbox job)
_sandbox_files: dict[str, str] = {}
# set by POST /jobs/{job_id}/skip-virustotal — lets a slow VT poll be cut short
_vt_skip_events: dict[str, threading.Event] = {}
# keyed by the main upload job_id (not sandbox_job_id) — created when
# /sandbox/start/{job_id} launches an adaptive run, set when that run
# finishes. _run_job waits on this before its own Gemini-calling report
# stage, so the sandbox's Gemini patch loop and the report pipeline's
# Gemini calls never run at the same time. Absence from this dict means
# no sandbox run was started for that job at all (e.g. vt_log mode).
_sandbox_done_events: dict[str, threading.Event] = {}

# ── Extension normalisation ───────────────────────────────────────────────────
# Suffixes people append to malware samples to make them "safe" to store/share.
_SAFETY_SUFFIXES = {
    ".malicious", ".malware", ".mal", ".virus", ".vir", ".infected",
    ".safe", ".sample", ".bad", ".disabled", ".quarantine", ".suspect",
    ".bak", ".orig",
}

_EXT_TO_TYPE = {
    ".js":  "JavaScript",
    ".jse": "JavaScript",
    ".exe": "Executable",
    ".dll": "DLL",
    ".ps1": "PowerShell",
    ".psm1": "PowerShell",
    ".vbs": "VBScript",
    ".vbe": "VBScript",
    ".bat": "Batch",
    ".cmd": "Batch",
    ".py":  "Python",
    ".msi": "Installer",
    ".hta": "HTA",
    ".wsf": "WSF",
}


def _resolve_true_extension(filename: str) -> str:
    """Strip known safety-label suffixes to get the real file extension.

    Examples:
      malware.js.malicious  →  .js
      dropper.exe.safe      →  .exe
      script.js             →  .js
      unknown.bin           →  .bin
    """
    p = Path(filename)
    while p.suffix.lower() in _SAFETY_SUFFIXES:
        p = Path(p.stem)
    return p.suffix.lower() or ".bin"


def _build_pipeline_input(filepath: str, analysis: dict, original_name: str | None = None) -> dict:
    """Map analyze_file() output to the dict expected by run_pipeline()."""
    display_name = original_name or Path(filepath).name
    size_kb = round(Path(filepath).stat().st_size / 1024, 2)

    with open(filepath, "rb") as fh:
        sha256 = hashlib.sha256(fh.read()).hexdigest()

    seen: set = set()
    raw_indicators: list[str] = []
    for item in (
        analysis.get("dangerous_functions", [])
        + analysis.get("urls_found", [])
        + analysis.get("ips_found", [])
        + analysis.get("behaviors", [])
    ):
        if item and item not in seen:
            seen.add(item)
            raw_indicators.append(item)

    true_ext = _resolve_true_extension(display_name)
    return {
        "file_name":     display_name,
        "file_type":     _EXT_TO_TYPE.get(true_ext, "Unknown"),
        "file_size_kb":  size_kb,
        "sha256":        sha256,
        "raw_indicators": raw_indicators[:30],
    }


# ── Background analysis job ───────────────────────────────────────────────────
def _run_job(
    job_id: str,
    filepath: str,
    original_name: str | None = None,
    mode: str = "malware",          # "malware" | "vt_log"
    run_mode: str = "full",         # "full" | "static_only" — stop after stage 0
) -> None:
    """Runs in a daemon thread; pushes JSON-serialisable dicts to the queue.

    mode="malware"  → static analysis + live VT API call + Claude pipeline
    mode="vt_log"   → parse uploaded VT JSON directly + Claude pipeline
                      (skips static analysis and VT API call)

    run_mode="full"        → everything, including the Claude/Gemini report agents
    run_mode="static_only" → stop after static analysis + VirusTotal — no AI
                              report stages, for a faster/cheaper raw-findings-only run
    """
    q = _jobs[job_id]

    def emit(event: dict) -> None:
        q.put(event)
        print(f"[queue PUT] job={job_id[:8]} event={event.get('event')!r}"
              f"{' stage=' + str(event.get('stage')) if 'stage' in event else ''}")

    try:
        vt_data: dict | None = None

        if mode == "vt_log":
            # ── VT log uploaded directly ─────────────────────────────────────
            with open(filepath, "rb") as fh:
                content = fh.read()
            vt_raw = json.loads(content)
            vt_data = _enrich_vt_raw(vt_raw)
            emit({"event": "virustotal", "status": "complete",
                  "message": "VT behavior log loaded from uploaded file"})

            metadata = _build_pipeline_input_from_vt(vt_raw, original_name or "vt_log.json", content)

            vt_labels = vt_data.get("verdict_labels", [])
            vt_mitre_count = len(vt_data.get("mitre_techniques", []))
            tail = "Starting AI pipeline..." if run_mode != "static_only" else "Static/dynamic run — stopping here."
            emit({"event": "pipeline_start", "status": "running",
                  "message": f"VT log: {vt_labels} ({vt_mitre_count} MITRE techniques). {tail}",
                  "data": metadata})

        else:
            # ── Malware file uploaded ─────────────────────────────────────────
            # Stage 0 — sandbox static analysis and VirusTotal enrichment run
            # in parallel. They're independent (VT only needs filepath/
            # original_name, never the static analysis result), and VT's own
            # upload+poll loop can take minutes — no reason to make the user
            # sit through a few seconds of local analysis first.
            #
            # "sandbox_static_analysis" is named distinctly from the
            # "static_analysis" AI agent emitted later in the AI pipeline
            # (agents/pipeline.py) — they used to share one event name, which
            # made the AGENTS flowchart's STATIC ANALYSIS node falsely show
            # "complete" during this sandbox phase, long before the real
            # agent call ever ran.
            def _run_sandbox_static_analysis() -> dict:
                emit({"event": "sandbox_static_analysis", "status": "running",
                      "message": "Running static analysis (deobfuscation + IOC extraction)..."})
                result = analyze_file(filepath, emit=lambda msg, step, total: emit(
                    {"event": "static_analysis_step", "status": "running",
                     "message": msg, "step": step, "total": total}
                ))
                emit({"event": "sandbox_static_analysis", "status": "complete", "data": {
                    "threat_level":        result.get("threat_level", "UNKNOWN"),
                    "is_obfuscated":       result.get("is_obfuscated", False),
                    "entropy":             result.get("entropy", 0),
                    "behaviors":           result.get("behaviors", []),
                    "dangerous_functions": result.get("dangerous_functions", []),
                    "mitre_techniques":    result.get("mitre_techniques", []),
                    "urls_found":          result.get("urls_found", []),
                    "ips_found":           result.get("ips_found", []),
                    "registry_keys":       result.get("registry_keys", []),
                    "dropped_files":       result.get("dropped_files", []),
                }})
                return result

            vt_skip_event = threading.Event()
            _vt_skip_events[job_id] = vt_skip_event
            try:
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    analysis_future = pool.submit(_run_sandbox_static_analysis)
                    vt_future = pool.submit(_fetch_vt_behavior, filepath, original_name or "upload.bin",
                                             emit, vt_skip_event)
                    analysis = analysis_future.result()
                    vt_raw = vt_future.result()
            finally:
                _vt_skip_events.pop(job_id, None)

            metadata = _build_pipeline_input(filepath, analysis, original_name)
            vt_data = _enrich_vt_raw(vt_raw) if vt_raw else None

            vt_labels = (vt_data or {}).get("verdict_labels", [])
            vt_mitre_count = len((vt_data or {}).get("mitre_techniques", []))
            tail = "Starting AI pipeline..." if run_mode != "static_only" else "Static/dynamic run — stopping here."
            if vt_data:
                msg = f"VirusTotal: {vt_labels} ({vt_mitre_count} MITRE techniques). {tail}"
            else:
                msg = f"Static analysis complete. {tail}"
            emit({"event": "pipeline_start", "status": "running",
                  "message": msg, "data": metadata})

        if run_mode == "static_only":
            # Static analysis + VirusTotal only — no AI report stages. Cheaper
            # and faster when you just want the raw findings, not a narrative
            # report. The frontend never sees `report_stage` events, so its
            # Reports widget simply never appears — the Agents flowchart and
            # Raw Logs already show everything this run produced.
            emit({"event": "done", "status": "complete",
                  "data": {"report": {}, "run_mode": "static_only"}})
            return

        # The dashboard auto-starts an e2b adaptive sandbox run for this same
        # job_id right after upload (see LinuxSandboxPanel's autoStart), and
        # that loop calls Gemini on every crash to generate a patch. Without
        # this wait, its Gemini calls and the report stage below's Gemini
        # calls run at the same time — GEMINI_LOCK only keeps them from
        # literally overlapping mid-request, not from both being "in
        # progress" together. Give /sandbox/start a brief window to register
        # (it's called within ~1s of upload, well inside the time static
        # analysis + VT just took), then wait for it to finish — capped so a
        # sandbox run paused on human-in-the-loop input can't block the
        # report forever.
        if mode == "malware":
            sandbox_event = None
            for _ in range(25):  # ~5s grace period
                sandbox_event = _sandbox_done_events.get(job_id)
                if sandbox_event is not None:
                    break
                time.sleep(0.2)
            if sandbox_event is not None and not sandbox_event.is_set():
                emit({"event": "pipeline_start", "status": "running",
                      "message": "Waiting for the sandbox run to finish before starting AI agents..."})
                sandbox_event.wait(timeout=360)

        # ── Stages 1-4 — Claude agents ────────────────────────────────────────
        result = run_pipeline(metadata, progress_cb=emit, vt_data=vt_data)
        emit({"event": "done", "status": "complete", "data": result})

    except Exception as exc:
        emit({"event": "error", "status": "error", "message": str(exc)})

    finally:
        pass  # file already registered in _sandbox_files at upload time


# ── Sandbox helpers ───────────────────────────────────────────────────────────

def _classify_sandbox_line(msg: str) -> tuple[str, dict | None]:
    """Classify a [MOCK...] log line → (tag, node) for the frontend graph."""
    tag = "sys" if msg.startswith("[SYSTEM]") else "info"
    node = None
    for pattern, ntype, _color, _ in _TAG_RULES:
        if pattern in msg:
            label = msg.split("] ", 1)[-1].strip()[:30] if "] " in msg else msg[:30]
            node = {"type": ntype, "label": label}
            tag = "crit" if ntype in ("EXEC", "NETWORK") else "warn" if ntype in (
                "REGISTRY", "FILE", "STREAM", "ACTIVEX", "WMI") else "info"
            break
    return tag, node


def _extract_failing_snippet(stderr_text: str, malware_filepath: str, mock_js: str) -> dict | None:
    """Pull the actual source around a Node crash's file:line, so a paused
    run shows real code instead of just an error string. malware.js comes
    from disk; mock.js only exists as the in-memory string we've been
    accumulating (it's never written to disk on this side)."""
    m = re.search(r'/home/user/(malware\.js|mock\.js):(\d+)', stderr_text)
    if not m:
        return None
    fname, line_no = m.group(1), int(m.group(2))
    try:
        if fname == "malware.js":
            with open(malware_filepath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = fh.readlines()
        else:
            lines = mock_js.splitlines(keepends=True)
    except Exception:
        return None
    if line_no < 1 or line_no > len(lines):
        return None
    start = max(0, line_no - 6)
    end = min(len(lines), line_no + 5)
    return {
        "file": fname,
        "line": line_no,
        "start_line": start + 1,
        "snippet": "".join(lines[start:end]),
    }


def _run_sandbox_job(sandbox_job_id: str, filepath: str, main_job_id: str) -> None:
    """Thin wrapper around _run_sandbox_job_impl that guarantees
    _sandbox_done_events[main_job_id] gets set on every exit path (normal
    finish, early return, or uncaught exception) — _run_job blocks on that
    event before starting its own Gemini-calling report stage.
    """
    try:
        _run_sandbox_job_impl(sandbox_job_id, filepath, main_job_id)
    finally:
        done_event = _sandbox_done_events.get(main_job_id)
        if done_event is not None:
            done_event.set()


def _run_sandbox_job_impl(sandbox_job_id: str, filepath: str, main_job_id: str) -> None:
    """Adaptive e2b sandbox loop — runs in a daemon thread, emits JSON events."""
    q = _sandbox_jobs[sandbox_job_id]
    ctrl = _sandbox_controls[sandbox_job_id]

    def emit(event: dict) -> None:
        q.put(event)

    def log(line: str, tag: str = "sys", node: dict | None = None) -> None:
        emit({"event": "sandbox_log", "line": line, "tag": tag, "node": node})

    if not _E2B_AVAILABLE:
        log("[ERROR] e2b / Gemini not installed in this environment.", "crit")
        emit({"event": "sandbox_done", "iterations": 0, "patch_file": None})
        return

    gemini_key = os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY", "")
    if not gemini_key:
        log("[ERROR] GEMINI_API_KEY / GOOGLE_API_KEY not set.", "crit")
        emit({"event": "sandbox_done", "iterations": 0, "patch_file": None})
        return

    # Timestamped patch file in testing/patches/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    patches_dir = Path(__file__).parent / "testing" / "patches"
    patches_dir.mkdir(parents=True, exist_ok=True)
    patches_path = patches_dir / f"patches_{timestamp}.js"

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            malware_js = fh.read()
    except Exception as exc:
        log(f"[ERROR] Cannot read malware file: {exc}", "crit")
        emit({"event": "sandbox_done", "iterations": 0, "patch_file": None})
        return

    malware_name = Path(filepath).name
    current_mock = _BASE_MOCK
    patches_applied: list[str] = []
    recent_error_hashes: list[str] = []

    log("[SYSTEM] e2b sandbox — Ubuntu 22.04 LTS x86_64")
    log(f"[SYSTEM] Mounting specimen → /home/user/{malware_name}")
    log("[SYSTEM] node --require mock.js malware.js 2>&1")
    log("[SYSTEM] Adaptive Simulation Layer Active.", "info")

    try:
        with _E2BSandbox.create() as sandbox:
            for iteration in range(1, _MAX_ITER + 1):
                if ctrl.end_requested:
                    log("[SYSTEM] Run ended by user.", "warn")
                    break

                log(f"[ADAPTIVE] Iteration {iteration} — running sandbox...", "sys")

                events, clean, stderr_text = _run_once(sandbox, current_mock, malware_js)

                for ev in events:
                    if ev.get("type") == "STDOUT":
                        msg = ev.get("data", "").strip()
                        if not msg:
                            continue
                        if "[MOCK" in msg or "[WSCRIPT" in msg or "[SYSTEM" in msg:
                            tag, node = _classify_sandbox_line(msg)
                            log(msg, tag, node)

                if clean:
                    log(f"[ADAPTIVE] Clean exit on iteration {iteration}.", "info")
                    break

                if not stderr_text.strip():
                    log("[ADAPTIVE] Non-zero exit, no stderr. Stopping.", "warn")
                    break

                mock_broke = "/home/user/mock.js" in stderr_text
                error_lines = re.findall(
                    r'(?:Reference|Type|Syntax|Range|URI|Eval)Error[^\n]*', stderr_text)
                actual_error = (error_lines[0].strip() if error_lines
                                else stderr_text.split("\n")[0][:200])

                err_hash = hashlib.md5(actual_error.encode()).hexdigest()
                recent_error_hashes.append(err_hash)
                stuck = (len(recent_error_hashes) >= _STUCK_THRESH
                         and len(set(recent_error_hashes[-_STUCK_THRESH:])) == 1)

                # Pause for a human either because we're genuinely stuck (3x
                # the same error — used to just give up here) or because the
                # user armed "take control on next failure" ahead of time.
                # Either way this blocks the thread on ctrl.resume_event
                # until /sandbox/{id}/continue or /sandbox/{id}/end wakes it.
                if stuck or ctrl.request_control:
                    reason = "stuck" if stuck else "user_requested"
                    ctrl.request_control = False  # one-shot, consumed now
                    log(f"[ADAPTIVE] Pausing for human input ({reason})...", "warn")
                    if _ask_gemini_to_diagnose:
                        try:
                            diagnosis = _ask_gemini_to_diagnose(stderr_text, current_mock, iteration)
                        except Exception as diag_exc:
                            diagnosis = f"(diagnosis unavailable: {diag_exc})"
                    else:
                        diagnosis = "(diagnosis unavailable — e2b module not loaded)"
                    snippet = _extract_failing_snippet(stderr_text, filepath, current_mock)
                    emit({
                        "event": "sandbox_awaiting_input",
                        "reason": reason,
                        "error": actual_error,
                        "diagnosis": diagnosis,
                        "iteration": iteration,
                        "snippet": snippet,
                    })
                    ctrl.resume_event.clear()
                    ctrl.resume_event.wait()  # blocks until /continue or /end
                    if ctrl.end_requested:
                        log("[SYSTEM] Run ended by user.", "warn")
                        break
                    emit({"event": "sandbox_resumed", "iteration": iteration})

                if iteration == _MAX_ITER:
                    log("[ADAPTIVE] Safety cap reached. Stopping.", "warn")
                    break

                origin = "mock.js" if mock_broke else "malware.js"
                log(f"[ADAPTIVE] Crash [{origin}]: {actual_error[:80]}", "crit")
                log("[ADAPTIVE] Asking Gemini to generate patch...", "sys")

                try:
                    patch = _ask_gemini_for_patch(
                        stderr_text, current_mock, iteration,
                        mock_broke=mock_broke, user_guidance=ctrl.guidance)
                except Exception as gemini_exc:
                    if _is_rate_limit_error(str(gemini_exc)):
                        log(f"[RATE LIMIT] Gemini API rate limit hit on iteration {iteration} — "
                            f"{str(gemini_exc)[:160]}", "warn")
                    else:
                        log(f"[ERROR] Gemini patch generation failed on iteration {iteration}: "
                            f"{str(gemini_exc)[:160]}", "crit")
                    break
                finally:
                    ctrl.guidance = None  # one-shot — don't bleed into later iterations
                patches_applied.append(patch)
                # Full replacement, not append — see ask_gemini_for_patch's
                # docstring. current_mock IS the file Gemini just returned.
                current_mock = patch

                # Overwrite (not append) with the latest complete mock.js —
                # by the time the loop ends this file is exactly the final,
                # clean, directly-usable version, not a log of fragments
                # that would redeclare things if actually concatenated.
                with open(patches_path, "w", encoding="utf-8") as pf:
                    pf.write(current_mock)

                emit({
                    "event": "sandbox_patch",
                    "iteration": iteration,
                    "line": (f"[ADAPTIVE] Patch {iteration} applied "
                             f"({len(patch)} chars) → {patches_path.name}"),
                    "tag": "info",
                    "mock_js": current_mock,
                })

    except Exception as exc:
        log(f"[ADAPTIVE] Fatal sandbox error: {exc}", "crit")

    log(
        f"[SYSTEM] ── simulation complete — {len(patches_applied)} patches"
        + (f" → {patches_path.name}" if patches_applied else "") + " ──",
        "info",
    )
    emit({
        "event": "sandbox_done",
        "iterations": len(patches_applied),
        "patch_file": patches_path.name if patches_applied else None,
    })
    _sandbox_controls.pop(sandbox_job_id, None)


# ── API routes ────────────────────────────────────────────────────────────────
@app.get("/health")
async def health():
    """Railway health check."""
    return {"status": "ok"}


@app.post("/upload")
async def upload_file(
    file: UploadFile,
    mode: str | None = Form(None),       # explicit override: "malware" | "vt_log"
    run_mode: str | None = Form(None),   # "full" (default) | "static_only"
):
    """Accept a malware file or a VirusTotal behaviour JSON, start the pipeline.

    The frontend can send mode="malware" or mode="vt_log" as a form field to
    force a specific path.  If omitted, the backend auto-detects by sniffing
    the file content.

    run_mode="static_only" stops after static analysis + VirusTotal, skipping
    the Claude/Gemini report agents — see _run_job for details.

    Returns {job_id, filename, mode}.
    """

    job_id = str(uuid.uuid4())
    original_name = file.filename or "upload.bin"
    content = await file.read()

    # Resolve mode: explicit > auto-detect
    if mode == "vt_log":
        resolved_mode = "vt_log"
        suffix = ".json"
    elif mode == "malware":
        resolved_mode = "malware"
        suffix = _resolve_true_extension(original_name)
    elif _is_vt_log(content):
        resolved_mode = "vt_log"
        suffix = ".json"
    else:
        resolved_mode = "malware"
        suffix = _resolve_true_extension(original_name)

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    # Register the file immediately so sandbox endpoints work without waiting for analysis.
    _sandbox_files[job_id] = tmp_path

    resolved_run_mode = run_mode if run_mode in ("full", "static_only") else "full"

    _jobs[job_id] = queue.Queue()
    threading.Thread(
        target=_run_job,
        args=(job_id, tmp_path, original_name, resolved_mode, resolved_run_mode),
        daemon=True,
    ).start()
    return {"job_id": job_id, "filename": original_name, "mode": resolved_mode}


@app.post("/jobs/{job_id}/skip-virustotal")
async def skip_virustotal(job_id: str):
    """Abandon a slow/stuck VirusTotal poll for this job and let the rest of
    the pipeline continue without it. No-op (but not an error) if VT already
    finished, was never started, or this job doesn't exist — skipping late is
    harmless either way.
    """
    event = _vt_skip_events.get(job_id)
    if event is not None:
        event.set()
    return {"skipped": event is not None}


@app.post("/sandbox/upload")
async def sandbox_upload(file: UploadFile):
    """Upload a file for sandbox-only use — no analysis pipeline started.

    Returns {job_id, filename} immediately. The file is stored in _sandbox_files
    so /sandbox/start and /sandbox/run-patch can use it.
    """
    job_id = str(uuid.uuid4())
    original_name = file.filename or "upload.bin"
    content = await file.read()
    suffix = _resolve_true_extension(original_name)

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    _sandbox_files[job_id] = tmp_path
    return {"job_id": job_id, "filename": original_name}


@app.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str) -> None:
    """Stream analysis progress events to the client."""
    await websocket.accept()

    if job_id not in _jobs:
        await websocket.send_json({"event": "error", "message": "Unknown job ID"})
        await websocket.close()
        return

    q = _jobs[job_id]
    loop = asyncio.get_event_loop()

    try:
        while True:
            try:
                event = await loop.run_in_executor(None, lambda: q.get(timeout=300))
            except queue.Empty:
                await websocket.send_json(
                    {"event": "error", "message": "Analysis timed out (300 s)"})
                break

            ename = event.get("event")
            print(f"[ws SEND]  job={job_id[:8]} event={ename!r}"
                  f"{' stage=' + str(event.get('stage')) if 'stage' in event else ''}")
            await websocket.send_json(event)
            if ename in ("done", "error"):
                break

    except WebSocketDisconnect:
        pass
    finally:
        _jobs.pop(job_id, None)


def _run_patch_job(sandbox_job_id: str, filepath: str, patch_content: str, main_job_id: str) -> None:
    """Single e2b run with a user-supplied patch as the mock layer — no Gemini loop."""
    q = _sandbox_jobs[sandbox_job_id]

    def emit(event: dict) -> None:
        q.put(event)

    def log(line: str, tag: str = "sys", node: dict | None = None) -> None:
        emit({"event": "sandbox_log", "line": line, "tag": tag, "node": node})

    if not _E2B_AVAILABLE:
        log("[ERROR] e2b not installed in this environment.", "crit")
        emit({"event": "sandbox_done", "iterations": 0, "patch_file": None})
        return

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            malware_js = fh.read()
    except Exception as exc:
        log(f"[ERROR] Cannot read malware file: {exc}", "crit")
        emit({"event": "sandbox_done", "iterations": 0, "patch_file": None})
        return

    malware_name = Path(filepath).name
    log("[SYSTEM] e2b sandbox — Ubuntu 22.04 LTS x86_64")
    log(f"[SYSTEM] Mounting specimen → /home/user/{malware_name}")
    log("[SYSTEM] Loading uploaded patch as mock layer...")
    log("[SYSTEM] node --require patch.js malware.js 2>&1")

    try:
        with _E2BSandbox.create() as sandbox:
            events, clean, stderr_text = _run_once(sandbox, patch_content, malware_js)

            for ev in events:
                if ev.get("type") == "STDOUT":
                    msg = ev.get("data", "").strip()
                    if not msg:
                        continue
                    if "[MOCK" in msg or "[WSCRIPT" in msg or "[SYSTEM" in msg:
                        tag, node = _classify_sandbox_line(msg)
                        log(msg, tag, node)

            if clean:
                log("[SYSTEM] ── clean exit — patch ran successfully ──", "info")
            else:
                log("[SYSTEM] ── non-zero exit — patch may be incomplete ──", "warn")
                if stderr_text.strip():
                    first_error = stderr_text.split("\n")[0][:120]
                    log(f"[ERROR] {first_error}", "crit")

    except Exception as exc:
        log(f"[ERROR] Sandbox error: {exc}", "crit")

    emit({"event": "sandbox_done", "iterations": 1, "patch_file": None})


@app.post("/sandbox/run-patch/{job_id}")
async def sandbox_run_patch(job_id: str, patch: UploadFile):
    """Run the malware once in e2b with an uploaded patch file as the mock layer."""
    filepath = _sandbox_files.get(job_id)
    if not filepath or not Path(filepath).exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="File not found for this job_id")

    patch_content = (await patch.read()).decode("utf-8", errors="ignore")
    sandbox_job_id = str(uuid.uuid4())
    _sandbox_jobs[sandbox_job_id] = queue.Queue()
    threading.Thread(
        target=_run_patch_job,
        args=(sandbox_job_id, filepath, patch_content, job_id),
        daemon=True,
    ).start()
    return {"sandbox_job_id": sandbox_job_id, "e2b_available": _E2B_AVAILABLE}


@app.post("/sandbox/start/{job_id}")
async def sandbox_start(job_id: str):
    """Start an adaptive e2b sandbox run for a previously uploaded file."""
    filepath = _sandbox_files.get(job_id)
    if not filepath or not Path(filepath).exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="File not found for this job_id")

    sandbox_job_id = str(uuid.uuid4())
    _sandbox_jobs[sandbox_job_id] = queue.Queue()
    # Created before the thread starts so /request-control, /continue and
    # /end can never 404 on a race against the thread not having set it up yet.
    _sandbox_controls[sandbox_job_id] = _SandboxControl()
    # Registers that an adaptive (Gemini-using) sandbox run is happening for
    # this upload job — _run_job waits on this before its own Gemini calls.
    _sandbox_done_events[job_id] = threading.Event()
    threading.Thread(
        target=_run_sandbox_job,
        args=(sandbox_job_id, filepath, job_id),
        daemon=True,
    ).start()
    return {"sandbox_job_id": sandbox_job_id, "e2b_available": _E2B_AVAILABLE}


def _get_sandbox_control(sandbox_job_id: str) -> "_SandboxControl":
    ctrl = _sandbox_controls.get(sandbox_job_id)
    if ctrl is None:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Unknown or already-finished sandbox run")
    return ctrl


@app.post("/sandbox/{sandbox_job_id}/request-control")
async def sandbox_request_control(sandbox_job_id: str):
    """Arm a one-shot pause: the *next* failure (not necessarily 3x the same
    error) will stop and wait for human input instead of auto-patching."""
    ctrl = _get_sandbox_control(sandbox_job_id)
    ctrl.request_control = True
    return {"ok": True}


@app.post("/sandbox/{sandbox_job_id}/continue")
async def sandbox_continue(sandbox_job_id: str, guidance: str | None = None):
    """Resume a paused adaptive run, optionally steering the next patch with
    free-text guidance (see ask_gemini_for_patch's user_guidance param)."""
    ctrl = _get_sandbox_control(sandbox_job_id)
    ctrl.guidance = guidance or None
    ctrl.resume_event.set()
    return {"ok": True}


@app.post("/sandbox/{sandbox_job_id}/end")
async def sandbox_end(sandbox_job_id: str):
    """Stop an adaptive run immediately — whether it's mid-iteration or
    currently paused waiting on human input."""
    ctrl = _get_sandbox_control(sandbox_job_id)
    ctrl.end_requested = True
    ctrl.resume_event.set()  # wake it up if it's currently paused
    return {"ok": True}


@app.websocket("/ws/sandbox/{sandbox_job_id}")
async def sandbox_websocket(websocket: WebSocket, sandbox_job_id: str) -> None:
    """Stream adaptive sandbox events to the client."""
    await websocket.accept()

    if sandbox_job_id not in _sandbox_jobs:
        await websocket.send_json({"event": "sandbox_error", "message": "Unknown sandbox job ID"})
        await websocket.close()
        return

    q = _sandbox_jobs[sandbox_job_id]
    loop = asyncio.get_event_loop()

    try:
        while True:
            try:
                # Generous — a human-in-the-loop pause can legitimately sit
                # idle for a while (reading the diagnosis, typing guidance)
                # without the run actually being stuck or dead.
                event = await loop.run_in_executor(None, lambda: q.get(timeout=3600))
            except queue.Empty:
                await websocket.send_json(
                    {"event": "sandbox_error", "message": "Sandbox timed out (3600 s)"})
                break

            await websocket.send_json(event)
            if event.get("event") in ("sandbox_done", "sandbox_error"):
                break

    except WebSocketDisconnect:
        pass
    finally:
        _sandbox_jobs.pop(sandbox_job_id, None)


@app.get("/sandbox/patches/{filename}")
async def download_patch(filename: str):
    """Download a Gemini-generated patch file from testing/patches/."""
    from fastapi import HTTPException
    # Prevent path traversal
    safe_name = Path(filename).name
    patch_path = Path(__file__).parent / "testing" / "patches" / safe_name
    if not patch_path.exists():
        raise HTTPException(status_code=404, detail="Patch file not found")
    return FileResponse(str(patch_path), filename=safe_name, media_type="application/javascript")


# ── Sample malware library ────────────────────────────────────────────────────
_SAMPLES_DIR = Path(__file__).parent / "testing" / "samples"
_RESULTS_DIR = Path(__file__).parent / "testing" / "results"


@app.get("/samples", include_in_schema=True)
async def list_samples():
    """Return a list of sample malware filenames available for analysis."""
    if not _SAMPLES_DIR.exists():
        return {"samples": []}
    names = [f.name for f in sorted(_SAMPLES_DIR.iterdir()) if f.is_file()]
    return {"samples": names}


@app.get("/samples/{filename}", include_in_schema=True)
async def get_sample(filename: str):
    """Serve a single sample file for the frontend to load."""
    safe = _SAMPLES_DIR / Path(filename).name
    if not safe.exists() or not safe.is_file():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Sample not found")
    return FileResponse(str(safe), filename=safe.name)


@app.get("/results", include_in_schema=True)
async def list_results():
    """Return a list of pre-saved VT behaviour log filenames."""
    if not _RESULTS_DIR.exists():
        return {"results": []}
    names = [f.name for f in sorted(_RESULTS_DIR.iterdir()) if f.is_file() and f.suffix == ".json"]
    return {"results": names}


@app.get("/results/{filename}", include_in_schema=True)
async def get_result(filename: str):
    """Serve a single pre-saved VT behaviour log."""
    safe = _RESULTS_DIR / Path(filename).name
    if not safe.exists() or not safe.is_file():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Result not found")
    return FileResponse(str(safe), filename=safe.name, media_type="application/json")


# ── Frontend routes ───────────────────────────────────────────────────────────
# These must come AFTER the API routes so FastAPI resolves /upload and /ws first.

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    f = _OUT / "favicon.ico"
    return FileResponse(str(f)) if f.exists() else HTMLResponse("", status_code=204)


@app.get("/dashboard", include_in_schema=False)
@app.get("/dashboard/", include_in_schema=False)
async def dashboard_page():
    return FileResponse(str(_OUT / "dashboard" / "index.html"))


@app.get("/", include_in_schema=False)
async def root():
    return FileResponse(str(_OUT / "index.html"))


# Catch-all: serve any other static file from out/ (images, manifests, etc.)
# Falls back to 404.html for unknown paths.
@app.get("/{full_path:path}", include_in_schema=False)
async def static_fallback(full_path: str):
    candidate = _OUT / full_path
    if candidate.is_file():
        return FileResponse(str(candidate))
    not_found = _OUT / "404.html"
    if not_found.exists():
        return FileResponse(str(not_found), status_code=404)
    return HTMLResponse("<h1>404</h1>", status_code=404)
