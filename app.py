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
{event: "static_analysis",  status: "running"|"complete", message?, data?}
{event: "pipeline_start",   status: "running",            message,  data}
{event: "ingestion",        status: "running"|"complete", message?, data?}
{event: "static_analysis",  status: "running"|"complete", message?, data?}
{event: "mitre_mapping",    status: "running"|"complete", message?, data?}
{event: "remediation",      status: "running"|"complete", message?, data?}
{event: "report",           status: "running"|"complete", message?, data?}
{event: "done",             status: "complete",           data: full_result}
{event: "error",            status: "error",              message: str}
"""
import asyncio
import hashlib
import os
import queue
import re
import sys
import tempfile
import threading
import types as _types
import uuid
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, WebSocket, WebSocketDisconnect
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
# Mock heavy deps so the testing module can be imported without networkx/matplotlib
for _mod in ("networkx", "matplotlib", "matplotlib.pyplot", "matplotlib.patches"):
    sys.modules.setdefault(_mod, _types.ModuleType(_mod))

_E2B_AVAILABLE = False
_ask_gemini_for_patch = None
_run_once = None
_TAG_RULES: list = []
_BASE_MOCK = "console.log('[SYSTEM] Bare sandbox started.');\n"
_MAX_ITER = 50
_STUCK_THRESH = 3
_RUN_TIMEOUT = 45

try:
    _testing_dir = str(Path(__file__).parent / "testing")
    if _testing_dir not in sys.path:
        sys.path.insert(0, _testing_dir)
    from e2b_adaptive_sandbox import (          # type: ignore[import]
        ask_gemini_for_patch as _ask_gemini_for_patch,
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

# Path to optional VirusTotal behavior dump — present during demos
_VT_PATH = Path(__file__).parent / "malware_behavior.json"

# ── Frontend paths ────────────────────────────────────────────────────────────
_OUT = Path(__file__).parent / "frontend" / "out"

# ── App ───────────────────────────────────────────────────────────────────────
app = FastAPI(title="UseProtection API", docs_url="/api/docs")

# CORS — allow the Next.js dev server (port 3000) during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
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

# ── Adapter: sandbox/analyze.py output → agents/pipeline.py input ────────────
_EXT_TO_TYPE = {
    ".js":  "JavaScript",
    ".exe": "Executable",
    ".ps1": "PowerShell",
    ".vbs": "VBScript",
    ".bat": "Batch",
    ".dll": "DLL",
    ".py":  "Python",
    ".msi": "Installer",
}


def _build_pipeline_input(filepath: str, analysis: dict) -> dict:
    """Map analyze_file() output to the dict expected by run_pipeline()."""
    name = Path(filepath).name
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

    return {
        "file_name":     name,
        "file_type":     _EXT_TO_TYPE.get(Path(filepath).suffix.lower(), "Unknown"),
        "file_size_kb":  size_kb,
        "sha256":        sha256,
        "raw_indicators": raw_indicators[:30],
    }


# ── Background analysis job ───────────────────────────────────────────────────
def _run_job(job_id: str, filepath: str) -> None:
    """Runs in a daemon thread; pushes JSON-serialisable dicts to the queue."""
    q = _jobs[job_id]

    def emit(event: dict) -> None:
        q.put(event)
        print(f"[queue PUT] job={job_id[:8]} event={event.get('event')!r}"
              f"{' stage=' + str(event.get('stage')) if 'stage' in event else ''}")

    try:
        # Stage 0 — static analysis (sandbox/analyze.py)
        emit({"event": "static_analysis", "status": "running",
              "message": "Running static analysis (deobfuscation + IOC extraction)..."})
        analysis = analyze_file(filepath)
        emit({"event": "static_analysis", "status": "complete", "data": {
            "threat_level":        analysis.get("threat_level", "UNKNOWN"),
            "is_obfuscated":       analysis.get("is_obfuscated", False),
            "entropy":             analysis.get("entropy", 0),
            "behaviors":           analysis.get("behaviors", []),
            "dangerous_functions": analysis.get("dangerous_functions", []),
            "mitre_techniques":    analysis.get("mitre_techniques", []),
            "urls_found":          analysis.get("urls_found", []),
            "ips_found":           analysis.get("ips_found", []),
            "registry_keys":       analysis.get("registry_keys", []),
            "dropped_files":       analysis.get("dropped_files", []),
        }})

        # Hand off to Claude pipeline
        metadata = _build_pipeline_input(filepath, analysis)

        # Optional VirusTotal enrichment — load malware_behavior.json if present
        vt_data = None
        if _VT_PATH.exists():
            try:
                vt_data = enrich_with_virustotal(str(_VT_PATH))
                vt_labels = vt_data.get("verdict_labels", [])
                vt_mitre_count = len(vt_data.get("mitre_techniques", []))
                emit({"event": "pipeline_start", "status": "running",
                      "message": (
                          f"VirusTotal enrichment loaded — {vt_labels} "
                          f"({vt_mitre_count} MITRE techniques). Starting AI pipeline..."
                      ),
                      "data": metadata})
            except Exception as vt_exc:
                vt_data = None
                emit({"event": "pipeline_start", "status": "running",
                      "message": f"Static analysis complete — starting AI agent pipeline... (VT load failed: {vt_exc})",
                      "data": metadata})
        else:
            emit({"event": "pipeline_start", "status": "running",
                  "message": "Static analysis complete — starting AI agent pipeline...",
                  "data": metadata})

        # Stages 1-4 — Claude agents (progress_cb forwards events directly)
        result = run_pipeline(metadata, progress_cb=emit, vt_data=vt_data)

        emit({"event": "done", "status": "complete", "data": result})

    except Exception as exc:
        emit({"event": "error", "status": "error", "message": str(exc)})

    finally:
        # Keep file around so /sandbox/start/{job_id} can use it.
        # The sandbox job (or GC) is responsible for deletion.
        _sandbox_files[job_id] = filepath


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


def _run_sandbox_job(sandbox_job_id: str, filepath: str, main_job_id: str) -> None:
    """Adaptive e2b sandbox loop — runs in a daemon thread, emits JSON events."""
    q = _sandbox_jobs[sandbox_job_id]

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

    # Timestamped patch file in testing/
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    testing_dir = Path(__file__).parent / "testing"
    testing_dir.mkdir(exist_ok=True)
    patches_path = testing_dir / f"patches_{timestamp}.js"

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
                if (len(recent_error_hashes) >= _STUCK_THRESH
                        and len(set(recent_error_hashes[-_STUCK_THRESH:])) == 1):
                    log(f"[ADAPTIVE] Stuck on same error × {_STUCK_THRESH}. Stopping.", "warn")
                    break

                if iteration == _MAX_ITER:
                    log("[ADAPTIVE] Safety cap reached. Stopping.", "warn")
                    break

                origin = "mock.js" if mock_broke else "malware.js"
                log(f"[ADAPTIVE] Crash [{origin}]: {actual_error[:80]}", "crit")
                log("[ADAPTIVE] Asking Gemini to generate patch...", "sys")

                patch = _ask_gemini_for_patch(
                    stderr_text, current_mock, iteration, mock_broke=mock_broke)
                patches_applied.append(patch)
                current_mock = (current_mock
                                + f"\n\n// === AUTO-PATCH (iteration {iteration}) ===\n"
                                + patch)

                # Append patch to timestamped file immediately
                with open(patches_path, "a", encoding="utf-8") as pf:
                    pf.write(f"// === Patch {iteration} ===\n{patch}\n\n")

                emit({
                    "event": "sandbox_patch",
                    "iteration": iteration,
                    "line": (f"[ADAPTIVE] Patch {iteration} applied "
                             f"({len(patch)} chars) → {patches_path.name}"),
                    "tag": "info",
                })

    except Exception as exc:
        log(f"[ADAPTIVE] Fatal sandbox error: {exc}", "crit")

    finally:
        # Clean up the kept file
        _sandbox_files.pop(main_job_id, None)
        try:
            os.unlink(filepath)
        except OSError:
            pass

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


# ── API routes ────────────────────────────────────────────────────────────────
@app.post("/upload")
async def upload_file(file: UploadFile):
    """Accept a suspicious file, start the analysis pipeline, return a job_id."""
    job_id = str(uuid.uuid4())
    suffix = Path(file.filename or "upload.bin").suffix or ".bin"
    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as tmp:
        tmp.write(await file.read())
        tmp_path = tmp.name

    _jobs[job_id] = queue.Queue()
    threading.Thread(target=_run_job, args=(job_id, tmp_path), daemon=True).start()
    return {"job_id": job_id, "filename": file.filename}


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


@app.post("/sandbox/start/{job_id}")
async def sandbox_start(job_id: str):
    """Start an adaptive e2b sandbox run for a previously uploaded file."""
    filepath = _sandbox_files.get(job_id)
    if not filepath or not Path(filepath).exists():
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="File not found for this job_id")

    sandbox_job_id = str(uuid.uuid4())
    _sandbox_jobs[sandbox_job_id] = queue.Queue()
    threading.Thread(
        target=_run_sandbox_job,
        args=(sandbox_job_id, filepath, job_id),
        daemon=True,
    ).start()
    return {"sandbox_job_id": sandbox_job_id, "e2b_available": _E2B_AVAILABLE}


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
                event = await loop.run_in_executor(None, lambda: q.get(timeout=600))
            except queue.Empty:
                await websocket.send_json(
                    {"event": "sandbox_error", "message": "Sandbox timed out (600 s)"})
                break

            await websocket.send_json(event)
            if event.get("event") in ("sandbox_done", "sandbox_error"):
                break

    except WebSocketDisconnect:
        pass
    finally:
        _sandbox_jobs.pop(sandbox_job_id, None)


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
