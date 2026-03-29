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
import tempfile
import threading
import uuid
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

# ── In-memory job registry ────────────────────────────────────────────────────
_jobs: dict[str, queue.Queue] = {}

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
        try:
            os.unlink(filepath)
        except OSError:
            pass


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
