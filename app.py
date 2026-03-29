"""MalwareScope FastAPI backend.

Endpoints:
  POST /upload          — accept a file, kick off analysis, return {job_id}
  GET  /ws/{job_id}     — WebSocket: stream progress events until done/error
  GET  /                — serve the frontend
"""
import hashlib
import os
import queue
import sys
import tempfile
import threading
import uuid
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

# ---------------------------------------------------------------------------
# Environment — load root .env first, then agents/.env (agents key wins if
# the root one doesn't have it, which is the common dev setup here)
# ---------------------------------------------------------------------------
load_dotenv()
_agents_env = Path(__file__).parent / "agents" / ".env"
if _agents_env.exists():
    load_dotenv(_agents_env, override=False)

# ---------------------------------------------------------------------------
# Add sandbox/ to sys.path so we can import its analyze module directly
# without it being a package.
# ---------------------------------------------------------------------------
_sandbox_path = str(Path(__file__).parent / "sandbox")
if _sandbox_path not in sys.path:
    sys.path.insert(0, _sandbox_path)

# Deferred imports — keep startup fast and surface import errors clearly
from analyze import analyze_js  # noqa: E402  (sandbox/analyze.py)
from agents.pipeline import run_pipeline  # noqa: E402

# ---------------------------------------------------------------------------
app = FastAPI(title="MalwareScope API")

# Static files (frontend)
_static_dir = Path(__file__).parent / "static"
_static_dir.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory=str(_static_dir)), name="static")

# In-memory job registry: job_id -> queue.Queue
_jobs: dict[str, queue.Queue] = {}


# ---------------------------------------------------------------------------
# Adapter: bridge sandbox/analyze.py output → agents/pipeline.py input
# ---------------------------------------------------------------------------
_EXT_TO_TYPE = {
    ".js": "JavaScript",
    ".exe": "Executable",
    ".ps1": "PowerShell",
    ".vbs": "VBScript",
    ".bat": "Batch",
    ".dll": "DLL",
    ".py": "Python",
}


def _build_pipeline_input(filepath: str, analysis: dict) -> dict:
    """Map analyze_js() output to the dict expected by run_pipeline()."""
    name = Path(filepath).name
    size_kb = round(Path(filepath).stat().st_size / 1024, 2)

    with open(filepath, "rb") as fh:
        sha256 = hashlib.sha256(fh.read()).hexdigest()

    # Merge all indicator lists; deduplicate while preserving order
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
    raw_indicators = raw_indicators[:30]  # stay within token budget

    ext = Path(filepath).suffix.lower()
    file_type = _EXT_TO_TYPE.get(ext, "Unknown")

    return {
        "file_name": name,
        "file_type": file_type,
        "file_size_kb": size_kb,
        "sha256": sha256,
        "raw_indicators": raw_indicators,
    }


# ---------------------------------------------------------------------------
# Background analysis job
# ---------------------------------------------------------------------------
def _run_job(job_id: str, filepath: str) -> None:
    """Runs in a background thread. Pushes events to the job queue."""
    q = _jobs[job_id]

    def emit(event: dict) -> None:
        q.put(event)

    try:
        # ── Stage 0: static analysis ────────────────────────────────────────
        emit({
            "event": "static_analysis",
            "status": "running",
            "message": "Running static JS analysis (deobfuscation + IOC extraction)...",
        })
        analysis = analyze_js(filepath)
        emit({
            "event": "static_analysis",
            "status": "complete",
            "data": {
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
            },
        })

        # ── Build pipeline input ─────────────────────────────────────────────
        metadata = _build_pipeline_input(filepath, analysis)
        emit({
            "event": "pipeline_start",
            "status": "running",
            "message": "Static analysis complete — handing off to AI agent pipeline...",
            "data": metadata,
        })

        # ── Stages 1-4: Claude agent pipeline ───────────────────────────────
        result = run_pipeline(metadata, progress_cb=emit)

        emit({"event": "done", "status": "complete", "data": result})

    except Exception as exc:
        emit({"event": "error", "status": "error", "message": str(exc)})

    finally:
        try:
            os.unlink(filepath)
        except OSError:
            pass


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.get("/")
async def root() -> FileResponse:
    return FileResponse(str(_static_dir / "index.html"))


@app.post("/upload")
async def upload_file(file: UploadFile):
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
    await websocket.accept()

    if job_id not in _jobs:
        await websocket.send_json({"event": "error", "message": "Unknown job ID"})
        await websocket.close()
        return

    q = _jobs[job_id]
    import asyncio

    loop = asyncio.get_event_loop()

    try:
        while True:
            try:
                event = await loop.run_in_executor(
                    None, lambda: q.get(timeout=300)
                )
            except queue.Empty:
                await websocket.send_json({
                    "event": "error",
                    "message": "Analysis timed out (300 s)",
                })
                break

            await websocket.send_json(event)

            if event.get("event") in ("done", "error"):
                break

    except WebSocketDisconnect:
        pass
    finally:
        _jobs.pop(job_id, None)
