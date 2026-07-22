import sys
import os
import json
import tempfile
import subprocess
import uuid
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sandbox'))

from fastapi import FastAPI, UploadFile, File, HTTPException, Response, BackgroundTasks, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import anthropic
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'sandbox', '.env'))

try:
    from analyze import analyze_file
except ImportError as e:
    print(f"Warning: could not import analyze_file: {e}")
    analyze_file = None

try:
    from hybrid_analysis import analyze as ha_analyze
except ImportError:
    ha_analyze = None

try:
    from pipeline import run_pipeline
except ImportError as e:
    print(f"Warning: could not import run_pipeline: {e}")
    run_pipeline = None

HA_API_KEY = os.getenv("HYBRID_ANALYSIS_API_KEY", "")

app = FastAPI(title="UseProtechtion Malware Analysis API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

SANDBOX_IMAGE = "useprotection-sandbox"
SANDBOX_DIR   = os.path.join(os.path.dirname(__file__), '..', 'sandbox')

# Reject absurdly large uploads before they hit disk/analysis.
MAX_UPLOAD_BYTES = 100 * 1024 * 1024  # 100 MB


# ── Docker dynamic analysis ────────────────────────────────────────────────────

def docker_available() -> bool:
    try:
        subprocess.run(['docker', 'info'], capture_output=True, timeout=5)
        return True
    except Exception:
        return False


def image_built() -> bool:
    try:
        r = subprocess.run(
            ['docker', 'image', 'inspect', SANDBOX_IMAGE],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


def build_image() -> bool:
    """Build the sandbox Docker image if it doesn't exist."""
    try:
        r = subprocess.run(
            ['docker', 'build', '-t', SANDBOX_IMAGE, '.'],
            capture_output=True, text=True, timeout=300,
            cwd=SANDBOX_DIR
        )
        return r.returncode == 0
    except Exception:
        return False


def run_static_in_docker(filepath: str) -> dict | None:
    """Run analyze.py inside the sandbox container."""
    try:
        r = subprocess.run([
            'docker', 'run', '--rm',
            '--network=none',
            '--memory=512m',
            '--cpus=1',
            '-v', f'{filepath}:/analysis/sample',
            SANDBOX_IMAGE,
            '/analysis/sample',
        ], capture_output=True, text=True, timeout=120)

        if r.returncode == 0 and r.stdout.strip():
            return json.loads(r.stdout)
        print(f"Docker static error: {r.stderr[:500]}")
    except Exception as e:
        print(f"Docker static exception: {e}")
    return None


def run_dynamic_in_docker(filepath: str, filename: str) -> dict | None:
    """Run dynamic_analyze.js inside the sandbox container (JS/script files only)."""
    ext = filename.lower().rsplit('.', 1)[-1] if '.' in filename else ''
    if ext not in ('js', 'jse', 'vbs', 'vbe', 'wsf', 'hta'):
        return None

    try:
        r = subprocess.run([
            'docker', 'run', '--rm',
            '--network=none',
            '--memory=256m',
            '--cpus=0.5',
            '-v', f'{filepath}:/analysis/sample.js',
            '--entrypoint', 'node',
            SANDBOX_IMAGE,
            '/analysis/dynamic_analyze.js',
            '/analysis/sample.js',
        ], capture_output=True, text=True, timeout=30)

        if r.stdout.strip():
            return json.loads(r.stdout)
        print(f"Docker dynamic error: {r.stderr[:500]}")
    except Exception as e:
        print(f"Docker dynamic exception: {e}")
    return None


# ── Claude AI report ───────────────────────────────────────────────────────────

def call_claude_report(file_meta: dict) -> dict:
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=2000,
        system="""You are a senior malware analyst. Given static and dynamic analysis results, generate a concise threat report.
Output valid JSON only. No markdown, no explanation.
Format:
{
  "malware_type": "RANSOMWARE | DROPPER | LOADER | INFOSTEALER | RAT | DOWNLOADER | BACKDOOR",
  "risk_score": 85,
  "confidence": 0.9,
  "executive_summary": "3 sentence technical explanation of the threat and kill chain",
  "mitre_techniques": [{"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"}],
  "iocs": ["list of IPs, domains, hashes"],
  "yara_rule": "compact YARA rule string",
  "action_plan": [{"priority": 1, "action": "immediate isolation step"}]
}""",
        messages=[{
            "role": "user",
            "content": f"Analyze this malware report:\n{json.dumps(file_meta, indent=2)}"
        }]
    )

    text = response.content[0].text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])
    return json.loads(text)


# ── Endpoints ─────────────────────────────────────────────────────────────────

job_queues = {}
job_loops = {}

@app.get("/")
def root():
    return {"message": "Welcome to the UseProtechtion Malware Analysis API"}

@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(content=b"", media_type="image/x-icon")

@app.get("/health")
def health():
    use_docker = docker_available() and image_built()
    return {
        "status":           "ok",
        "docker":           use_docker,
        "static_analysis":  analyze_file is not None,
        "hybrid_analysis":  bool(HA_API_KEY),
        "anthropic":        bool(os.getenv("ANTHROPIC_API_KEY")),
    }


@app.post("/build-image")
def build_sandbox_image():
    """Build the Docker sandbox image. Call once before first analysis."""
    if not docker_available():
        raise HTTPException(status_code=500, detail="Docker not available")
    ok = build_image()
    if not ok:
        raise HTTPException(status_code=500, detail="Image build failed")
    return {"status": "built"}


@app.post("/upload")
@app.post("/analyze")
async def analyze(background_tasks: BackgroundTasks, file: UploadFile = File(...)):
    job_id = str(uuid.uuid4())
    job_queues[job_id] = asyncio.Queue()
    job_loops[job_id] = asyncio.get_running_loop()

    suffix = f"_{file.filename}" if file.filename else ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        total = 0
        while True:
            chunk = file.file.read(1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_UPLOAD_BYTES:
                tmp.close()
                os.unlink(tmp.name)
                raise HTTPException(status_code=413, detail="File too large")
            tmp.write(chunk)
        tmp_path = tmp.name

    background_tasks.add_task(process_file, job_id, tmp_path, file.filename)
    return {"job_id": job_id}

def process_file(job_id: str, tmp_path: str, filename: str):
    loop = job_loops.get(job_id)
    queue = job_queues.get(job_id)

    def emit(event_name: str, status: str, data=None, message=None):
        if loop and queue:
            payload = {"event": event_name, "status": status}
            if data is not None:
                payload["data"] = data
            if message is not None:
                payload["message"] = message
            loop.call_soon_threadsafe(queue.put_nowait, payload)

    try:
        filename = filename or "sample"
        use_docker = docker_available() and image_built()

        # ── Static analysis ──────────────────────────────────────────────────
        emit("static_analysis", "running")
        static_result = None
        if use_docker:
            static_result = run_static_in_docker(tmp_path)
        if static_result is None and analyze_file is not None:
            static_result = analyze_file(tmp_path)
        if static_result is None:
            emit("error", "error", message="Static analysis unavailable")
            return

        emit("static_analysis", "complete", static_result)

        # ── Docker: JS dynamic analysis ──────────────────────────────────────
        dynamic_js = None
        if use_docker:
            dynamic_js = run_dynamic_in_docker(tmp_path, filename)

        # ── Hybrid Analysis: .NET / PE dynamic execution ─────────────────────
        dynamic_pe = None
        if ha_analyze and HA_API_KEY:
            try:
                dynamic_pe = ha_analyze(tmp_path, HA_API_KEY)
            except Exception as e:
                print(f"Hybrid Analysis error: {e}")

        # ── Build context for Claude ─────────────────────────────────────────
        file_meta = {
            "file_name":           filename,
            "file_size_kb":        os.path.getsize(tmp_path) // 1024,
            "file_type":           static_result.get("file_type"),
            "entropy":             static_result.get("entropy"),
            "is_obfuscated":       static_result.get("is_obfuscated"),
            "threat_level":        static_result.get("threat_level"),
            "behaviors":           static_result.get("behaviors", []),
            "mitre_techniques":    static_result.get("mitre_techniques", []),
            "dangerous_functions": static_result.get("dangerous_functions", [])[:10],
            "urls_found":          static_result.get("urls_found", [])[:5],
            "ips_found":           static_result.get("ips_found", [])[:5],
            "yara_matches":        static_result.get("yara_matches", []),
            "dropped_files":       static_result.get("dropped_files", [])[:5],
            "dotnet":              static_result.get("dotnet", {}),
        }
        if dynamic_js:
            file_meta["js_objects_created"] = dynamic_js.get("objects_created", [])
            file_meta["js_shell_commands"]  = [c["cmd"][:200] for c in dynamic_js.get("shell_commands", [])][:5]
            file_meta["js_file_ops"]        = [f.get("path", "") for f in dynamic_js.get("file_ops", [])][:10]
            file_meta["js_network"]         = dynamic_js.get("network", [])[:5]
            file_meta["js_registry"]        = dynamic_js.get("registry", [])[:5]
        if dynamic_pe:
            file_meta["pe_verdict"]         = dynamic_pe.get("verdict")
            file_meta["pe_threat_score"]    = dynamic_pe.get("threat_score")
            file_meta["pe_malware_family"]  = dynamic_pe.get("malware_family")
            file_meta["pe_processes"]       = [p["name"] for p in dynamic_pe.get("processes", [])][:10]
            file_meta["pe_network"]         = dynamic_pe.get("network", [])[:5]
            file_meta["pe_signatures"]      = [s["name"] for s in dynamic_pe.get("signatures", [])][:10]
            file_meta["pe_mitre"]           = dynamic_pe.get("mitre", [])[:10]

        emit("pipeline_start", "running", message="AI agent pipeline starting...")

        # ── 5-agent Claude pipeline with live streaming ───────────────────────
        pipeline_result = {"report": {}}

        def on_agent_event(name: str, status: str, data: dict = None):
            emit(name, status, data or {})

            # Stream each report stage as it's generated.
            # NOTE: pipeline.run_pipeline() emits the terminal report event with
            # status="complete" (not "done") — matched here so this block (and
            # pipeline_result["report"] below) actually fires. The stage_map
            # field names (classification_confidence, behavior_confidence,
            # reasoning, mitigations) assume a report schema that doesn't match
            # pipeline.py's combined_report (stage1..stage4 + flat fields) —
            # left as-is since reconciling it is a business-logic decision.
            if name == "report" and status == "complete" and data:
                report = data
                stage_map = {
                    1: {
                        "malware_family":  report.get("malware_type", "UNKNOWN"),
                        "verdict":         "MALICIOUS" if report.get("risk_score", 0) >= 60 else "SUSPICIOUS",
                        "risk_score":      report.get("risk_score", 0),
                        "severity":        "CRITICAL" if report.get("risk_score", 0) >= 80 else "HIGH",
                        "confidence":      report.get("classification_confidence", 80) / 100,
                        "one_line_summary": report.get("reasoning", "")[:120],
                    },
                    2: {
                        "executive_summary": report.get("reasoning", ""),
                        "affected_systems":  ["Windows hosts", "Corporate endpoints"],
                        "business_impact":   "Credential theft and data exfiltration risk",
                        "confidence":        report.get("behavior_confidence", 80) / 100,
                    },
                    3: {
                        "mitre_techniques": [
                            {"id": t.split(" ")[0], "name": " ".join(t.split(" ")[1:]), "tactic": "Execution", "description": ""}
                            for t in (file_meta.get("mitre_techniques") or [])[:6]
                        ],
                        "iocs": {
                            "domains": file_meta.get("domains_found", [])[:4],
                            "ips":     file_meta.get("ips_found", [])[:4],
                            "files":   file_meta.get("dropped_files", [])[:4],
                            "registry_keys": [],
                        },
                        "attack_chain": report.get("reasoning", ""),
                        "confidence": 0.88,
                    },
                    4: {
                        "action_plan": [
                            {"priority": i + 1, "action": m, "urgency": "immediate" if i == 0 else "24h"}
                            for i, m in enumerate(report.get("mitigations", [])[:5])
                        ],
                        "yara_rule":                "",
                        "iocs_to_block":            (file_meta.get("ips_found") or []) + (file_meta.get("urls_found") or []),
                        "long_term_recommendations": report.get("mitigations", [])[3:6],
                        "confidence": 0.85,
                    },
                }
                for stage_num, stage_data in stage_map.items():
                    emit("report_stage", "complete", stage_data, stage=stage_num)

            if name == "report" and status == "complete":
                pipeline_result["report"] = data or {}

        if run_pipeline:
            # pipeline.run_pipeline() takes progress_cb(event_dict) — not
            # on_event(name, status, data). Adapt so on_agent_event (which
            # expects the 3-arg form) still gets called correctly instead of
            # raising TypeError on every run.
            def _progress_cb(event: dict) -> None:
                on_agent_event(event.get("event"), event.get("status"), event.get("data"))

            run_pipeline(file_meta, progress_cb=_progress_cb)
        else:
            pipeline_result["report"] = call_claude_report(file_meta)

        result = {
            "static_analysis": static_result,
            "dynamic_js":      dynamic_js,
            "dynamic_pe":      dynamic_pe,
            "report":          pipeline_result["report"],
        }

        emit("done", "complete", result)

    except Exception as e:
        emit("error", "error", message=str(e))
    finally:
        emit("close", "close")
        try:
            os.unlink(tmp_path)
        except Exception:
            pass

@app.websocket("/ws/{job_id}")
async def websocket_endpoint(websocket: WebSocket, job_id: str):
    await websocket.accept()
    queue = job_queues.get(job_id)
    if not queue:
        await websocket.send_json({"event": "error", "message": "Invalid job ID"})
        await websocket.close()
        return

    try:
        while True:
            msg = await queue.get()
            if msg["event"] == "close":
                break
            await websocket.send_json(msg)
    except WebSocketDisconnect:
        pass
    finally:
        job_queues.pop(job_id, None)
        job_loops.pop(job_id, None)
