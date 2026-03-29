import sys
import os
import json
import tempfile
import shutil
import subprocess
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'sandbox'))

from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
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
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000", "http://localhost:3001", "http://127.0.0.1:3001"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SANDBOX_IMAGE = "useprotection-sandbox"
SANDBOX_DIR   = os.path.join(os.path.dirname(__file__), '..', 'sandbox')


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


# ── Endpoints ─────────────────────────────────────────────────────────────────

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


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    suffix = f"_{file.filename}" if file.filename else ".bin"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        shutil.copyfileobj(file.file, tmp)
        tmp_path = tmp.name

    try:
        filename = file.filename or "sample"
        use_docker = docker_available() and image_built()

        # ── Static analysis ──────────────────────────────────────────────────
        static_result = None
        if use_docker:
            static_result = run_static_in_docker(tmp_path)
        if static_result is None and analyze_file is not None:
            static_result = analyze_file(tmp_path)
        if static_result is None:
            raise HTTPException(status_code=500, detail="Static analysis unavailable")

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

        print(f"[analyze] static done, behaviors={len(file_meta.get('behaviors',[]))}, running pipeline...")
        if run_pipeline:
            pipeline_result = run_pipeline(file_meta)
            ai_report = pipeline_result["report"]
            agents = {k: pipeline_result[k] for k in ("ingestion", "static_analysis", "mitre_mapping", "remediation")}
            print("[analyze] pipeline done")
        else:
            raise HTTPException(status_code=500, detail="AI pipeline unavailable")

        return {
            "static":     static_result,
            "dynamic_js": dynamic_js,
            "dynamic_pe": dynamic_pe,
            "report":     ai_report,
            "agents":     agents,
        }

    except json.JSONDecodeError as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"AI report parse error: {e}")
    except HTTPException:
        raise
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {e}")
    finally:
        os.unlink(tmp_path)
