# UseProtection

An AI-powered malware analysis platform. Drop in a suspicious file (or a VirusTotal log) and get back a full automated security report — static analysis, live sandboxed execution, MITRE ATT&CK mapping, and remediation guidance — all streamed in real time to a dashboard.

🏆 **Winner — Cybersecurity & AI Track (sponsored by NextEra)** at HackUSF. [View on Devpost](https://devpost.com/software/use-protech-tion)

![Dashboard overview](screenshot/dashboard-overview.png)

## What it does

1. **Upload** a file (or paste a VirusTotal report) through the web UI.
2. A pipeline of AI agents kicks off: static analysis of the file's structure and behavior, VirusTotal enrichment, malware family classification, MITRE ATT&CK technique mapping, and remediation planning.
3. The suspicious file is detonated live inside an **isolated E2B sandbox**. If it crashes on a missing API/environment (common with obfuscated droppers), Gemini reads the crash, generates a JS patch to mock the missing behavior, and re-runs — adapting automatically instead of giving up, with a human-in-the-loop view into every patch.
4. Everything streams live over WebSocket to the dashboard: agent progress, raw pipeline logs, and the sandbox's live console, syscall/behavior tree, and generated patches.
5. A multi-stage report (threat ID → executive summary → technical breakdown → remediation plan) builds progressively and exports to a downloadable PDF.

## Features

- **Parallel agent pipeline** — static analysis, VirusTotal lookups, MITRE ATT&CK mapping, and remediation recommendations run concurrently and stream progress independently.
- **Adaptive E2B sandbox** — detonates the sample in an isolated Linux sandbox; on a runtime crash, an LLM-generated patch mocks the missing API (network, filesystem, ActiveX/WMI, etc.) and the run resumes automatically, up to a bounded number of iterations.
- **Human-in-the-loop patching** — every auto-generated patch is visible and reviewable, with a live syscall/behavior tree, console output, and save/upload controls for the sandbox session.
- **PE / .NET static analysis** — entropy analysis, YARA matching, PE section/import inspection, IOC extraction, and reflective-loading / fileless-execution detection, with built-in handling for large obfuscated scripts.
- **MITRE ATT&CK mapping** — detected behaviors are automatically mapped to ATT&CK technique IDs.
- **Malware family classification & risk scoring** — severity and a 0–100 risk score, surfaced per analysis.
- **Live streaming dashboard** — every pipeline and sandbox event pushes to the UI over WebSocket as it happens, no polling.
- **4-stage report generation** — threat ID, executive summary, technical detail, and remediation each stream in and render independently, with a downloadable PDF export.
- **VirusTotal integration** — enriches analysis with existing VT reports when available.

## Tech Stack

**Frontend**
- Next.js 15 (React 19, TypeScript)
- Three.js for 3D UI elements, Framer Motion for animation/page transitions
- jsPDF for report export
- Static export served by the backend

**Backend**
- Python / FastAPI with WebSockets for real-time event streaming
- Google Gemini (`google-genai`) for all agent/LLM calls
- E2B for isolated sandboxed code execution
- `pefile`, `yara-python`, NetworkX, Matplotlib for static analysis and behavior graphing
- Docker support via `Dockerfile`

![Adaptive sandbox trace](screenshot/sandbox-trace.png)

## Setup

### Prerequisites
- Python 3.10+
- Node.js 18+
- API keys: Google Gemini, E2B, (optional) VirusTotal

### Backend

```bash
python -m venv venv
source venv/Scripts/activate   # Windows
# source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
cp .env.example .env            # add your API keys
uvicorn app:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run build    # produces frontend/out/ (static export)
```

Then visit `http://localhost:8000`.

For frontend dev mode:

```bash
npm run dev      # http://localhost:3000
```

## Contributors

- Kushagra K
- Abhay D
- Madhu B
- Esha G
