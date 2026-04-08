# UseProtection

An AI-powered malware analysis platform. Upload a suspicious file and get back a full automated security report — static analysis, MITRE ATT&CK mapping, remediation suggestions, and more — all streamed in real time to a web dashboard.

## What it does

1. **Upload** a file via the web UI
2. An **agent pipeline** kicks off in parallel:
   - Static analysis of the file's structure and behavior
   - MITRE ATT&CK technique mapping
   - Remediation recommendations
   - Final report generation
3. Results stream live to the **dashboard** over WebSocket
4. A downloadable PDF report is generated at the end

## Tech Stack

**Frontend**
- Next.js 15 (React 19, TypeScript)
- Three.js for 3D UI elements
- jsPDF for report export
- Static export served by the backend

**Backend**
- Python / FastAPI
- WebSockets for real-time event streaming
- Google ADK + Anthropic SDK for AI agents
- E2B for sandboxed code execution
- NetworkX / Matplotlib for analysis graphs
- Docker support via `Dockerfile`

## Setup

### Prerequisites
- Python 3.10+
- Node.js 18+
- API keys: Anthropic, Google Gemini, E2B

### Backend

```bash
python -m venv venv
source venv/Scripts/activate   # Windows
# source venv/bin/activate     # Mac/Linux

pip install -r requirements.txt
cp .env.example .env           # add your API keys
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
