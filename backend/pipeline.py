"""
5-Agent Claude pipeline — mirrors the ADK agent design from agent-pipeline branch.
Ingestion → (Static + MITRE parallel) → Remediation → Report
Each agent returns structured JSON and emits a status event.
"""

import json
import concurrent.futures
import anthropic
import os
from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(__file__), '.env'))

_client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
MODEL   = "claude-haiku-4-5-20251001"


def _call(system: str, user: str, max_tokens: int = 1500) -> dict:
    print(f"[Claude] calling {MODEL}...")
    resp = _client.messages.create(
        model=MODEL, max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user}],
    )
    text = resp.content[0].text.strip()
    if text.startswith("```"):
        lines = text.split("\n")
        text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
    return json.loads(text.strip())


# ── Agent 1: Ingestion ─────────────────────────────────────────────────────────

def run_ingestion(file_meta: dict) -> dict:
    return _call(
        system="""You are a malware triage specialist.
Given raw file analysis data, structure it cleanly and flag suspicious indicators.
Output valid JSON only.
Format:
{
  "file_name": "string",
  "file_type": "string",
  "file_size_kb": number,
  "sha256": "string",
  "suspicious_flags": ["list of specific concerns"],
  "is_obfuscated": true,
  "threat_indicators": ["list"],
  "confidence": 0.95
}""",
        user=f"Triage this file analysis output:\n{json.dumps(file_meta)}",
    )


# ── Agent 2: Static Analysis ───────────────────────────────────────────────────

def run_static_analysis(ingestion: dict) -> dict:
    return _call(
        system="""You are a malware analyst specializing in static analysis.
Classify the malware type, explain behavior, identify obfuscation, assess severity.
Output valid JSON only.
Format:
{
  "malware_type": "string",
  "malware_family": "string or null",
  "likely_behavior": "string",
  "obfuscation_techniques": ["list"],
  "severity": 8,
  "iocs": ["list of specific IOCs"],
  "kill_chain_stage": "string",
  "confidence": 0.9
}""",
        user=f"Perform static analysis on:\n{json.dumps(ingestion)}",
    )


# ── Agent 3: MITRE Mapping ─────────────────────────────────────────────────────

def run_mitre_mapping(ingestion: dict) -> dict:
    return _call(
        system="""You are a MITRE ATT&CK framework specialist.
Map the observed behaviors to the most specific ATT&CK technique IDs possible.
Output valid JSON only.
Format:
{
  "techniques": [
    {
      "id": "T1059.007",
      "name": "JavaScript",
      "tactic": "Execution",
      "reason": "why this technique applies"
    }
  ],
  "confidence": 0.9
}""",
        user=f"Map these malware behaviors to MITRE ATT&CK:\n{json.dumps(ingestion)}",
    )


# ── Agent 4: Remediation (with self-correction loop) ──────────────────────────

def run_remediation(static: dict, mitre: dict, attempt: int = 1) -> dict:
    result = _call(
        system="""You are a cybersecurity incident responder.
Given malware classification and MITRE techniques, provide actionable remediation.
If confidence is below 0.75, set needs_rerun to true.
Output valid JSON only.
Format:
{
  "iocs_to_block": ["list of IPs, domains, hashes"],
  "containment_steps": ["ordered list of immediate actions"],
  "yara_rule": "compact YARA rule string",
  "confidence": 0.9,
  "needs_rerun": false
}""",
        user=f"Generate remediation.\nStatic: {json.dumps(static)}\nMITRE: {json.dumps(mitre)}",
    )
    if result.get("needs_rerun") and attempt < 2:
        return run_remediation(static, mitre, attempt + 1)
    return result


# ── Agent 5: Report ────────────────────────────────────────────────────────────

def run_report(ingestion: dict, static: dict, mitre: dict, remediation: dict) -> dict:
    return _call(
        system="""You are a senior threat intelligence analyst.
Synthesize all agent findings into a final report for the dashboard.
Output valid JSON only.
Format:
{
  "malware_type": "string",
  "risk_score": 85,
  "classification_confidence": 92,
  "behavior_confidence": 88,
  "findings": [
    {"type": "critical", "label": "CRITICAL", "text": "short finding"},
    {"type": "warn",     "label": "WARNING",  "text": "short finding"},
    {"type": "ok",       "label": "INFO",     "text": "short finding"}
  ],
  "mitigations": ["① step", "② step", "③ step", "④ step", "⑤ step"],
  "reasoning": "2-3 sentence technical explanation of the threat and kill chain"
}""",
        user=f"Generate final report.\nIngestion:{json.dumps(ingestion)}\nStatic:{json.dumps(static)}\nMITRE:{json.dumps(mitre)}\nRemediation:{json.dumps(remediation)}",
        max_tokens=2000,
    )


# ── Pipeline orchestrator ──────────────────────────────────────────────────────

def run_pipeline(file_meta: dict, on_event=None) -> dict:
    """
    Run all 5 agents in order. on_event(name, status, data) is called
    after each agent completes so the caller can stream progress.
    """

    def emit(name: str, status: str, data: dict = None):
        if on_event:
            on_event(name, status, data or {})

    emit("ingestion", "running")
    ingestion = run_ingestion(file_meta)
    emit("ingestion", "done", ingestion)

    emit("static_analysis", "running")
    emit("mitre_mapping",   "running")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        sf = ex.submit(run_static_analysis, ingestion)
        mf = ex.submit(run_mitre_mapping,   ingestion)
        static = sf.result()
        mitre  = mf.result()
    emit("static_analysis", "done", static)
    emit("mitre_mapping",   "done", mitre)

    emit("remediation", "running")
    remediation = run_remediation(static, mitre)
    emit("remediation", "done", remediation)

    emit("report", "running")
    report = run_report(ingestion, static, mitre, remediation)
    emit("report", "done", report)

    return {
        "ingestion":       ingestion,
        "static_analysis": static,
        "mitre_mapping":   mitre,
        "remediation":     remediation,
        "report":          report,
    }
