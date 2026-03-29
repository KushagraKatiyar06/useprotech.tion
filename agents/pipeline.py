import asyncio
import json
import os
import time
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()
MODEL = "claude-haiku-4-5"

def call_claude(system_prompt: str, user_message: str) -> dict:
    """Call Claude and return parsed JSON response."""
    response = client.messages.create(
        model=MODEL,
        max_tokens=2000,
        system=system_prompt,
        messages=[{"role": "user", "content": user_message}]
    )
    text = response.content[0].text.strip()
    # Strip markdown if present
    if text.startswith("```"):
        text = text.split("```")[1]
        if text.startswith("json"):
            text = text[4:]
    return json.loads(text.strip())

def enrich_with_virustotal(vt_json_path: str) -> dict:
    """Read a VirusTotal behavior JSON and extract enrichment fields.

    Returns a dict with:
      verdict_labels    – e.g. ["AgentTesla", "AgentTesla.v4"]
      mitre_techniques  – deduplicated list of {id, description, severity}
      dns_hostnames     – contacted domains
      files_dropped     – list of {sha256, path?, type?}
      ip_addresses      – unique destination IPs
      processes_created – command-line strings (truncated to 300 chars each)
      registry_keys_set – list of registry key strings
    """
    with open(vt_json_path, encoding="utf-8") as fh:
        raw = json.load(fh)
    data = raw.get("data", {})

    # MITRE — deduplicate on ID, keep first description seen per ID
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

    # Processes — truncate long PowerShell blobs so they don't blow the token budget
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


def run_ingestion(file_metadata: dict) -> dict:
    print("Running Ingestion Agent...")
    return call_claude(
        system_prompt="""You are a malware triage specialist.
        Given raw file metadata, structure it cleanly and flag anything suspicious.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "file_name": "string",
            "file_type": "string",
            "file_size_kb": number,
            "sha256": "string",
            "suspicious_flags": ["list of concerns"],
            "confidence": 0.95
        }""",
        user_message=f"Analyze this file metadata: {json.dumps(file_metadata)}"
    )

def run_static_analysis(ingestion_output: dict) -> dict:
    print("Running Static Analysis Agent...")
    return call_claude(
        system_prompt="""You are a malware analyst specializing in static analysis.
        Classify the malware type, explain behavior, identify obfuscation, assess severity.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "malware_type": "string",
            "likely_behavior": "string",
            "obfuscation_techniques": ["list"],
            "severity": 8,
            "iocs": ["list"],
            "confidence": 0.9
        }""",
        user_message=f"Analyze this malware metadata: {json.dumps(ingestion_output)}"
    )

def run_mitre_mapping(ingestion_output: dict) -> dict:
    print("Running MITRE Mapping Agent...")
    return call_claude(
        system_prompt="""You are a MITRE ATT&CK framework specialist.
        Map behaviors to the most specific ATT&CK technique IDs possible.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "techniques": [
                {
                    "id": "T1059.007",
                    "name": "string",
                    "tactic": "string",
                    "reason": "string"
                }
            ],
            "confidence": 0.9
        }""",
        user_message=f"Map these malware behaviors to MITRE ATT&CK: {json.dumps(ingestion_output)}"
    )

def run_remediation(static_output: dict, mitre_output: dict, attempt: int = 1) -> dict:
    print(f"🛡️ Running Remediation Agent (attempt {attempt})...")
    result = call_claude(
        system_prompt="""You are a cybersecurity incident responder.
        Given malware analysis and MITRE techniques, provide:
        1. A YARA detection rule
        2. IOCs to immediately block
        3. Containment steps in priority order
        4. A confidence score (0.0 to 1.0)
        If confidence is below 0.75, set needs_rerun to true.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "yara_rule": "string",
            "iocs_to_block": ["list"],
            "containment_steps": ["list"],
            "confidence": 0.9,
            "needs_rerun": false
        }""",
        user_message=f"""Generate remediation for this malware.
        Static analysis: {json.dumps(static_output)}
        MITRE techniques: {json.dumps(mitre_output)}
        Use the MITRE techniques above directly — no need to look them up."""
    )
    if result.get("needs_rerun") and attempt < 2:
        print("⚠️ Confidence low, rerunning remediation...")
        return run_remediation(static_output, mitre_output, attempt + 1)
    return result

def run_report(ingestion: dict, static: dict, mitre: dict, remediation: dict) -> dict:
    print("Running Report Agent...")
    return call_claude(
        system_prompt="""You are a senior threat intelligence analyst.
        Synthesize all findings into a final report for technical and executive audiences.
        Output valid JSON only, no markdown, no explanation.
        Format:
        {
            "executive_summary": "3 sentence summary",
            "risk_score": 85,
            "malware_type": "string",
            "mitre_techniques": [{"id": "string", "name": "string", "tactic": "string"}],
            "iocs": ["list"],
            "yara_rule": "string",
            "action_plan": [{"priority": 1, "action": "string", "urgency": "immediate"}],
            "confidence": 0.9
        }""",
        user_message=f"Generate final threat report. Ingestion: {json.dumps(ingestion)}. Static: {json.dumps(static)}. MITRE: {json.dumps(mitre)}. Remediation: {json.dumps(remediation)}"
    )

def run_pipeline(file_metadata: dict, progress_cb=None, vt_data: dict | None = None):
    """Run the full analysis pipeline.

    progress_cb, if provided, is called with a dict at each stage transition:
      {"event": str, "status": "running"|"complete", "data": dict|None, "message": str|None}

    vt_data, if provided (from enrich_with_virustotal), is merged into the metadata so all
    five Claude agents receive the real VirusTotal behavioral context.
    """
    import concurrent.futures

    # ── Merge VirusTotal enrichment ──────────────────────────────────────────
    if vt_data:
        file_metadata = dict(file_metadata)  # don't mutate caller's dict

        # Embed the full VT context so agents can reference it
        file_metadata["vt_enrichment"] = vt_data

        # Also surface the most actionable IOCs into raw_indicators so the
        # ingestion agent flags them immediately
        existing = set(file_metadata.get("raw_indicators", []))
        extra: list[str] = (
            vt_data.get("verdict_labels", [])
            + vt_data.get("dns_hostnames", [])
            + vt_data.get("ip_addresses", [])
            + vt_data.get("registry_keys_set", [])
            + vt_data.get("processes_created", [])
        )
        augmented = list(file_metadata.get("raw_indicators", []))
        for item in extra:
            if item and item not in existing:
                existing.add(item)
                augmented.append(item)
        file_metadata["raw_indicators"] = augmented[:50]  # cap to avoid token overflow

    def emit(event: str, status: str, data=None, message: str = None):
        if progress_cb:
            payload = {"event": event, "status": status}
            if message:
                payload["message"] = message
            if data is not None:
                payload["data"] = data
            progress_cb(payload)

    print("Starting MalwareScope Pipeline...")
    print("=" * 50)

    # Step 1: Ingestion
    emit("ingestion", "running", message="Structuring file metadata and flagging suspicious indicators...")
    ingestion = run_ingestion(file_metadata)
    flags = ingestion.get("suspicious_flags", [])
    print(f"Ingestion complete — {len(flags)} flags found")
    emit("ingestion", "complete", data=ingestion)

    # Step 2: Static + MITRE in parallel
    emit("static_analysis", "running", message="Classifying malware type and assessing severity...")
    emit("mitre_mapping", "running", message="Mapping behaviors to MITRE ATT&CK techniques...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        static_future = executor.submit(run_static_analysis, ingestion)
        mitre_future = executor.submit(run_mitre_mapping, ingestion)
        static = static_future.result()
        mitre = mitre_future.result()
    print(f"Static Analysis complete — {static.get('malware_type', '?')}, severity {static.get('severity', '?')}/10")
    print(f"MITRE Mapping complete — {len(mitre.get('techniques', []))} techniques identified")
    emit("static_analysis", "complete", data=static)
    emit("mitre_mapping", "complete", data=mitre)

    # Step 3: Remediation (with self-correction loop)
    emit("remediation", "running", message="Generating YARA rule, IOC blocklist, and containment steps...")
    remediation = run_remediation(static, mitre)
    print(f"Remediation complete — confidence {remediation.get('confidence', '?')}")
    emit("remediation", "complete", data=remediation)

    # Step 4: Final Report
    emit("report", "running", message="Synthesizing executive report and action plan...")
    report = run_report(ingestion, static, mitre, remediation)
    print(f"Report complete — risk score {report.get('risk_score', '?')}/100")
    emit("report", "complete", data=report)

    print("\n" + "=" * 50)
    print("Pipeline complete! Final report:")
    print(json.dumps(report, indent=2))

    return {
        "ingestion": ingestion,
        "static_analysis": static,
        "mitre_mapping": mitre,
        "remediation": remediation,
        "report": report,
    }

# Test
mock_file = {
    "file_name": "6108674530.JS.malicious",
    "file_type": "JavaScript",
    "file_size_kb": 4086,
    "sha256": "abc123placeholder",
    "raw_indicators": [
        "eval",
        "unescape",
        "WScript.Shell",
        "ActiveXObject",
        "http://suspicious-domain.ru"
    ]
}

if __name__ == "__main__":
    run_pipeline(mock_file)
