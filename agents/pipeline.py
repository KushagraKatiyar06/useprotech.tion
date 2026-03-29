import concurrent.futures
import json
import os
import anthropic
from dotenv import load_dotenv

load_dotenv()

client = anthropic.Anthropic()
MODEL = "claude-haiku-4-5"

CALL_TIMEOUT = 45  # seconds — hard limit per Claude call

def call_claude(system_prompt: str, user_message: str, max_tokens: int = 2000) -> dict:
    """Call Claude and return parsed JSON response."""
    response = client.messages.create(
        model=MODEL,
        max_tokens=max_tokens,
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


def _call_claude_timed(system_prompt: str, user_message: str,
                       timeout: int = CALL_TIMEOUT, max_tokens: int = 2000) -> dict:
    """call_claude() with a hard timeout.
    Returns {'error': 'timeout', 'partial': True} if the call exceeds `timeout` seconds
    so the pipeline can continue with partial data rather than hanging indefinitely.
    """
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(call_claude, system_prompt, user_message, max_tokens)
        try:
            return fut.result(timeout=timeout)
        except concurrent.futures.TimeoutError:
            print(f"WARNING: Claude call timed out after {timeout}s — returning partial stub")
            return {"error": "timeout", "partial": True}
        except Exception as exc:
            print(f"WARNING: Claude call failed: {exc}")
            return {"error": str(exc), "partial": True}

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

def run_report_threat_id(ingestion: dict, static: dict, vt_data: dict | None = None) -> dict:
    """Stage 1 — Threat identity: family, verdict, risk score. Target: <10s."""
    print("Running Report Stage 1: Threat ID...")
    ctx = {
        "sha256":           ingestion.get("sha256", ""),
        "malware_type":     static.get("malware_type", ""),
        "severity":         static.get("severity", 0),
        "suspicious_flags": ingestion.get("suspicious_flags", [])[:5],
        "verdict_labels":   (vt_data or {}).get("verdict_labels", []),
    }
    return _call_claude_timed(
        system_prompt="""You are a malware classification expert.
Given concise file metadata, identify the malware family, assign a risk score 0-100, and write one sentence.
Output valid JSON only. No markdown, no explanation.
Format:
{
  "stage": 1,
  "malware_family": "string e.g. AgentTesla v4",
  "verdict": "MALWARE",
  "risk_score": 95,
  "severity": "CRITICAL",
  "confidence": 0.99,
  "one_line_summary": "one sentence — what this malware does and its primary impact"
}""",
        user_message=f"Identify this malware: {json.dumps(ctx)}",
        timeout=CALL_TIMEOUT,
        max_tokens=400,
    )


def run_report_executive(stage1: dict, static: dict, vt_data: dict | None = None) -> dict:
    """Stage 2 — Executive summary: non-technical overview, business impact. Target: <15s."""
    print("Running Report Stage 2: Executive Summary...")
    ctx = {
        "malware_family":   stage1.get("malware_family", ""),
        "risk_score":       stage1.get("risk_score", 0),
        "severity":         stage1.get("severity", ""),
        "one_line_summary": stage1.get("one_line_summary", ""),
        "likely_behavior":  static.get("likely_behavior", ""),
        "verdict_labels":   (vt_data or {}).get("verdict_labels", []),
        "dns_hostnames":    (vt_data or {}).get("dns_hostnames", []),
    }
    return _call_claude_timed(
        system_prompt="""You are a cybersecurity communications specialist writing for executives.
Given malware analysis, write a clear non-technical executive brief.
Output valid JSON only. No markdown, no explanation.
Format:
{
  "stage": 2,
  "executive_summary": "3-4 sentence non-technical summary of what happened and why it matters",
  "affected_systems": ["list of what is at risk, e.g. Saved browser passwords, Email credentials, FTP accounts"],
  "business_impact": "one sentence describing the potential business impact",
  "confidence": 0.99
}""",
        user_message=f"Write executive summary: {json.dumps(ctx)}",
        timeout=CALL_TIMEOUT,
        max_tokens=600,
    )


def run_report_technical(static: dict, mitre: dict, vt_data: dict | None = None) -> dict:
    """Stage 3 — Technical deep-dive: MITRE, IOCs, attack chain. Target: <25s."""
    print("Running Report Stage 3: Technical Analysis...")
    vt = vt_data or {}
    ctx = {
        "malware_type":     static.get("malware_type", ""),
        "obfuscation":      static.get("obfuscation_techniques", [])[:3],
        "iocs_from_static": static.get("iocs", [])[:5],
        "mitre_from_agent": mitre.get("techniques", [])[:8],
        "vt_mitre":         vt.get("mitre_techniques", [])[:17],
        "domains":          vt.get("dns_hostnames", []),
        "ips":              vt.get("ip_addresses", []),
        "files_dropped":    [f.get("sha256", "") for f in vt.get("files_dropped", []) if f.get("sha256")][:8],
        "registry_keys":    vt.get("registry_keys_set", [])[:5],
        "processes":        vt.get("processes_created", [])[:1],
    }
    return _call_claude_timed(
        system_prompt="""You are a malware reverse engineer writing a technical threat report.
Synthesize all indicators into structured technical analysis.
Output valid JSON only. No markdown, no explanation.
Format:
{
  "stage": 3,
  "mitre_techniques": [
    {"id": "T1005", "name": "Data from Local System", "tactic": "Collection", "description": "brief one-line reason this applies"}
  ],
  "iocs": {
    "domains": ["contacted domains"],
    "ips": ["destination IPs"],
    "files": ["dropped file hashes or paths"],
    "registry_keys": ["modified registry keys"]
  },
  "attack_chain": "string — full attack sequence from initial execution to final payload",
  "confidence": 0.99
}""",
        user_message=f"Generate technical analysis: {json.dumps(ctx)}",
        timeout=CALL_TIMEOUT,
        max_tokens=1500,
    )


def run_report_remediation(remediation: dict, mitre: dict, stage1: dict) -> dict:
    """Stage 4 — Remediation: prioritized action plan, YARA rule, long-term steps. Target: <35s."""
    print("Running Report Stage 4: Remediation Plan...")
    ctx = {
        "malware_family":    stage1.get("malware_family", ""),
        "risk_score":        stage1.get("risk_score", 0),
        "containment_steps": remediation.get("containment_steps", []),
        "iocs_to_block":     remediation.get("iocs_to_block", []),
        "yara_rule":         remediation.get("yara_rule", ""),
        "mitre_ids":         [t.get("id") for t in mitre.get("techniques", [])[:8]],
    }
    return _call_claude_timed(
        system_prompt="""You are a senior incident responder writing a prioritized action plan.
Produce a final actionable remediation report with a valid YARA rule.
Output valid JSON only. No markdown, no explanation.
Format:
{
  "stage": 4,
  "action_plan": [
    {"priority": 1, "action": "string", "urgency": "immediate"},
    {"priority": 2, "action": "string", "urgency": "immediate"},
    {"priority": 3, "action": "string", "urgency": "24h"},
    {"priority": 4, "action": "string", "urgency": "72h"}
  ],
  "yara_rule": "full YARA detection rule as a string",
  "iocs_to_block": ["IPs, domains, hashes to block at firewall/DNS"],
  "long_term_recommendations": ["3-4 strategic security improvements"],
  "confidence": 0.99
}""",
        user_message=f"Generate remediation plan: {json.dumps(ctx)}",
        timeout=CALL_TIMEOUT,
        max_tokens=1200,
    )

def run_pipeline(file_metadata: dict, progress_cb=None, vt_data: dict | None = None):
    """Run the full analysis pipeline.

    progress_cb, if provided, is called with a dict at each stage transition.
    Report generation is split into 4 fast focused calls that each stream to the
    frontend as soon as they complete, rather than one large blocking call.

    Event shapes emitted via progress_cb
    -------------------------------------
    Agents 1-4 (existing):
      {"event": "ingestion"|"static_analysis"|"mitre_mapping"|"remediation",
       "status": "running"|"complete", "data"?: dict, "message"?: str}

    Report sub-stages (new — stream progressively):
      {"event": "report_stage", "stage": 1|2|3|4, "status": "complete", "data": dict}

    Terminal:
      emitted by _run_job in app.py:
      {"event": "done", "status": "complete", "data": full_result}
    """
    # ── Merge VirusTotal enrichment ──────────────────────────────────────────
    if vt_data:
        file_metadata = dict(file_metadata)  # don't mutate caller's dict
        file_metadata["vt_enrichment"] = vt_data
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
        file_metadata["raw_indicators"] = augmented[:50]

    def emit(event: str, status: str, data=None, message: str = None):
        if progress_cb:
            payload = {"event": event, "status": status}
            if message:
                payload["message"] = message
            if data is not None:
                payload["data"] = data
            progress_cb(payload)

    def emit_stage(stage_num: int, data: dict):
        if progress_cb:
            progress_cb({"event": "report_stage", "stage": stage_num,
                         "status": "complete", "data": data})

    print("Starting MalwareScope Pipeline...")
    print("=" * 50)

    # ── Agent 1: Ingestion ────────────────────────────────────────────────────
    emit("ingestion", "running", message="Structuring file metadata and flagging suspicious indicators...")
    ingestion = run_ingestion(file_metadata)
    print(f"Ingestion complete — {len(ingestion.get('suspicious_flags', []))} flags found")
    emit("ingestion", "complete", data=ingestion)

    # ── Agents 2 & 3: Static Analysis + MITRE in parallel ────────────────────
    emit("static_analysis", "running", message="Classifying malware type and assessing severity...")
    emit("mitre_mapping",    "running", message="Mapping behaviors to MITRE ATT&CK techniques...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        static_future = executor.submit(run_static_analysis, ingestion)
        mitre_future  = executor.submit(run_mitre_mapping, ingestion)
        static = static_future.result()
        mitre  = mitre_future.result()
    print(f"Static Analysis complete — {static.get('malware_type', '?')}, severity {static.get('severity', '?')}/10")
    print(f"MITRE Mapping complete — {len(mitre.get('techniques', []))} techniques identified")
    emit("static_analysis", "complete", data=static)
    emit("mitre_mapping",   "complete", data=mitre)

    # ── Agent 4: Remediation ─────────────────────────────────────────────────
    emit("remediation", "running", message="Generating YARA rule, IOC blocklist, and containment steps...")
    remediation = run_remediation(static, mitre)
    print(f"Remediation complete — confidence {remediation.get('confidence', '?')}")
    emit("remediation", "complete", data=remediation)

    # ── Report: 4 fast focused stages (each streams to frontend immediately) ──
    emit("report", "running", message="Generating multi-stage threat report (4 phases)...")

    # Stage 1 — Threat identity (~10 s)
    stage1 = run_report_threat_id(ingestion, static, vt_data)
    print(f"Report S1 complete — {stage1.get('malware_family', '?')} risk={stage1.get('risk_score', '?')}")
    emit_stage(1, stage1)

    # Stage 2 — Executive summary (~15 s)
    stage2 = run_report_executive(stage1, static, vt_data)
    print("Report S2 complete — executive summary written")
    emit_stage(2, stage2)

    # Stage 3 — Technical deep-dive (~25 s)
    stage3 = run_report_technical(static, mitre, vt_data)
    print(f"Report S3 complete — {len(stage3.get('mitre_techniques', []))} MITRE techniques")
    emit_stage(3, stage3)

    # Stage 4 — Remediation plan (~35 s)
    stage4 = run_report_remediation(remediation, mitre, stage1)
    print(f"Report S4 complete — {len(stage4.get('action_plan', []))} action items")
    emit_stage(4, stage4)

    # Build combined report (backward-compat flat fields + all 4 sub-stage blobs)
    iocs_s3 = stage3.get("iocs") or {}
    combined_report = {
        # Sub-stage blobs for the frontend streaming cards
        "stage1": stage1,
        "stage2": stage2,
        "stage3": stage3,
        "stage4": stage4,
        # Flat fields — used by done-event handler as fallback
        "malware_type":     stage1.get("malware_family", ""),
        "risk_score":       stage1.get("risk_score", 50),
        "executive_summary": stage2.get("executive_summary", ""),
        "mitre_techniques": stage3.get("mitre_techniques", []),
        "iocs":             iocs_s3.get("domains", []) + iocs_s3.get("ips", []),
        "yara_rule":        stage4.get("yara_rule", ""),
        "action_plan":      stage4.get("action_plan", []),
        "confidence":       stage1.get("confidence", 0.9),
    }
    emit("report", "complete", data=combined_report)

    print("\n" + "=" * 50)
    print(f"Pipeline complete! Risk score: {stage1.get('risk_score', '?')}/100")

    return {
        "ingestion":       ingestion,
        "static_analysis": static,
        "mitre_mapping":   mitre,
        "remediation":     remediation,
        "report":          combined_report,
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
