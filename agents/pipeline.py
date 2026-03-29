import asyncio
import json
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
    print(f"Running Remediation Agent (attempt {attempt})...")
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
        user_message=f"Generate remediation for this malware. Static analysis: {json.dumps(static_output)}. MITRE techniques: {json.dumps(mitre_output)}"
    )
    # Self-correction loop
    if result.get("needs_rerun") and attempt < 2:
        print("Confidence low, rerunning remediation...")
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

def run_pipeline(file_metadata: dict):
    print("Starting MalwareScope Pipeline...")
    print("=" * 50)

    # Step 1: Ingestion
    ingestion = run_ingestion(file_metadata)
    print(f"Ingestion complete — {len(ingestion['suspicious_flags'])} flags found")

    # Step 2: Static + MITRE in parallel (using threads)
    import concurrent.futures
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        print("Running Static Analysis + MITRE Mapping in parallel...")
        static_future = executor.submit(run_static_analysis, ingestion)
        mitre_future = executor.submit(run_mitre_mapping, ingestion)
        static = static_future.result()
        mitre = mitre_future.result()
    print(f"Static Analysis complete — {static['malware_type']}, severity {static['severity']}/10")
    print(f"MITRE Mapping complete — {len(mitre['techniques'])} techniques identified")

    # Step 3: Remediation (with self-correction loop)
    remediation = run_remediation(static, mitre)
    print(f"Remediation complete — confidence {remediation['confidence']}")

    # Step 4: Final Report
    report = run_report(ingestion, static, mitre, remediation)
    print(f"Report complete — risk score {report['risk_score']}/100")

    print("\n" + "=" * 50)
    print("Pipeline complete! Final report:")
    print(json.dumps(report, indent=2))

    return {
        "ingestion": ingestion,
        "static_analysis": static,
        "mitre_mapping": mitre,
        "remediation": remediation,
        "report": report
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
