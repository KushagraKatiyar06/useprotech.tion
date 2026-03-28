import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

report_agent = LlmAgent(
    name="report_agent",
    model="gemini-2.5-flash",
    instruction="""You are a senior threat intelligence analyst writing for both
    technical and executive audiences. Synthesize all prior agent findings into
    a final report.
    Always output valid JSON only, no explanation, no markdown, just raw JSON.
    Output format:
    {
        "executive_summary": "3 sentence summary for non-technical audience",
        "risk_score": 85,
        "malware_type": "string",
        "mitre_techniques": [{"id": "T1059.007", "name": "string", "tactic": "string"}],
        "iocs": ["list of all indicators of compromise"],
        "yara_rule": "rule string",
        "action_plan": [
            {"priority": 1, "action": "string", "urgency": "immediate"}
        ],
        "confidence": 0.9
    }"""
)

async def run_report(all_findings: dict):
    session_service = InMemorySessionService()
    runner = Runner(
        agent=report_agent,
        session_service=session_service,
        app_name="malwarescope"
    )

    session = await session_service.create_session(
        app_name="malwarescope",
        user_id="user1"
    )

    message = f"Generate a final threat report from these findings: {json.dumps(all_findings)}"

    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text=message)])
    )

    for event in response:
        if event.is_final_response():
            return event.content.parts[0].text

    return None

mock_all_findings = {
    "ingestion": {
        "file_name": "6108674530.JS.malicious",
        "file_type": "JavaScript",
        "file_size_kb": 4086,
        "sha256": "abc123placeholder",
        "suspicious_flags": ["eval", "unescape", "WScript.Shell", "ActiveXObject", "http://suspicious-domain.ru"]
    },
    "static_analysis": {
        "malware_type": "JavaScript Dropper",
        "likely_behavior": "Downloads and executes secondary payload via WScript.Shell",
        "severity": 8,
        "iocs": ["http://suspicious-domain.ru"]
    },
    "mitre_mapping": {
        "techniques": [
            {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control"},
            {"id": "T1027", "name": "Obfuscated Files", "tactic": "Defense Evasion"}
        ]
    },
    "remediation": {
        "iocs_to_block": ["http://suspicious-domain.ru", "suspicious-domain.ru"],
        "containment_steps": ["Isolate affected system", "Block malicious domain", "Scan for persistence"],
        "confidence": 0.91
    }
}

async def main():
    print("Running Report Agent...")
    try:
        result = await run_report(mock_all_findings)
        print("\nOutput:", result)
    except Exception as e:
        pass

asyncio.run(main())