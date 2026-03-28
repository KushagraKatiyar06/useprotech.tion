import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent, ParallelAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

# --- Static Analysis Agent ---
static_analysis_agent = LlmAgent(
    name="static_analysis_agent",
    model="gemini-2.5-flash",
    instruction="""You are a malware analyst specializing in static analysis.
    Given file analysis output, classify the malware type, explain its likely 
    behavior, identify obfuscation techniques, and assess severity.
    Always output valid JSON only, no explanation, no markdown, just raw JSON.
    Output format:
    {
        "malware_type": "string (e.g. Dropper, Ransomware, Infostealer)",
        "likely_behavior": "string describing what it does",
        "obfuscation_techniques": ["list of detected techniques"],
        "severity": number 1-10,
        "iocs": ["list of indicators of compromise"],
        "confidence": number 0-1
    }"""
)

# --- MITRE Mapping Agent ---
mitre_agent = LlmAgent(
    name="mitre_agent",
    model="gemini-2.5-flash",
    instruction="""You are a MITRE ATT&CK framework specialist.
    Given behavioral indicators and suspicious patterns from malware analysis,
    map each behavior to the most specific ATT&CK technique ID possible.
    Always output valid JSON only, no explanation, no markdown, just raw JSON.
    Output format:
    {
        "techniques": [
            {
                "id": "T1059.007",
                "name": "JavaScript Execution",
                "tactic": "Execution",
                "reason": "why this technique matches"
            }
        ],
        "confidence": number 0-1
    }"""
)

# --- Parallel Agent wrapping both ---
parallel_analysis = ParallelAgent(
    name="parallel_analysis",
    sub_agents=[static_analysis_agent, mitre_agent]
)

async def run_parallel(ingestion_output: dict):
    session_service = InMemorySessionService()
    runner = Runner(
        agent=parallel_analysis,
        session_service=session_service,
        app_name="malwarescope"
    )

    session = await session_service.create_session(
        app_name="malwarescope",
        user_id="user1"
    )

    message = f"Analyze this malware metadata: {json.dumps(ingestion_output)}"

    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text=message)])
    )

    results = []
    for event in response:
        if event.is_final_response():
            results.append({
                "agent": event.author,
                "output": event.content.parts[0].text
            })

    return results

# Test with mock ingestion output
mock_ingestion_output = {
    "file_name": "6108674530.JS.malicious",
    "file_type": "JavaScript",
    "file_size_kb": 4086,
    "sha256": "abc123placeholder",
    "suspicious_flags": [
        "eval function usage",
        "unescape function usage",
        "WScript.Shell object creation",
        "ActiveXObject creation",
        "Network connection to suspicious domain: http://suspicious-domain.ru"
    ],
    "confidence": 0.99
}

async def main():
    print("Running Parallel Agents (Static Analysis + MITRE Mapping)...")
    results = await run_parallel(mock_ingestion_output)
    for r in results:
        print(f"\n--- {r['agent']} ---")
        print(r["output"])

asyncio.run(main())