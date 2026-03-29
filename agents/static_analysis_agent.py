import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

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

async def run_static_analysis(ingestion_output: dict):
    session_service = InMemorySessionService()
    runner = Runner(
        agent=static_analysis_agent,
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
    for event in response:
        if event.is_final_response():
            return event.content.parts[0].text
    return None
