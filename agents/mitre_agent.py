import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

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

async def run_mitre_mapping(ingestion_output: dict):
    session_service = InMemorySessionService()
    runner = Runner(
        agent=mitre_agent,
        session_service=session_service,
        app_name="malwarescope"
    )
    session = await session_service.create_session(
        app_name="malwarescope",
        user_id="user1"
    )
    message = f"Map these malware behaviors to MITRE ATT&CK: {json.dumps(ingestion_output)}"
    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text=message)])
    )
    for event in response:
        if event.is_final_response():
            return event.content.parts[0].text
    return None
