import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

ingestion_agent = LlmAgent(
    name="ingestion_agent",
    model="gemini-2.5-flash",
    instruction="""You are a malware triage specialist.
    You will be given raw file metadata about a potentially malicious file.
    Your job is to structure it cleanly and flag anything immediately suspicious.
    Always output valid JSON only, no explanation, no markdown, just raw JSON.
    Output format:
    {
        "file_name": "string",
        "file_type": "string",
        "file_size_kb": number,
        "sha256": "string",
        "suspicious_flags": ["list of anything immediately concerning"],
        "confidence": 0.95
    }"""
)

async def run_ingestion(file_metadata: dict):
    session_service = InMemorySessionService()
    runner = Runner(agent=ingestion_agent, session_service=session_service, app_name="malwarescope")

    session = await session_service.create_session(app_name="malwarescope", user_id="user1")

    message = f"Analyze this file metadata and return structured JSON: {json.dumps(file_metadata)}"

    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text=message)])
    )

    for event in response:
        if event.is_final_response():
            return event.content.parts[0].text

# Test with mock data (since Person 1 isn't done yet)
mock_metadata = {
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

async def main():
    print("Running Ingestion Agent...")
    result = await run_ingestion(mock_metadata)
    print("Output:", result)

asyncio.run(main())
