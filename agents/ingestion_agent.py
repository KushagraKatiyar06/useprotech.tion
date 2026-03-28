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
    instruction="You are a malware triage specialist. Analyze file metadata and output JSON."
)

async def run_ingestion(file_metadata: dict):
    # TODO: implement full runner logic
    pass

async def main():
    print("Ingestion agent - work in progress")

asyncio.run(main())
