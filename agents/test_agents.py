import asyncio
import os
from dotenv import load_dotenv
from google.adk.agents import LlmAgent
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

test_agent = LlmAgent(
    name="test_agent",
    model="gemini-2.5-flash",
    instruction="You are a helpful assistant. Respond in one sentence only."
)

async def main():
    session_service = InMemorySessionService()
    runner = Runner(agent=test_agent, session_service=session_service, app_name="test")

    session = await session_service.create_session(app_name="test", user_id="user1")

    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text="Say hello and confirm you are working.")])
    )

    for event in response:
        if event.is_final_response():
            print("✅ ADK is working:", event.content.parts[0].text)

asyncio.run(main())