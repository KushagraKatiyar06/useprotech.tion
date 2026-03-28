import asyncio
import json
from dotenv import load_dotenv
from google.adk.agents import LlmAgent, LoopAgent
from google.adk.tools import agent_tool
from google.adk.runners import Runner
from google.adk.sessions import InMemorySessionService
from google.genai import types

load_dotenv()

# --- MITRE Agent (imported here for A2A handshake) ---
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
        "confidence": 0.9
    }"""
)

# --- Remediation Agent (calls MITRE via A2A handshake) ---
remediation_agent = LlmAgent(
    name="remediation_agent",
    model="gemini-2.5-flash",
    instruction="""You are a cybersecurity incident responder.
    You have access to a MITRE ATT&CK specialist agent — consult it first
    to understand the threat's techniques. Then provide:
    1. A YARA detection rule for this malware
    2. IOCs to immediately block (IPs, domains, hashes)
    3. Containment steps in priority order
    4. A confidence score (0.0 to 1.0) on your findings
    If your confidence is below 0.75, set needs_rerun to true.
    Always output valid JSON only, no explanation, no markdown, just raw JSON.
    Output format:
    {
        "yara_rule": "rule string here",
        "iocs_to_block": ["list of IOCs"],
        "containment_steps": ["step 1", "step 2"],
        "confidence": 0.9,
        "needs_rerun": false
    }""",
    tools=[agent_tool.AgentTool(agent=mitre_agent)]  # A2A handshake
)

# --- Loop Agent wrapping Remediation ---
def should_continue(response) -> bool:
    try:
        text = response.content.parts[0].text
        clean = text.strip().strip("```json").strip("```").strip()
        data = json.loads(clean)
        return data.get("needs_rerun", False)
    except:
        return False

remediation_loop = LoopAgent(
    name="remediation_loop",
    sub_agents=[remediation_agent],
    max_iterations=2
)

async def run_remediation(parallel_output: dict):
    session_service = InMemorySessionService()
    runner = Runner(
        agent=remediation_loop,
        session_service=session_service,
        app_name="malwarescope"
    )

    session = await session_service.create_session(
        app_name="malwarescope",
        user_id="user1"
    )

    message = f"Analyze this malware and provide remediation: {json.dumps(parallel_output)}"

    response = runner.run(
        user_id="user1",
        session_id=session.id,
        new_message=types.Content(parts=[types.Part(text=message)])
    )

    for event in response:
        if event.is_final_response():
            return event.content.parts[0].text

    return None

# Test input (combined output from parallel agents)
mock_parallel_output = {
    "static_analysis": {
        "malware_type": "JavaScript Dropper",
        "likely_behavior": "Downloads and executes secondary payload via WScript.Shell",
        "obfuscation_techniques": ["eval", "unescape", "string concatenation"],
        "severity": 8,
        "iocs": ["http://suspicious-domain.ru"],
        "confidence": 0.91
    },
    "mitre_mapping": {
        "techniques": [
            {"id": "T1059.007", "name": "JavaScript", "tactic": "Execution", "reason": "Uses eval and WScript.Shell"},
            {"id": "T1105", "name": "Ingress Tool Transfer", "tactic": "Command and Control", "reason": "Downloads payload"},
            {"id": "T1027", "name": "Obfuscated Files", "tactic": "Defense Evasion", "reason": "Heavy obfuscation"}
        ],
        "confidence": 0.88
    }
}

async def main():
    print("Running Remediation Agent (with A2A handshake to MITRE)...")
    try:
        result = await run_remediation(mock_parallel_output)
        print("\nOutput:", result)
    except Exception as e:
        pass

asyncio.run(main())
