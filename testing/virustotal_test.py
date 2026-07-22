import os
import requests
import time
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# API key must come from the environment (see .env.example: VIRUSTOTAL_API_KEY)
# — never hardcode real API keys in source.
API_KEY = os.environ.get("VIRUSTOTAL_API_KEY", "")
if not API_KEY:
    print("ERROR: VIRUSTOTAL_API_KEY not set in environment/.env")
    exit(1)

_SCRIPT_DIR = Path(__file__).parent
FILE_PATH = _SCRIPT_DIR / "samples" / "6108674530.JS.malicious"
_RESULTS_DIR = _SCRIPT_DIR / "results"
_RESULTS_DIR.mkdir(exist_ok=True)

REQUEST_TIMEOUT = 30          # seconds per HTTP call
MAX_POLL_ATTEMPTS = 40        # ~20 min at 30s intervals — avoid an infinite loop

headers = {"x-apikey": API_KEY}

# 1. UPLOAD
print("Uploading file...")
with open(FILE_PATH, "rb") as file:
    files = {"file": (FILE_PATH, file)}
    upload_response = requests.post(
        "https://www.virustotal.com/api/v3/files",
        headers=headers, files=files, timeout=REQUEST_TIMEOUT,
    )

# Error check for upload
if upload_response.status_code != 200:
    print(f"Upload failed: {upload_response.text}")
    exit()

analysis_id = upload_response.json()["data"]["id"]
print(f"Upload successful. Analysis ID: {analysis_id}")

# 2. WAIT for AV Scans (bounded — was an unconditional `while True`)
status_check = None
for _poll_attempt in range(MAX_POLL_ATTEMPTS):
    status_check = requests.get(
        f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
        headers=headers, timeout=REQUEST_TIMEOUT,
    )
    status = status_check.json()["data"]["attributes"]["status"]

    if status == "completed":
        print("AV Scans finished!")
        break
    else:
        print(f"Current Status: {status}... waiting 30s.")
        time.sleep(30)
else:
    print("Timed out waiting for AV scans to complete.")
    exit(1)

# 3. GET BEHAVIOR (With a retry loop for Sandbox completion)
file_hash = status_check.json()["meta"]["file_info"]["sha256"]
behavior_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"

print("Waiting for Sandbox detonation to generate logs...")
time.sleep(60) # Give the sandboxes a head start

for attempt in range(5): # Try 5 times to get behavior
    behavior_response = requests.get(behavior_url, headers=headers, timeout=REQUEST_TIMEOUT)

    if behavior_response.status_code == 200:
        behavior_json = behavior_response.json()
        
        # Save to file for your AI Agent
        with open(_RESULTS_DIR / "malware_behavior.json", "w") as f:
            json.dump(behavior_json, f, indent=4)

        print("Success! JSON saved to 'results/malware_behavior.json'.")
        break
    else:
        print(f"Behavior logs not ready yet (Attempt {attempt+1}/5). Waiting 60s...")
        time.sleep(60)

print("Done. You can now upload 'results/malware_behavior.json' to your AI.")