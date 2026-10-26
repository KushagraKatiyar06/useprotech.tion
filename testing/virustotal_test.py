import os
import requests
import time
import json
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.environ.get("VT_API_KEY", "")
if not API_KEY:
    raise SystemExit("VT_API_KEY not set — add it to your .env file")
_SCRIPT_DIR = Path(__file__).parent
FILE_PATH = _SCRIPT_DIR / "samples" / "6108674530.JS.malicious"
_RESULTS_DIR = _SCRIPT_DIR / "results"
_RESULTS_DIR.mkdir(exist_ok=True)

headers = {"x-apikey": API_KEY}

# 1. UPLOAD
print("Uploading file...")
with open(FILE_PATH, "rb") as file:
    files = {"file": (FILE_PATH, file)}
    upload_response = requests.post("https://www.virustotal.com/api/v3/files", headers=headers, files=files)

# Error check for upload
if upload_response.status_code != 200:
    print(f"Upload failed: {upload_response.text}")
    exit()

analysis_id = upload_response.json()["data"]["id"]
print(f"Upload successful. Analysis ID: {analysis_id}")

# 2. WAIT for AV Scans
while True:
    status_check = requests.get(f"https://www.virustotal.com/api/v3/analyses/{analysis_id}", headers=headers)
    status = status_check.json()["data"]["attributes"]["status"]
    
    if status == "completed":
        print("AV Scans finished!")
        break
    else:
        print(f"Current Status: {status}... waiting 30s.")
        time.sleep(30)

# 3. GET BEHAVIOR (With a retry loop for Sandbox completion)
file_hash = status_check.json()["meta"]["file_info"]["sha256"]
behavior_url = f"https://www.virustotal.com/api/v3/files/{file_hash}/behaviour_summary"

print("Waiting for Sandbox detonation to generate logs...")
time.sleep(60) # Give the sandboxes a head start

for attempt in range(5): # Try 5 times to get behavior
    behavior_response = requests.get(behavior_url, headers=headers)
    
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