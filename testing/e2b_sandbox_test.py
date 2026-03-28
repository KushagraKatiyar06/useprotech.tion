import os
import json
from pathlib import Path
from dotenv import load_dotenv
from e2b_code_interpreter import Sandbox

# Path Setup
SCRIPT_DIR = Path(__file__).parent.absolute()
env_path = SCRIPT_DIR / ".env"
load_dotenv(dotenv_path=env_path)

def analyze_malware_sample(filename):
    full_path = SCRIPT_DIR / filename
    analysis_events = []

    try:
        with Sandbox.create() as sandbox:
            def handle_files_change(event):
                analysis_events.append({"type": "FILESYSTEM", "op": event.operation, "path": event.path})
                print(f"[WATCHER] {event.operation}: {event.path}")

            sandbox.files.on_change = handle_files_change
            sandbox.files.watch_dir("/home/user")
            
            with open(full_path, "rb") as f:
                remote_path = f"/home/user/{filename}"
                sandbox.files.write(remote_path, f.read())
            
            print(f"Detonating sample: {filename}...")
            
            # FIXED: msg is a string, so we append it directly without .line
            execution = sandbox.commands.run(
                f"node {remote_path}",
                on_stdout=lambda msg: analysis_events.append({"type": "STDOUT", "data": msg}),
                on_stderr=lambda msg: analysis_events.append({"type": "STDERR", "data": msg}),
                timeout=60 
            )

            return {
                "exit_code": execution.exit_code,
                "events": analysis_events,
                "final_files": [f.name for f in sandbox.files.list("/home/user")]
            }
    except Exception as e:
        print(f"[DEBUG ERROR] Sandbox failed: {e}")
        return None

malware_results = analyze_malware_sample("6108674530.JS.malicious")
if malware_results:
    print(json.dumps(malware_results, indent=2))