import os
import json
import networkx as nx
import matplotlib.pyplot as plt
from pathlib import Path
from dotenv import load_dotenv
from e2b_code_interpreter import Sandbox

# Path Setup
SCRIPT_DIR = Path(__file__).parent.absolute()
env_path = SCRIPT_DIR / ".env"
load_dotenv(dotenv_path=env_path)

# Advanced "Feeder" Mock: This mimics the specific environment Agent Tesla wants
# It returns 'true' for file checks and specific values for registry reads.
WINDOWS_MOCK = """
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + prop);
        }
        return function() { return this; }; 
    }
};

// Simulation of Windows Management Instrumentation (WMI)
global.GetObject = function(path) {
    console.log('[MOCK WMI] Querying: ' + path);
    return new Proxy({
        ExecQuery: (query) => {
            console.log('[MOCK WMI] Executed: ' + query);
            // Return fake hardware info to bypass VM detection checks
            return [{ 
                Name: 'Standard PC', 
                VideoProcessor: 'GenuineIntel', 
                Manufacturer: 'Dell Inc.' 
            }];
        }
    }, catchAll);
};

global.ActiveXObject = function(type) {
    console.log('[MOCK ACTIVEX] Created: ' + type);
    
    // 1. Fake Network: Simulate the C2 and IP-lookup behavior from the PDF
    if (type.includes('XMLHTTP') || type.includes('WinHttp')) {
        return new Proxy({
            Open: (method, url) => console.log('[MOCK NET] Connecting to: ' + url),
            Send: (data) => console.log('[MOCK NET] Sending exfiltration data...'),
            Status: 200,
            ResponseText: '{"status":"success","country":"US","org":"Business Network"}' 
        }, catchAll);
    }

    // 2. Fake Stream: Catch the payload assembly
    if (type.includes('Stream')) {
        return new Proxy({
            Open: () => console.log('[MOCK STREAM] Opened Connection'),
            WriteText: (t) => console.log('[MOCK STREAM] Writing payload chunk'),
            SaveToFile: (p) => console.log('[MOCK ATTEMPT] SaveToFile: ' + p),
            Close: () => {}
        }, catchAll);
    }

    // 3. Fake Shell: Simulate Registry and PowerShell execution
    if (type.includes('Shell')) {
        return new Proxy({
            Run: (cmd) => console.log('[MOCK ATTEMPT] Run Command: ' + cmd),
            ExpandEnvironmentStrings: (s) => s.replace('%TEMP%', '/tmp').replace('%PUBLIC%', '/home/user'),
            RegRead: (key) => { 
                console.log('[MOCK REG] Reading: ' + key); 
                // Return fake success for Agent Tesla's favorite targets
                if (key.includes('Foxmail') || key.includes('Aerofox')) return 'C:\\\\Users\\\\Public\\\\Foxmail';
                return "1"; 
            }
        }, catchAll);
    }

    // 4. Fake FileSystem: The "Yes-Man" Mock
    return new Proxy({
        FileExists: (path) => { 
            console.log('[MOCK FS] Checking for presence of: ' + path); 
            return true; // LIE: Tell the malware every file it looks for exists
        },
        GetFolder: (path) => ({ Files: [] }),
        CreateTextFile: (path) => {
            console.log('[MOCK FS] Creating: ' + path);
            return { Write: () => {}, Close: () => {} };
        },
        DeleteFile: (path) => console.log('[MOCK FS] Self-Deletion Attempt: ' + path),
        createElement: (tag) => { return { appendChild: () => {}, text: "" }; }
    }, catchAll);
};

global.WScript = new Proxy({
    CreateObject: (type) => new ActiveXObject(type),
    Sleep: (ms) => console.log('[MOCK TIME] Skipping anti-sandbox sleep: ' + ms + 'ms'),
    ScriptName: '6108674530.js',
    Echo: (m) => console.log('[WSCRIPT] ' + m)
}, catchAll);

// Global obfuscation stubs
global.IMLRHNEGARRR = function() { return ""; }; 
global.IMLRHNEGARR = function() { return ""; };

console.log('[SYSTEM] Agent Tesla Simulation Layer Active.');
"""

def analyze_malware_with_graph(filename):
    full_path = SCRIPT_DIR / filename
    analysis_events = []
    G = nx.DiGraph()
    root_node = filename
    G.add_node(root_node, type="PROCESS", color="salmon")

    try:
        with Sandbox.create() as sandbox:
            def handle_files_change(event):
                file_node = event.path.split("/")[-1]
                if file_node:
                    G.add_node(file_node, type="FILE", color="skyblue")
                    G.add_edge(root_node, file_node, action=event.operation)
                analysis_events.append({"type": "FILESYSTEM", "data": event.path})

            sandbox.files.on_change = handle_files_change
            sandbox.files.watch_dir("/home/user")
            
            # Write the injection script and the malware
            sandbox.files.write("/home/user/mock.js", WINDOWS_MOCK)
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                malware_content = f.read()
            sandbox.files.write("/home/user/malware.js", malware_content)
            
            print(f"Detonating {filename} in advanced simulation mode...")
            
            execution = sandbox.commands.run(
                "node --require /home/user/mock.js /home/user/malware.js",
                on_stdout=lambda msg: analysis_events.append({"type": "STDOUT", "data": msg}),
                on_stderr=lambda msg: analysis_events.append({"type": "STDERR", "data": msg}),
                timeout=60 
            )

            # Build Graph nodes from simulation logs
            for event in analysis_events:
                if event.get("type") == "STDOUT":
                    msg = event.get("data", "")
                    # Filter for specific simulation markers
                    if any(tag in msg for tag in ["[MOCK", "[WSCRIPT", "[SYSTEM"]):
                        # Log it to terminal so you know it's working
                        print(f"[MALWARE LOG] {msg.strip()}")
                        try:
                            # Parse out the action detail for the node label
                            detail = msg.split("] ")[-1].strip()
                            if detail and detail not in G:
                                G.add_node(detail, type="ACTION", color="gold")
                                G.add_edge(root_node, detail, action="INTENT")
                        except:
                            pass

            return G
    except Exception as e:
        print(f"Session Error: {e}")
        return G

def visualize_results(G):
    if not G or len(G.nodes) <= 1:
        print("No behavior data collected. Ensure the .js file is in the script directory.")
        return

    plt.figure(figsize=(14, 10))
    # Higher k value spreads nodes out more for larger graphs
    pos = nx.spring_layout(G, k=1.2)
    
    node_colors = [G.nodes[n].get("color", "gray") for n in G.nodes()]
    
    nx.draw(G, pos, with_labels=True, node_color=node_colors, 
            node_size=3500, font_size=7, font_weight="bold", 
            arrows=True, edge_color="silver", width=1.5)
    
    edge_labels = nx.get_edge_attributes(G, 'action')
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)
    
    plt.title("Agent Tesla: Comprehensive Behavioral Mapping")
    plt.show()

# --- EXECUTION ---
behavior_graph = analyze_malware_with_graph("6108674530.JS.malicious")
visualize_results(behavior_graph)