"""
Adaptive Malware Sandbox — e2b_adaptive_sandbox.py

Strategy:
  1. Run malware in e2b sandbox with current mock
  2. Collect all stdout/stderr
  3. On crash, send error + current mock to Gemini → it generates a JS patch
  4. Append patch to mock, re-run
  5. Loop until clean exit, stuck (same error N times), or safety cap
  6. Build rich behavioral graph: NET / EXEC / FILE / REG / WMI / ACTIVEX nodes
"""

import os
import re
import json
import hashlib
import networkx as nx
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from google import genai
from google.genai import types
from pathlib import Path
from dotenv import load_dotenv
from e2b_code_interpreter import Sandbox

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).parent.absolute()
load_dotenv(dotenv_path=SCRIPT_DIR / ".env")

MAX_ITERATIONS  = 50   # safety cap — loop stops earlier on clean exit or stuck
STUCK_THRESHOLD = 3    # stop if the same error repeats this many times in a row
RUN_TIMEOUT     = 45   # seconds per sandbox run

# ---------------------------------------------------------------------------
# Base Windows mock — choose how bare to start
# ---------------------------------------------------------------------------

# OPTION A: truly empty — Gemini must build everything from scratch
BASE_WINDOWS_MOCK_EMPTY = r"""
console.log('[SYSTEM] Bare sandbox started — no mock loaded.');
"""

# OPTION B: just the catch-all proxy (Gemini prompt tells it patches can reference this)
BASE_WINDOWS_MOCK_CATCHALL_ONLY = r"""
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + prop);
        }
        return function() { return this; };
    }
};
console.log('[SYSTEM] Bare sandbox started — only catchAll defined.');
"""

# OPTION C: original full mock (reference baseline)
BASE_WINDOWS_MOCK_FULL = r"""
const catchAll = {
    get: function(target, prop) {
        if (prop in target) return target[prop];
        if (typeof prop === 'string' && prop.length < 100) {
            console.log('[MOCK ATTEMPT] Called: ' + prop);
        }
        return function() { return this; };
    }
};

global.GetObject = function(path) {
    console.log('[MOCK WMI] Querying: ' + path);
    return new Proxy({
        ExecQuery: (query) => {
            console.log('[MOCK WMI] Executed: ' + query);
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

    if (type.includes('XMLHTTP') || type.includes('WinHttp')) {
        return new Proxy({
            Open: (method, url) => console.log('[MOCK NET] Connecting to: ' + url),
            Send: (data) => console.log('[MOCK NET] Sending exfiltration data...'),
            Status: 200,
            ResponseText: '{"status":"success","country":"US","org":"Business Network"}'
        }, catchAll);
    }

    if (type.includes('Stream')) {
        return new Proxy({
            Open: () => console.log('[MOCK STREAM] Opened Connection'),
            WriteText: (t) => console.log('[MOCK STREAM] Writing payload chunk'),
            SaveToFile: (p) => console.log('[MOCK ATTEMPT] SaveToFile: ' + p),
            Close: () => {}
        }, catchAll);
    }

    if (type.includes('Shell')) {
        return new Proxy({
            Run: (cmd) => console.log('[MOCK ATTEMPT] Run Command: ' + cmd),
            ExpandEnvironmentStrings: (s) => s.replace('%TEMP%', '/tmp').replace('%PUBLIC%', '/home/user'),
            RegRead: (key) => {
                console.log('[MOCK REG] Reading: ' + key);
                if (key.includes('Foxmail') || key.includes('Aerofox')) return 'C:\\Users\\Public\\Foxmail';
                return "1";
            }
        }, catchAll);
    }

    return new Proxy({
        FileExists: (path) => { console.log('[MOCK FS] Checking: ' + path); return true; },
        GetFolder: (path) => ({ Files: [] }),
        CreateTextFile: (path) => { console.log('[MOCK FS] Creating: ' + path); return { Write: () => {}, Close: () => {} }; },
        DeleteFile: (path) => console.log('[MOCK FS] Self-Deletion Attempt: ' + path),
        createElement: (tag) => { return { appendChild: () => {}, text: "" }; }
    }, catchAll);
};

global.WScript = new Proxy({
    CreateObject: (type) => new ActiveXObject(type),
    Sleep: (ms) => console.log('[MOCK TIME] Skipping sleep: ' + ms + 'ms'),
    ScriptName: '6108674530.js',
    Echo: (m) => console.log('[WSCRIPT] ' + m)
}, catchAll);

global.IMLRHNEGARRR = function() { return ""; };
global.IMLRHNEGARR  = function() { return ""; };

console.log('[SYSTEM] Adaptive Simulation Layer Active.');
"""

# --- Active mock: swap between EMPTY / CATCHALL_ONLY / FULL to test ---
BASE_WINDOWS_MOCK = BASE_WINDOWS_MOCK_CATCHALL_ONLY

# ---------------------------------------------------------------------------
# MITRE ATT&CK context — behaviors confirmed in the real sandbox report
# Used to prime Gemini so it anticipates what the malware will do next
# ---------------------------------------------------------------------------
MITRE_TTP_CONTEXT = """
This sample is an Agent Tesla dropper (JS → PowerShell → reflective .NET PE loader).
Confirmed TTPs from sandbox analysis:

EXECUTION
  T1059.001 PowerShell  — WScript.Shell.Run("powershell -enc <base64>") called multiple times
  T1059.007 JavaScript  — obfuscated JS with custom string decoder (IMLRHNEGARR*)
  T1047     WMI         — used for VM fingerprinting and system info gathering

DISCOVERY / ANTI-VM
  T1082  System Info     — WMI: SELECT * FROM Win32_Processor, Win32_ComputerSystem,
                           Win32_BaseBoard, Win32_VideoController
  T1016  Network Config  — WMI: Win32_NetworkAdapterConfiguration (MAC address check)
  T1012  Query Registry  — HKCU\\Software\\Aerofox\\Foxmail\\V3.1 (credential target)
                           Also checks AV/sandbox registry keys (Comodo IceDragon etc.)
  T1497  VM Evasion      — checks for VMware, SbieDll.dll, snxhk.dll, SxIn.dll, cmdvrt32.dll

DEFENSE EVASION
  T1027  Obfuscation     — AES-encrypted payload, Base64, custom encoding
  T1620  Reflective Load — .NET PE loaded in memory without touching disk

COLLECTION / C2
  T1056  Input Capture   — keylogger, screen capture (Agent Tesla payload)
  T1071  Web Protocols   — HTTP to ip-api.com (?fields=hosting — checks if on hosting/VM)
                         — HTTPS to account.dyn.com (DynDNS C2)
  T1555  Password Stores — FTP clients: FileZilla, WinSCP, SmartFTP, CoreFTP, FTPGetter
                         — Email: Foxmail/Aerofox
                         — Browser credentials, Windows Vault

FILE ARTIFACTS
  C:\\Users\\Public\\Mands.png — checked and deleted (dropper cleanup)
  C:\\Users\\Public\\Vile.png  — checked and deleted (dropper cleanup)
  C:\\Users\\Public\\mock_script.url — checked (dropper stage marker)
"""

# ---------------------------------------------------------------------------
# Windows API stub catalog — reference implementations Gemini can use
# Indexed by error pattern → canonical Node.js stub
# ---------------------------------------------------------------------------
WINDOWS_API_CATALOG = """
=== WINDOWS API STUB CATALOG FOR NODE.JS ===
Use these as reference when generating patches. Adapt as needed.

--- WScript (T1059.007) ---
global.WScript = {
  ScriptName: 'dropper.js',
  ScriptFullName: 'C:\\\\Users\\\\Public\\\\dropper.js',
  Echo: (m) => console.log('[MOCK PATCH] WScript.Echo: ' + m),
  Sleep: (ms) => console.log('[MOCK PATCH] WScript.Sleep: ' + ms + 'ms'),
  Quit: (code) => console.log('[MOCK PATCH] WScript.Quit: ' + code),
  CreateObject: (t) => new ActiveXObject(t),
  Arguments: { length: 0, Item: () => '' },
};

--- WScript.Shell → Run (T1059.001 PowerShell execution) ---
// Inside ActiveXObject handler for type.includes('Shell'):
{
  Run: (cmd, style, wait) => {
    console.log('[MOCK PATCH] WScript.Shell.Run: ' + cmd);
    return 0;
  },
  Exec: (cmd) => {
    console.log('[MOCK PATCH] WScript.Shell.Exec: ' + cmd);
    return { StdOut: { ReadAll: () => '' }, StdErr: { ReadAll: () => '' }, Status: 0 };
  },
  ExpandEnvironmentStrings: (s) => s.replace(/%TEMP%/g,'/tmp').replace(/%PUBLIC%/g,'/home/user').replace(/%APPDATA%/g,'/home/user/.config').replace(/%WINDIR%/g,'C:\\\\Windows'),
  RegRead: (key) => {
    console.log('[MOCK PATCH] WScript.Shell.RegRead: ' + key);
    if (key.includes('Foxmail') || key.includes('Aerofox')) return 'C:\\\\Users\\\\Public\\\\Foxmail';
    if (key.includes('IceDragon') || key.includes('Comodo')) return '';
    return '1';
  },
  RegWrite: (key, val) => console.log('[MOCK PATCH] WScript.Shell.RegWrite: ' + key + ' = ' + val),
  RegDelete: (key) => console.log('[MOCK PATCH] WScript.Shell.RegDelete: ' + key),
  Environment: (t) => new Proxy({ Item: (k) => '' }, catchAll),
}

--- GetObject / WMI (T1047, T1082, T1016, T1497) ---
global.GetObject = function(path) {
  console.log('[MOCK PATCH] GetObject: ' + path);
  return new Proxy({
    ExecQuery: function(query) {
      console.log('[MOCK PATCH] WMI ExecQuery: ' + query);
      if (query.includes('Win32_Processor'))
        return [{ Name: 'Intel(R) Core(TM) i7', NumberOfCores: 4, ProcessorId: 'BFEBFBFF000906EA' }];
      if (query.includes('Win32_VideoController'))
        return [{ Name: 'NVIDIA GeForce RTX 3080', VideoProcessor: 'NVIDIA' }];
      if (query.includes('Win32_NetworkAdapterConfiguration'))
        return [{ MACAddress: '00:1A:2B:3C:4D:5E', IPAddress: ['192.168.1.100'] }];
      if (query.includes('Win32_ComputerSystem') || query.includes('Win32_BaseBoard'))
        return [{ Manufacturer: 'Dell Inc.', Model: 'OptiPlex 7090', SerialNumber: 'ABC123' }];
      return [{}];
    },
    Get: (cls) => { console.log('[MOCK PATCH] WMI Get: ' + cls); return {}; }
  }, catchAll);
};

--- WinHttp / XMLHTTP (T1071.001 — Network C2) ---
// Inside ActiveXObject handler for type.includes('WinHttp') or type.includes('XMLHTTP'):
{
  open: (method, url, async) => console.log('[MOCK PATCH] HTTP ' + method + ': ' + url),
  send: (data) => console.log('[MOCK PATCH] HTTP send'),
  setRequestHeader: (k, v) => {},
  responseText: '{"status":"success","country":"US","org":"Business Network","hosting":false}',
  responseBody: new Uint8Array(0),
  status: 200,
  statusText: 'OK',
}

--- ADODB.Stream (T1027 — binary payload write) ---
// Inside ActiveXObject handler for type.includes('Stream') or type.includes('ADODB'):
{
  Open: () => console.log('[MOCK PATCH] ADODB.Stream.Open'),
  Write: (d) => console.log('[MOCK PATCH] ADODB.Stream.Write: ' + (d ? d.length : 0) + ' bytes'),
  WriteText: (t) => console.log('[MOCK PATCH] ADODB.Stream.WriteText'),
  SaveToFile: (p, mode) => console.log('[MOCK PATCH] ADODB.Stream.SaveToFile: ' + p),
  LoadFromFile: (p) => console.log('[MOCK PATCH] ADODB.Stream.LoadFromFile: ' + p),
  Read: (n) => new Uint8Array(0),
  ReadText: () => '',
  Close: () => {},
  Position: 0,
  Size: 0,
  Type: 1,
  Charset: 'utf-8',
}

--- Microsoft.XMLDOM (payload extraction via XML) ---
// Inside ActiveXObject handler for type.includes('XMLDOM') or type.includes('DOMDocument'):
{
  createElement: (tag) => {
    console.log('[MOCK PATCH] XMLDOM.createElement: ' + tag);
    return new Proxy({ text: '', dataType: '', nodeTypedValue: new Uint8Array(0),
                       appendChild: () => {}, getAttribute: () => '', setAttribute: () => {} }, catchAll);
  },
  createTextNode: (t) => ({ data: t }),
  loadXML: (xml) => { console.log('[MOCK PATCH] XMLDOM.loadXML'); return true; },
  load: (path) => { console.log('[MOCK PATCH] XMLDOM.load: ' + path); return true; },
  getElementsByTagName: (tag) => [],
  documentElement: new Proxy({}, catchAll),
  async: false,
}
"""

# ---------------------------------------------------------------------------
# Gemini patch generator — gemini-2.5-pro + MITRE context + API catalog
# ---------------------------------------------------------------------------
def ask_gemini_for_patch(error_output: str, current_mock: str, iteration: int,
                         mock_broke: bool = False) -> str:
    """
    Ask Gemini 2.5 Pro to generate a JS patch for the current crash.
    Gemini receives full MITRE TTP context + Windows API catalog so it can
    anticipate upcoming behaviors, not just fix the immediate error.
    mock_broke=True means the previous patch itself broke mock.js.
    """
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

    system_prompt = (
        "You are a malware sandbox engineer. You are building a Windows API mock that runs "
        "in Node.js (Linux) so a security researcher can observe malware behavior without it crashing.\n\n"

        "=== CRITICAL NODE.JS ENVIRONMENT RULES ===\n"
        "- This is Node.js on Linux. There is NO ActiveXObject, WScript, GetObject, Shell natively.\n"
        "- You MUST use 'global.X = ...' to define any Windows global.\n"
        "- NEVER reference a global at top level of a patch unless you defined it in that same patch.\n"
        "- If extending an existing global, guard it: if (typeof X !== 'undefined') { ... }\n"
        "- catchAll Proxy handler is always in scope if it appears in the current mock.\n"
        "- Every stub MUST log via console.log with a [MOCK PATCH] prefix.\n"
        "- Never throw. Always return a sensible Windows API value.\n"
        "- Output ONLY valid JavaScript — no markdown, no code fences, no explanations.\n\n"

        + MITRE_TTP_CONTEXT + "\n\n"
        + WINDOWS_API_CATALOG
    )

    if mock_broke:
        user_msg = (
            f"=== ITERATION {iteration}: YOUR PATCH BROKE mock.js ===\n"
            f"Error in mock.js (your patch caused this):\n{error_output.strip()}\n\n"
            f"Root cause: your patch referenced a global that wasn't defined yet.\n"
            f"Fix: DEFINE the global with 'global.X = ...' instead of referencing it.\n\n"
        )
    else:
        user_msg = (
            f"=== ITERATION {iteration}: malware.js CRASH ===\n"
            f"{error_output.strip()}\n\n"
        )

    user_msg += (
        f"=== CURRENT mock.js (last 3000 chars) ===\n"
        f"{current_mock[-3000:]}\n\n"
        f"Using the MITRE TTP context and API catalog in your system prompt as reference, "
        f"generate the JS patch that fixes this crash AND stubs any APIs this malware will "
        f"likely call next based on its known behavior chain. Keep it tight — fix what's "
        f"broken and pre-stub the next logical step."
    )

    response = client.models.generate_content(
        model="gemini-2.5-pro",
        config=types.GenerateContentConfig(system_instruction=system_prompt),
        contents=user_msg,
    )
    patch = response.text.strip()

    # Strip accidental markdown fences
    patch = re.sub(r'^```[a-z]*\n?', '', patch)
    patch = re.sub(r'\n?```$', '', patch)
    return patch.strip()


# ---------------------------------------------------------------------------
# Single sandbox run
# ---------------------------------------------------------------------------
def run_once(sandbox: Sandbox, mock_js: str, malware_js: str) -> tuple[list, bool, str]:
    """
    Write files, execute, collect events.
    Returns (events, clean_exit, stderr_text).
    """
    events: list[dict] = []
    stderr_lines: list[str] = []

    sandbox.files.write("/home/user/mock.js", mock_js)
    sandbox.files.write("/home/user/malware.js", malware_js)

    try:
        result = sandbox.commands.run(
            "node --require /home/user/mock.js /home/user/malware.js",
            on_stdout=lambda msg: events.append({"type": "STDOUT", "data": msg}),
            on_stderr=lambda msg: (
                events.append({"type": "STDERR", "data": msg}),
                stderr_lines.append(msg),
            ),
            timeout=RUN_TIMEOUT,
        )
        clean = result.exit_code == 0
    except Exception as e:
        # e2b raises on non-zero exit; stderr may come via callback or exception message
        clean = False
        if not stderr_lines:
            # exception message contains the stderr — strip the "Command exited..." prefix
            err_str = str(e)
            stderr_lines.append(err_str)

    stderr_text = "\n".join(stderr_lines)
    return events, clean, stderr_text


# ---------------------------------------------------------------------------
# Behavior tag → (graph node type, color, edge label)
# ---------------------------------------------------------------------------
TAG_RULES = [
    # More specific rules first — order matters
    # (substring to match,             node_type,   color,        edge_label)

    # Execution
    ("[MOCK PATCH] WScript.Shell.Run",  "EXEC",      "#FF4500",    "EXECUTE"),
    ("[MOCK PATCH] WScript.Shell.Exec", "EXEC",      "#FF4500",    "EXECUTE"),
    ("[MOCK ATTEMPT] Run",              "EXEC",      "#FF4500",    "EXECUTE"),

    # Network
    ("[MOCK PATCH] HTTP open",          "NETWORK",   "#FF6B6B",    "HTTP_REQUEST"),
    ("[MOCK PATCH] HTTP send",          "NETWORK",   "#FF6B6B",    "HTTP_SEND"),
    ("[MOCK NET]",                      "NETWORK",   "#FF6B6B",    "CONNECT"),

    # Registry
    ("[MOCK PATCH] WScript.Shell.RegRead",  "REGISTRY", "#DA70D6", "REG_READ"),
    ("[MOCK PATCH] WScript.Shell.RegWrite", "REGISTRY", "#DA70D6", "REG_WRITE"),
    ("[MOCK REG]",                          "REGISTRY", "#DA70D6", "REG_READ"),

    # WMI
    ("[MOCK PATCH] WMI ExecQuery",      "WMI",       "#90EE90",    "WMI_QUERY"),
    ("[MOCK PATCH] GetObject",          "WMI",       "#90EE90",    "WMI_OPEN"),
    ("[MOCK WMI]",                      "WMI",       "#90EE90",    "WMI_QUERY"),

    # File system
    ("[MOCK PATCH] FileSystemObject.FileExists",  "FILE", "#00BFFF", "FILE_CHECK"),
    ("[MOCK PATCH] FileSystemObject.DeleteFile",  "FILE", "#00BFFF", "FILE_DELETE"),
    ("[MOCK PATCH] FileSystemObject.CreateTextFile","FILE","#00BFFF","FILE_CREATE"),
    ("[MOCK PATCH] FileSystemObject.OpenTextFile", "FILE", "#00BFFF","FILE_OPEN"),
    ("[MOCK FS]",                                  "FILE", "#00BFFF","FILE_OP"),

    # Stream / payload write
    ("[MOCK PATCH] ADODB.Stream",       "STREAM",    "#87CEEB",    "STREAM_OP"),
    ("[MOCK STREAM]",                   "STREAM",    "#87CEEB",    "STREAM_OP"),

    # ActiveX object creation
    ("[MOCK PATCH] new ActiveXObject",  "ACTIVEX",   "#FFD700",    "CREATE_OBJ"),
    ("[MOCK ACTIVEX]",                  "ACTIVEX",   "#FFD700",    "CREATE_OBJ"),

    # XML / payload extraction
    ("[MOCK PATCH] XMLDOM",             "ACTIVEX",   "#FFD700",    "XML_OP"),

    # Sleep / timing
    ("[MOCK PATCH] WScript.Sleep",      "SLEEP",     "#D3D3D3",    "SLEEP"),
    ("[MOCK TIME]",                     "SLEEP",     "#D3D3D3",    "SLEEP"),

    # WScript output
    ("[MOCK PATCH] WScript.Echo",       "WSCRIPT",   "#FF8C00",    "WSCRIPT_OUT"),
    ("[WSCRIPT]",                       "WSCRIPT",   "#FF8C00",    "WSCRIPT_OUT"),

    # Generic patched API — catch-all last
    ("[MOCK PATCH]",                    "PATCHED",   "#FFA500",    "PATCHED_API"),
    ("[MOCK ATTEMPT]",                  "API_CALL",  "#F0E68C",    "API_CALL"),
]

def classify_and_add(G: nx.DiGraph, root_node: str, msg: str):
    """Parse a mock log line into a typed graph node."""
    msg = msg.strip()
    for tag, ntype, color, edge_label in TAG_RULES:
        if tag in msg:
            detail = msg.split("] ", 1)[-1].strip()
            if not detail:
                return
            # Truncate long labels (e.g. base64 payloads) but keep the node
            if len(detail) > 120:
                detail = detail[:117] + "..."
            node_key = f"[{ntype}] {detail}"
            if node_key not in G:
                G.add_node(node_key, type=ntype, color=color)
                G.add_edge(root_node, node_key, action=edge_label)
            return


# ---------------------------------------------------------------------------
# Main adaptive analysis loop
# ---------------------------------------------------------------------------
def adaptive_analyze(filename: str) -> nx.DiGraph:
    full_path = SCRIPT_DIR / filename
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        malware_js = f.read()

    G = nx.DiGraph()
    root_node = filename
    G.add_node(root_node, type="PROCESS", color="salmon")

    # Resume from saved patches if they exist — avoids regenerating known-good stubs.
    # If the patches already define catchAll, skip the base mock to avoid duplicate const.
    patches_file = SCRIPT_DIR / "adaptive_patches.js"
    if patches_file.exists():
        saved = patches_file.read_text(encoding="utf-8")
        if "catchAll" in saved:
            # Patches are self-contained — use empty base to avoid duplicate declaration
            current_mock = "// === RESUMED FROM PREVIOUS RUN ===\n" + saved
        else:
            current_mock = BASE_WINDOWS_MOCK_CATCHALL_ONLY + "\n\n// === RESUMED FROM PREVIOUS RUN ===\n" + saved
        print(f"[ADAPTIVE] Resuming from {patches_file} ({len(saved)} chars of prior patches)")
    else:
        current_mock = BASE_WINDOWS_MOCK_CATCHALL_ONLY

    all_events: list[dict] = []
    patches_applied: list[str] = []
    recent_error_hashes: list[str] = []   # for stuck detection

    print(f"\n[ADAPTIVE] Starting analysis of {filename}")
    print(f"[ADAPTIVE] Safety cap: {MAX_ITERATIONS} iterations, stuck threshold: {STUCK_THRESHOLD}\n")

    try:
        with Sandbox.create() as sandbox:
            for iteration in range(1, MAX_ITERATIONS + 1):
                print(f"--- Iteration {iteration} ---")

                # File-system watcher
                def handle_fs(event, it=iteration):
                    fname = event.path.split("/")[-1]
                    if fname and fname not in ("mock.js", "malware.js"):
                        node_key = f"[FILE] {fname}"
                        G.add_node(node_key, type="FILE", color="#00BFFF")
                        G.add_edge(root_node, node_key, action=event.operation)
                    all_events.append({"type": "FILESYSTEM", "data": event.path, "iter": it})

                sandbox.files.on_change = handle_fs
                sandbox.files.watch_dir("/home/user")

                events, clean, stderr_text = run_once(sandbox, current_mock, malware_js)
                all_events.extend(events)

                # Extract behavioral graph nodes from this run's stdout
                for ev in events:
                    if ev.get("type") == "STDOUT":
                        msg = ev.get("data", "")
                        if "[MOCK" in msg or "[WSCRIPT" in msg:
                            print(f"  [LOG] {msg.strip()}")
                            classify_and_add(G, root_node, msg)

                if clean:
                    print(f"[ADAPTIVE] Clean exit on iteration {iteration}. Done.\n")
                    break

                if not stderr_text.strip():
                    print("[ADAPTIVE] Non-zero exit but no stderr. Stopping.")
                    break

                # Detect whether mock.js itself crashed (broken patch) vs malware.js
                mock_broke = "/home/user/mock.js" in stderr_text

                # Extract the actual error line (ReferenceError/TypeError/etc.)
                error_lines = re.findall(r'(?:Reference|Type|Syntax|Range|URI|Eval)Error[^\n]*', stderr_text)
                actual_error = error_lines[0].strip() if error_lines else stderr_text.split("\n")[0][:200]

                # Stuck detection — hash actual error message (not the code dump)
                err_hash = hashlib.md5(actual_error.encode()).hexdigest()
                recent_error_hashes.append(err_hash)
                if len(recent_error_hashes) >= STUCK_THRESHOLD and len(set(recent_error_hashes[-STUCK_THRESHOLD:])) == 1:
                    print(f"[ADAPTIVE] Truly stuck on: {actual_error}")
                    print(f"[ADAPTIVE] Same error {STUCK_THRESHOLD} times in a row. Stopping.")
                    break

                origin = "mock.js (broken patch!)" if mock_broke else "malware.js"
                print(f"[ADAPTIVE] Crash on iteration {iteration} [{origin}]: {actual_error}")
                print(f"[ADAPTIVE] Full stderr head:\n  {stderr_text[:400]}\n")

                if iteration == MAX_ITERATIONS:
                    print("[ADAPTIVE] Safety cap reached. Stopping.")
                    break

                print("[ADAPTIVE] Asking Gemini to patch the mock...")
                patch = ask_gemini_for_patch(stderr_text, current_mock, iteration, mock_broke=mock_broke)
                patches_applied.append(patch)
                current_mock = current_mock + "\n\n// === AUTO-PATCH (iteration " + str(iteration) + ") ===\n" + patch
                print(f"[ADAPTIVE] Patch applied ({len(patch)} chars). Retrying...\n")

    except Exception as e:
        print(f"[ADAPTIVE] Fatal sandbox error: {e}")

    # Summary
    print(f"\n[ADAPTIVE] Summary:")
    print(f"  Patches generated : {len(patches_applied)}")
    print(f"  Total events      : {len(all_events)}")
    print(f"  Graph nodes       : {len(G.nodes)}")

    node_types = {}
    for n, d in G.nodes(data=True):
        t = d.get("type", "?")
        node_types[t] = node_types.get(t, 0) + 1
    for t, count in sorted(node_types.items()):
        print(f"    {t:<12} : {count}")

    if patches_applied:
        # Count existing patches so numbering continues across runs
        existing_count = 0
        if patches_file.exists():
            existing_count = patches_file.read_text(encoding="utf-8").count("// === Patch ")
        with open(patches_file, "a", encoding="utf-8") as pf:
            for i, p in enumerate(patches_applied, existing_count + 1):
                pf.write(f"// === Patch {i} ===\n{p}\n\n")
        print(f"\n[ADAPTIVE] {len(patches_applied)} new patch(es) appended to adaptive_patches.js "
              f"(total: {existing_count + len(patches_applied)})")

    return G


# ---------------------------------------------------------------------------
# Dry-run — test current saved mock with NO Gemini calls
# Shows exactly what the malware does with what we have, and the next crash
# ---------------------------------------------------------------------------
def dry_run(filename: str):
    patches_file = SCRIPT_DIR / "adaptive_patches.js"
    if not patches_file.exists():
        print("[DRY RUN] No adaptive_patches.js found. Run adaptive_analyze first.")
        return

    full_path = SCRIPT_DIR / filename
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        malware_js = f.read()

    saved = patches_file.read_text(encoding="utf-8")
    mock_js = ("// === RESUMED FROM PREVIOUS RUN ===\n" + saved
               if "catchAll" in saved
               else BASE_WINDOWS_MOCK_CATCHALL_ONLY + "\n" + saved)

    print(f"\n[DRY RUN] Testing current mock ({len(mock_js)} chars) against {filename}")
    print("[DRY RUN] No Gemini calls — showing raw behavior + next crash\n")

    try:
        with Sandbox.create() as sandbox:
            events, clean, stderr_text = run_once(sandbox, mock_js, malware_js)

        print("[DRY RUN] === BEHAVIOR LOG ===")
        for ev in events:
            if ev.get("type") == "STDOUT":
                msg = ev.get("data", "").strip()
                if msg:
                    print(f"  {msg}")

        if clean:
            print("\n[DRY RUN] ✓ CLEAN EXIT — mock is complete!")
        else:
            error_lines = re.findall(r'(?:Reference|Type|Syntax|Range|URI|Eval)Error[^\n]*', stderr_text)
            next_crash = error_lines[0].strip() if error_lines else stderr_text.split("\n")[0]
            print(f"\n[DRY RUN] Next crash to fix: {next_crash}")
            print(f"[DRY RUN] Full error:\n  {stderr_text[:600]}")
    except Exception as e:
        print(f"[DRY RUN] Error: {e}")


# ---------------------------------------------------------------------------
# Payload encryption — Fernet symmetric encryption for sensitive output files
# ---------------------------------------------------------------------------
_PAYLOAD_KEY_FILE = SCRIPT_DIR / "payload_key.bin"


def _encrypt_payload_outputs():
    """Encrypt payload output files so they are not stored in plaintext."""
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        print("[ENCRYPT] 'cryptography' not installed — run: pip install cryptography")
        return

    if _PAYLOAD_KEY_FILE.exists():
        key = _PAYLOAD_KEY_FILE.read_bytes()
    else:
        key = Fernet.generate_key()
        _PAYLOAD_KEY_FILE.write_bytes(key)
        print(f"[ENCRYPT] New key generated → {_PAYLOAD_KEY_FILE.name}  (keep this file!)")

    f = Fernet(key)
    targets = [
        SCRIPT_DIR / "payload_decoded.ps1",
        SCRIPT_DIR / "payload_agent_tesla.bin",
    ]
    encrypted_any = False
    for fpath in targets:
        if fpath.exists():
            enc_path = fpath.with_suffix(fpath.suffix + ".enc")
            enc_path.write_bytes(f.encrypt(fpath.read_bytes()))
            fpath.unlink()
            print(f"[ENCRYPT] {fpath.name} → {enc_path.name}  (plaintext deleted)")
            encrypted_any = True

    if encrypted_any:
        print(
            "\n[ENCRYPT] To decrypt later:\n"
            "  from cryptography.fernet import Fernet\n"
            f"  key = open('{_PAYLOAD_KEY_FILE.name}', 'rb').read()\n"
            "  f = Fernet(key)\n"
            "  data = f.decrypt(open('payload_decoded.ps1.enc', 'rb').read())\n"
            "  open('payload_decoded.ps1', 'wb').write(data)\n"
        )


# ---------------------------------------------------------------------------
# Payload extraction — Option B
# Captures the PowerShell -enc command from Shell.Run, decodes the base64
# chain, extracts embedded PE bytes, and asks Gemini to enumerate the
# Agent Tesla behaviors so they appear as payload-layer nodes on the graph.
# ---------------------------------------------------------------------------
def extract_and_analyze_payload(filename: str, G: nx.DiGraph):
    import base64

    patches_file = SCRIPT_DIR / "adaptive_patches.js"
    if not patches_file.exists():
        print("[PAYLOAD] No patches found. Run adaptive_analyze first.")
        return

    full_path = SCRIPT_DIR / filename
    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
        malware_js = f.read()

    # Inject a payload-capture hook into the mock so Shell.Run writes
    # the full command with a special prefix we can grep for
    saved = patches_file.read_text(encoding="utf-8")
    capture_hook = r"""
// === PAYLOAD CAPTURE HOOK ===
(function() {
    const _origAX = global.ActiveXObject;
    global.ActiveXObject = function(type) {
        const obj = _origAX(type);
        if (type && type.toLowerCase().includes('shell')) {
            const _origRun = obj.Run ? obj.Run.bind(obj) : null;
            obj.Run = function(cmd, style, wait) {
                process.stdout.write('[PAYLOAD_CMD]' + cmd + '\n');
                return 0;
            };
        }
        return obj;
    };
})();
"""
    mock_js = ("// === RESUMED ===\n" + saved + capture_hook
               if "catchAll" in saved
               else BASE_WINDOWS_MOCK_CATCHALL_ONLY + "\n" + saved + capture_hook)

    print("\n[PAYLOAD] Running malware to capture Shell.Run command...")
    payload_cmd = None
    try:
        with Sandbox.create() as sandbox:
            events, _, _ = run_once(sandbox, mock_js, malware_js)
        for ev in events:
            if ev.get("type") == "STDOUT" and "[PAYLOAD_CMD]" in ev.get("data", ""):
                payload_cmd = ev["data"].split("[PAYLOAD_CMD]", 1)[1].strip()
                break
    except Exception as e:
        print(f"[PAYLOAD] Sandbox error: {e}")
        return

    if not payload_cmd:
        print("[PAYLOAD] No Shell.Run command captured.")
        return

    print(f"[PAYLOAD] Captured command ({len(payload_cmd)} chars)")

    # Always save the raw command for debugging
    raw_path = SCRIPT_DIR / "payload_cmd_raw.txt"
    raw_path.write_text(payload_cmd, encoding="utf-8", errors="replace")
    print(f"[PAYLOAD] Raw command saved to payload_cmd_raw.txt")

    # ------------------------------------------------------------------
    # Multi-strategy base64 decode
    # ------------------------------------------------------------------
    def _try_decode(b64_raw: str) -> str | None:
        """Try decoding a base64 candidate as UTF-16LE or UTF-8 PowerShell."""
        b64 = re.sub(r'\s', '', b64_raw)
        if len(b64) < 50:
            return None
        # Correct padding (not just always "==")
        b64 += "=" * ((4 - len(b64) % 4) % 4)
        try:
            raw_bytes = base64.b64decode(b64)
        except Exception:
            return None
        # Try each encoding in priority order
        for enc in ["utf-16-le", "utf-8-sig", "utf-8"]:
            try:
                text = raw_bytes.decode(enc, errors="strict")
                # Accept if >65% ASCII printable — avoids false positives on binary
                printable_ratio = sum(0x20 <= ord(c) < 0x7F or c in "\r\n\t" for c in text)
                if printable_ratio / max(len(text), 1) > 0.65:
                    return text
            except Exception:
                continue
        # Last resort: UTF-16LE with replacement (captures partial decode)
        try:
            return raw_bytes.decode("utf-16-le", errors="replace")
        except Exception:
            return None

    ps_script = None

    # Strategy 0: FromBase64String(('...')) wrapper — exact IMLRHNEGA strip
    # This is the obfuscation pattern used by this specific dropper.
    # The marker 'IMLRHNEGA' (9 chars) is injected at regular intervals;
    # stripping it exactly (no trailing wildcard) reveals clean base64.
    m = re.search(r"FromBase64String\(\('([^']+)'", payload_cmd)
    if m:
        b64_raw = m.group(1).replace("IMLRHNEGA", "")
        result = _try_decode(b64_raw)
        if result:
            ps_script = result
            print("[PAYLOAD] Decode strategy: FromBase64String wrapper + IMLRHNEGA strip")

    # Strategy 1: -enc / -EncodedCommand flag (standard PowerShell)
    if not ps_script:
        m = re.search(r'-[Ee]nc(?:odedCommand)?\s+([A-Za-z0-9+/=]{50,})', payload_cmd)
        if m:
            result = _try_decode(m.group(1))
            if result:
                ps_script = result
                print("[PAYLOAD] Decode strategy: -enc flag match")

    # Strategy 2: strip IMLRHNEGA markers (exact, no wildcard) then find longest b64 run
    if not ps_script:
        cleaned = payload_cmd.replace("IMLRHNEGA", "")  # exact strip, not regex
        candidates = sorted(re.finditer(r'[A-Za-z0-9+/=]{80,}', cleaned),
                            key=lambda x: len(x.group(0)), reverse=True)
        for m in candidates:
            result = _try_decode(m.group(0))
            if result:
                ps_script = result
                print("[PAYLOAD] Decode strategy: global IMLRHNEGA strip + scan")
                break

    # Strategy 3: scan raw command for long b64 segments (skip obfuscated ones)
    if not ps_script:
        candidates = sorted(re.finditer(r'[A-Za-z0-9+/=]{80,}', payload_cmd),
                            key=lambda x: len(x.group(0)), reverse=True)
        for m in candidates:
            seg = m.group(0)
            if "IMLRHNEGA" in seg:
                continue
            result = _try_decode(seg)
            if result:
                ps_script = result
                print("[PAYLOAD] Decode strategy: raw b64 scan")
                break

    if not ps_script:
        print("[PAYLOAD] All decode strategies failed — using raw command for analysis.")
        ps_script = payload_cmd
    else:
        ps_path = SCRIPT_DIR / "payload_decoded.ps1"
        ps_path.write_text(ps_script, encoding="utf-8", errors="replace")
        preview = ps_script.replace('\x00', '').strip()[:300]
        print(f"[PAYLOAD] Decoded PowerShell ({len(ps_script)} chars). Preview:\n{preview}\n")

    # Look for embedded PE (MZ header as base64: 'TVqQ' prefix)
    pe_match = re.search(r"(TVqQ[A-Za-z0-9+/=]{200,})", ps_script)
    if pe_match:
        try:
            pe_b64 = pe_match.group(1)
            pe_b64 += "=" * ((4 - len(pe_b64) % 4) % 4)
            pe_bytes = base64.b64decode(pe_b64)
            pe_path = SCRIPT_DIR / "payload_agent_tesla.bin"
            pe_path.write_bytes(pe_bytes)
            print(f"[PAYLOAD] Extracted .NET PE → payload_agent_tesla.bin ({len(pe_bytes):,} bytes)")
        except Exception as e:
            print(f"[PAYLOAD] PE extraction failed: {e}")

    # Encrypt sensitive output files before continuing
    _encrypt_payload_outputs()

    # Ask Gemini to enumerate behaviors from the decoded PowerShell/payload
    print("\n[PAYLOAD] Asking Gemini to enumerate payload-layer behaviors...")
    client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))
    response = client.models.generate_content(
        model="gemini-2.5-pro",
        config=types.GenerateContentConfig(system_instruction=(
            "You are a malware analyst. Given a PowerShell script or encoded payload from "
            "an Agent Tesla dropper, enumerate every observable behavior as a JSON array. "
            "Each item: {\"type\": \"NETWORK|REGISTRY|EXEC|FILE|WMI|CREDENTIAL\", "
            "\"detail\": \"<specific value — URL, registry key, filename, query, etc.>\"}. "
            "Be specific — use exact strings from the script where visible. "
            "Output ONLY the JSON array, no markdown."
        )),
        contents=(
            f"Analyze this decoded payload and list every behavior:\n\n"
            f"{ps_script[:6000]}"
        ),
    )

    root_node = filename
    try:
        behaviors = json.loads(response.text.strip().lstrip("```json").rstrip("```"))
        type_map = {
            "NETWORK":    ("#FF6B6B", "C2_CONNECT"),
            "REGISTRY":   ("#DA70D6", "REG_ACCESS"),
            "EXEC":       ("#FF4500", "EXECUTE"),
            "FILE":       ("#00BFFF", "FILE_OP"),
            "WMI":        ("#90EE90", "WMI_QUERY"),
            "CREDENTIAL": ("#FF1493", "CRED_THEFT"),
        }
        added = 0
        for b in behaviors:
            btype = b.get("type", "PATCHED").upper()
            detail = b.get("detail", "")[:120]
            if not detail:
                continue
            color, edge = type_map.get(btype, ("#AAAAAA", "PAYLOAD"))
            node_key = f"[{btype}][AT] {detail}"
            if node_key not in G:
                G.add_node(node_key, type=btype, color=color, layer="payload")
                G.add_edge(root_node, node_key, action=f"PAYLOAD:{edge}")
                added += 1
        print(f"[PAYLOAD] Added {added} Agent Tesla behavior nodes to graph")
    except Exception as e:
        print(f"[PAYLOAD] Could not parse Gemini response as JSON: {e}")
        print(f"[PAYLOAD] Raw response:\n{response.text[:1000]}")

    return G


# ---------------------------------------------------------------------------
# Visualization — rich multi-type graph
# ---------------------------------------------------------------------------
def visualize(G: nx.DiGraph):
    if not G or len(G.nodes) <= 1:
        print("No behavior data collected.")
        return

    n = len(G.nodes)
    fig_w = max(20, n * 0.8)
    fig_h = max(14, n * 0.5)
    plt.figure(figsize=(fig_w, fig_h))

    # Layout — more spread for large graphs
    k_val = 3.0 if n > 20 else 2.0
    pos = nx.spring_layout(G, k=k_val, seed=42)

    node_colors = [G.nodes[nd].get("color", "#AAAAAA") for nd in G.nodes()]

    # Node size: root node bigger, others by type
    type_sizes = {
        "PROCESS": 6000, "NETWORK": 3000, "EXEC": 3000,
        "REGISTRY": 2200, "WMI": 2200, "ACTIVEX": 2200,
        "FILE": 1800, "STREAM": 1800, "SLEEP": 1200,
        "PATCHED": 1500, "API_CALL": 1500, "WSCRIPT": 1800,
    }
    node_sizes = [type_sizes.get(G.nodes[nd].get("type", ""), 1500) for nd in G.nodes()]

    nx.draw(G, pos,
            with_labels=True,
            node_color=node_colors,
            node_size=node_sizes,
            font_size=6,
            font_weight="bold",
            arrows=True,
            arrowsize=12,
            edge_color="#CCCCCC",
            width=1.2)

    edge_labels = nx.get_edge_attributes(G, "action")
    nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=5)

    # Legend
    legend_items = {
        "PROCESS (root)":    "salmon",
        "NETWORK":           "#FF6B6B",
        "EXEC":              "#FF4500",
        "REGISTRY":          "#DA70D6",
        "WMI":               "#90EE90",
        "ACTIVEX":           "#FFD700",
        "FILE":              "#00BFFF",
        "STREAM":            "#87CEEB",
        "SLEEP":             "#D3D3D3",
        "API_CALL":          "#F0E68C",
        "PATCHED":           "#FFA500",
        "MITRE (HA Windows)":"#9370DB",
    }
    patches_legend = [mpatches.Patch(color=c, label=l) for l, c in legend_items.items()]
    plt.legend(handles=patches_legend, loc="upper left", fontsize=8, framealpha=0.8)

    plt.title("Adaptive Behavioral Map — Agent Tesla dropper", fontsize=14, fontweight="bold")
    plt.tight_layout()
    plt.savefig(SCRIPT_DIR / "behavior_graph.png", dpi=150, bbox_inches="tight")
    print("[VIZ] Graph saved to behavior_graph.png")
    plt.show()


# ---------------------------------------------------------------------------
# Hybrid Analysis (Windows sandbox) enrichment
# Submits the file to hybrid-analysis.com, waits for the Windows 10 report,
# then parses network / registry / process / file / MITRE nodes into the graph.
# Requires: HYBRID_ANALYSIS_API_KEY in .env  +  pip install requests
# ---------------------------------------------------------------------------
def hybrid_analysis_enrich(filename: str, G: nx.DiGraph):
    import requests
    import time

    api_key = os.environ.get("HYBRID_ANALYSIS_API_KEY")
    if not api_key:
        print("[HA] HYBRID_ANALYSIS_API_KEY not set in .env — skipping enrichment.")
        return

    full_path = SCRIPT_DIR / filename
    file_bytes = full_path.read_bytes()
    sha256 = hashlib.sha256(file_bytes).hexdigest()

    BASE = "https://www.hybrid-analysis.com/api/v2"
    hdrs = {
        "api-key": api_key,
        "User-Agent": "Falcon Sandbox",
        "Accept": "application/json",
    }
    root_node = filename

    def _extract_job_id(obj: dict) -> str | None:
        """Pull the report identifier out of any HA response shape."""
        return (obj.get("job_id") or obj.get("id") or
                obj.get("submission_id") or obj.get("sha256"))

    # --- Step 1: search for an existing Windows report by hash ---
    print(f"\n[HA] Searching for existing report (SHA256: {sha256[:16]}...)")
    job_id = None
    try:
        r = requests.post(f"{BASE}/search/hash", headers=hdrs,
                          data={"hash": sha256}, timeout=30)
        if not r.ok:
            print(f"[HA] Search HTTP {r.status_code}: {r.text[:200]}")
        else:
            raw = r.json()
            # API v2 returns {"count":N,"result":[...]} or a plain list
            results = raw.get("result", raw) if isinstance(raw, dict) else raw
            if isinstance(results, list) and results:
                for env_pref in (160, 120, 110):
                    for res in results:
                        if res.get("environment_id") == env_pref:
                            job_id = _extract_job_id(res)
                            print(f"[HA] Found existing report (env {env_pref}): {job_id}")
                            break
                    if job_id:
                        break
                if not job_id:
                    job_id = _extract_job_id(results[0])
                    print(f"[HA] Using first available report: {job_id}")
            else:
                print(f"[HA] No prior report in HA. Raw: {str(raw)[:200]}")
    except Exception as e:
        print(f"[HA] Hash search error: {e}")

    # --- Step 2: submit if no existing report found ---
    if not job_id:
        print("[HA] Submitting to Windows 10 sandbox (env 160)...")
        try:
            with open(full_path, "rb") as fh:
                r = requests.post(
                    f"{BASE}/submit/file",
                    headers=hdrs,
                    files={"file": (filename, fh, "application/octet-stream")},
                    data={"environment_id": 160, "allow_community_access": True},
                    timeout=60,
                )
            if not r.ok:
                print(f"[HA] Submit HTTP {r.status_code}: {r.text[:300]}")
                return
            sub = r.json()
            print(f"[HA] Submit response keys: {list(sub.keys())}")
            job_id = _extract_job_id(sub)
            print(f"[HA] Submitted. Job ID: {job_id}")
        except Exception as e:
            print(f"[HA] Submission failed: {e}")
            return

    if not job_id:
        print("[HA] Could not obtain a job ID. Skipping.")
        return

    # --- Step 3: poll until analysis completes (up to 10 min) ---
    print("[HA] Polling for analysis completion (up to 10 min)...")
    report = None
    for attempt in range(20):
        try:
            r = requests.get(f"{BASE}/report/{job_id}/summary",
                             headers=hdrs, timeout=30)
            data = r.json()
            state = data.get("state", "")
            if state == "SUCCESS":
                report = data
                print(f"[HA] Analysis complete.")
                break
            elif state in ("ERROR", "FAILED"):
                print(f"[HA] Analysis failed: {data.get('error', state)}")
                return
            else:
                print(f"[HA] State: {state} — waiting 30s (attempt {attempt+1}/20)...")
                time.sleep(30)
        except Exception as e:
            print(f"[HA] Poll error: {e}")
            time.sleep(15)

    if not report:
        print("[HA] Timed out waiting for report. Skipping.")
        return

    # --- Step 4: parse every behavior category into graph nodes ---
    added = 0

    def _ha_node(ntype: str, color: str, label: str, edge: str):
        nonlocal added
        node_key = f"[{ntype}][HA] {label[:110]}"
        if node_key not in G:
            G.add_node(node_key, type=ntype, color=color, layer="ha_windows")
            G.add_edge(root_node, node_key, action=f"HA:{edge}")
            added += 1

    # Network
    for net in report.get("network_list", []) or []:
        url = net.get("url") or net.get("host") or ""
        method = (net.get("request_method") or "CONNECT").upper()
        if url:
            _ha_node("NETWORK", "#FF6B6B", f"{method} {url}", "HTTP_REQUEST")

    # DNS / hosts
    for host in report.get("hosts", []) or []:
        _ha_node("NETWORK", "#FF6B6B", f"DNS {host}", "DNS_LOOKUP")

    # Registry
    for reg in report.get("registry", []) or []:
        key = reg.get("key") or reg.get("registry_key") or ""
        op  = (reg.get("operation") or "ACCESS").upper()
        if key:
            _ha_node("REGISTRY", "#DA70D6", f"{op}: {key}", "REG_ACCESS")

    # Processes
    for proc in report.get("process_list", []) or []:
        label = proc.get("cmd") or proc.get("command_line") or proc.get("name") or ""
        if label:
            _ha_node("EXEC", "#FF4500", label, "PROCESS_SPAWN")

    # File operations
    for fop in report.get("file_details", []) or []:
        path = fop.get("file_path") or fop.get("filename") or ""
        op   = (fop.get("operation") or "FILE_OP").upper()
        if path:
            _ha_node("FILE", "#00BFFF", f"{op}: {path}", "FILE_OP")

    # MITRE ATT&CK
    for m in report.get("mitre_attcks", []) or []:
        tid       = m.get("attck_id") or ""
        technique = m.get("technique") or ""
        tactic    = (m.get("tactic") or "unknown").upper()[:20]
        if tid:
            _ha_node("MITRE", "#9370DB", f"{tid}: {technique}", f"MITRE_{tactic}")

    print(f"[HA] Added {added} nodes from Windows sandbox report")


# ---------------------------------------------------------------------------
# Entry point  —  set MODE below:
#   "run"      adaptive loop (resumes from saved patches, calls Gemini for new crashes)
#   "dryrun"   single run, no Gemini, shows behavior log + next crash
#   "payload"  full pipeline: dropper graph + PS1 decode + Hybrid Analysis Windows enrich
# ---------------------------------------------------------------------------
MODE = "payload"

if __name__ == "__main__":
    TARGET = "6108674530.JS.malicious"
    if MODE == "dryrun":
        dry_run(TARGET)
    elif MODE == "payload":
        graph = adaptive_analyze(TARGET)
        extract_and_analyze_payload(TARGET, graph)
        hybrid_analysis_enrich(TARGET, graph)
        visualize(graph)
    else:
        graph = adaptive_analyze(TARGET)
        visualize(graph)
