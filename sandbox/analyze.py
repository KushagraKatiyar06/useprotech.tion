"""
UseProtechtion — Sandbox Analysis Engine
Handles: PE32/PE64 (EXE, DLL), JavaScript, PowerShell, VBScript, Batch
Returns unified structured JSON consumed by the agent pipeline.
"""

import re
import sys
import math
import json
import base64
import hashlib
import subprocess
from pathlib import Path


# ─── File type detection ────────────────────────────────────────────────────

MAGIC_BYTES = {
    b'MZ': 'PE',
}

SCRIPT_EXTENSIONS = {
    '.js': 'JS', '.jse': 'JS',
    '.ps1': 'POWERSHELL', '.psm1': 'POWERSHELL', '.psd1': 'POWERSHELL',
    '.vbs': 'VBS', '.vbe': 'VBS',
    '.bat': 'BATCH', '.cmd': 'BATCH',
    '.hta': 'HTA',
    '.wsf': 'WSF',
}

_SAFETY_SUFFIXES = {
    '.malicious', '.malware', '.mal', '.virus', '.vir', '.infected',
    '.safe', '.sample', '.bad', '.disabled', '.quarantine', '.suspect',
    '.bak', '.orig',
}


def _resolve_true_ext(filepath: str) -> str:
    """Return the real extension, stripping any trailing safety-label suffixes."""
    p = Path(filepath)
    while p.suffix.lower() in _SAFETY_SUFFIXES:
        p = Path(p.stem)
    return p.suffix.lower()


def detect_file_type(filepath: str) -> str:
    with open(filepath, 'rb') as f:
        magic = f.read(2)
    if magic == b'MZ':
        return 'PE'
    ext = _resolve_true_ext(filepath)
    if ext in SCRIPT_EXTENSIONS:
        return SCRIPT_EXTENSIONS[ext]
    # Fall back: try reading as text and sniff keywords
    try:
        with open(filepath, 'r', errors='ignore') as f:
            head = f.read(512).lower()
        if 'invoke-expression' in head or 'invoke-webrequest' in head:
            return 'POWERSHELL'
        if 'wscript' in head or 'createobject' in head:
            return 'VBS'
        if 'eval(' in head or 'function ' in head:
            return 'JS'
    except Exception:
        pass
    return 'BINARY'


# ─── Shared utilities ────────────────────────────────────────────────────────

def get_sha256(filepath: str) -> str:
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            h.update(chunk)
    return h.hexdigest()


def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = [0] * 256
    for byte in data:
        counts[byte] += 1
    for c in counts:
        if c:
            p = c / length
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def extract_iocs(text: str) -> dict:
    urls = list(set(re.findall(r'https?://[^\s\'"<>|)]{4,}', text)))
    ips  = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    domains = list(set(re.findall(
        r'\b(?:[a-zA-Z0-9\-]+\.)+(?:com|net|org|ru|cn|info|biz|io|cc)\b', text
    )))
    registry = list(set(re.findall(r'HK[A-Z_]{2,}\\[^\s\'"<>|)]+', text)))
    file_drops = list(set(re.findall(
        r'(?:C:\\Users\\Public\\|%PUBLIC%\\|%TEMP%\\|%APPDATA%\\|C:\\Windows\\Temp\\)'
        r'[^\s\'"<>|,)]+',
        text, re.IGNORECASE
    )))
    emails = list(set(re.findall(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', text
    )))
    return {
        'urls': urls[:10],
        'ips': ips[:10],
        'domains': [d for d in domains if d not in urls][:10],
        'registry_keys': registry[:10],
        'dropped_files': file_drops[:10],
        'emails': emails[:10],
    }


# ─── PE analysis tools ───────────────────────────────────────────────────────

SUSPICIOUS_API = [
    'VirtualAlloc', 'VirtualAllocEx', 'VirtualProtect',
    'WriteProcessMemory', 'ReadProcessMemory',
    'CreateRemoteThread', 'NtCreateThreadEx', 'RtlCreateUserThread',
    'SetWindowsHookEx', 'OpenProcess',
    'CreateProcess', 'ShellExecute', 'WinExec',
    'RegSetValue', 'RegCreateKey', 'RegOpenKey',
    'WSASocket', 'connect', 'send', 'recv',
    'InternetOpen', 'URLDownloadToFile', 'HttpSendRequest',
    'CryptEncrypt', 'CryptDecrypt', 'CryptAcquireContext',
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent',
    'NtQueryInformationProcess', 'ZwQueryInformationProcess',
    'GetProcAddress', 'LoadLibrary', 'LdrLoadDll',
    'AmsiScanBuffer', 'EtwEventWrite',
]


def run_strings(filepath: str) -> list:
    try:
        result = subprocess.run(
            ['strings', '-n', '6', filepath],
            capture_output=True, text=True, timeout=30
        )
        lines = [l.strip() for l in result.stdout.splitlines() if l.strip()]
        return lines
    except Exception:
        return []


def run_pefile(filepath: str) -> dict:
    try:
        import pefile
        import datetime

        pe = pefile.PE(filepath)

        sections = []
        for s in pe.sections:
            name = s.Name.decode('utf-8', errors='ignore').rstrip('\x00')
            raw = s.get_data()
            sections.append({
                'name': name,
                'virtual_address': hex(s.VirtualAddress),
                'raw_size': s.SizeOfRawData,
                'entropy': calculate_entropy(raw),
            })

        imports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    fname = imp.name.decode('utf-8', errors='ignore') if imp.name else f'ord_{imp.ordinal}'
                    imports.append(f'{dll}!{fname}')

        exports = []
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    exports.append(exp.name.decode('utf-8', errors='ignore'))

        compile_time = None
        try:
            ts = pe.FILE_HEADER.TimeDateStamp
            compile_time = str(datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc))
        except Exception:
            pass

        machine = pe.FILE_HEADER.Machine
        arch = 'x64' if machine == 0x8664 else 'x86' if machine == 0x14c else hex(machine)

        return {
            'architecture': arch,
            'compile_time': compile_time,
            'is_dll': bool(pe.is_dll()),
            'is_exe': bool(pe.is_exe()),
            'num_sections': len(sections),
            'sections': sections,
            'imports': imports[:150],
            'exports': exports[:50],
        }
    except Exception as e:
        return {'error': str(e)}


def run_exiftool(filepath: str) -> dict:
    try:
        result = subprocess.run(
            ['exiftool', '-json', filepath],
            capture_output=True, text=True, timeout=30
        )
        data = json.loads(result.stdout)
        if data:
            skip = {'SourceFile', 'ExifToolVersion', 'Directory', 'FileName', 'FilePermissions'}
            return {k: v for k, v in data[0].items() if k not in skip}
        return {}
    except Exception:
        return {}


def run_binwalk(filepath: str) -> list:
    try:
        result = subprocess.run(
            ['binwalk', '--signature', '--term', filepath],
            capture_output=True, text=True, timeout=60
        )
        lines = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and not line.startswith('DECIMAL') and not line.startswith('-') and not line.startswith('WARNING'):
                lines.append(line)
        return lines[:20]
    except Exception:
        return []


# Inline YARA rules — no external files required
INLINE_YARA_RULES = r"""
rule Suspicious_PE_Packer {
    meta: description = "Detects common PE packer signatures"
    strings:
        $upx = "UPX0" ascii
        $upx1 = "UPX1" ascii
        $mpress = "MPRESS" ascii
        $aspack = "ASPack" ascii
    condition:
        any of them
}

rule AMSI_Bypass {
    meta: description = "Detects AMSI patching strings"
    strings:
        $a = "AmsiScanBuffer" ascii nocase
        $b = "amsi.dll" ascii nocase
    condition:
        any of them
}

rule Reflective_Loader {
    meta: description = "Reflective DLL loading pattern"
    strings:
        $a = "ReflectiveLoader" ascii
        $b = "reflective_dll" ascii nocase
    condition:
        any of them
}

rule Powershell_Encoded {
    meta: description = "Encoded PowerShell command"
    strings:
        $a = "-EncodedCommand" ascii nocase
        $b = "-enc " ascii nocase
        $c = "FromBase64String" ascii nocase
    condition:
        2 of them
}

rule Ransomware_Indicators {
    meta: description = "Common ransomware behavioral strings"
    strings:
        $a = "vssadmin" ascii nocase
        $b = "shadow" ascii nocase
        $c = ".locked" ascii nocase
        $d = "your files" ascii nocase
        $e = "decrypt" ascii nocase
        $f = "ransom" ascii nocase
    condition:
        3 of them
}

rule C2_Communication {
    meta: description = "Possible C2 communication setup"
    strings:
        $a = "InternetOpen" ascii
        $b = "WinHttpOpen" ascii
        $c = "URLDownloadToFile" ascii
        $d = "HttpSendRequest" ascii
    condition:
        any of them
}
"""


def run_yara(filepath: str) -> list:
    try:
        import yara
        rules = yara.compile(source=INLINE_YARA_RULES)
        matches = rules.match(filepath, timeout=30)
        return [m.rule for m in matches]
    except ImportError:
        # yara-python not available — try CLI
        try:
            rules_path = Path(__file__).parent / 'rules'
            if rules_path.exists():
                result = subprocess.run(
                    ['yara', '-r', str(rules_path), filepath],
                    capture_output=True, text=True, timeout=30
                )
                return [l.split()[0] for l in result.stdout.splitlines() if l.strip()]
        except Exception:
            pass
        return []
    except Exception:
        return []


def classify_pe_behaviors(pe_data: dict, strings_list: list) -> list:
    all_text = ' '.join(pe_data.get('imports', []) + strings_list).lower()
    behaviors = []

    checks = [
        (['virtualallocex', 'writeprocessmemory', 'createremotethread', 'ntcreatethreadex'],
         'Process injection'),
        (['regsetvalue', 'regcreatekey'],
         'Registry persistence'),
        (['wsasocket', 'internetopen', 'urldownloadtofile', 'httpsendrequest', 'winhttpopen'],
         'Network communication'),
        (['isdebuggerpresent', 'checkremotedebuggerpresent', 'ntqueryinformationprocess'],
         'Anti-debugging'),
        (['cryptencrypt', 'cryptdecrypt', 'cryptacquirecontext'],
         'Cryptographic operations'),
        (['virtualalloc', 'getprocaddress', 'loadlibrary', 'ldrdloaddll'],
         'Dynamic code loading'),
        (['amsiscanbuffer'],
         'AMSI bypass - antivirus evasion'),
        (['etweventwrite'],
         'ETW patching - event log evasion'),
        (['setwindowshookex', 'getasynckeystate', 'getforegroundwindow'],
         'Keylogging / screen capture'),
        (['createmutex', 'openmutex'],
         'Mutex anti-reinfection check'),
        (['vssadmin', 'shadow'],
         'Shadow copy deletion (ransomware)'),
    ]

    for keywords, label in checks:
        if any(kw in all_text for kw in keywords):
            behaviors.append(label)

    if 'powershell' in all_text:
        behaviors.append('PowerShell execution')

    if any(p in all_text for p in ['http://', 'https://']):
        behaviors.append('Network C2 communication')

    for section in pe_data.get('sections', []):
        if section.get('entropy', 0) > 7.0:
            behaviors.append('Packed or encrypted section (obfuscation)')
            break

    return list(set(behaviors))


# ─── MITRE mapping (shared) ───────────────────────────────────────────────────

BEHAVIOR_TO_MITRE = {
    'Process injection':                         'T1055 - Process Injection',
    'Registry persistence':                      'T1547.001 - Registry Run Keys / Startup Folder',
    'Network communication':                     'T1071 - Application Layer Protocol',
    'Anti-debugging':                            'T1622 - Debugger Evasion',
    'Cryptographic operations':                  'T1140 - Deobfuscate/Decode Files or Information',
    'Dynamic code loading':                      'T1620 - Reflective Code Loading',
    'AMSI bypass - antivirus evasion':           'T1562.001 - Disable or Modify Tools',
    'ETW patching - event log evasion':          'T1562.006 - Indicator Blocking',
    'Keylogging / screen capture':               'T1056.001 - Keylogging',
    'Mutex anti-reinfection check':              'T1480 - Execution Guardrails',
    'Shadow copy deletion (ransomware)':         'T1490 - Inhibit System Recovery',
    'PowerShell execution':                      'T1059.001 - PowerShell',
    'Network C2 communication':                  'T1071.001 - Web Protocols',
    'Packed or encrypted section (obfuscation)': 'T1027 - Obfuscated Files or Information',
    # Script-specific
    'Dynamic code execution':                    'T1059.007 - JavaScript/Command Scripting',
    'Windows scripting host abuse':              'T1059.005 - Visual Basic',
    'Base64 decoding':                           'T1140 - Deobfuscate/Decode Files or Information',
    'Binary file write to disk':                 'T1105 - Ingress Tool Transfer',
    'Reflective .NET assembly loading (fileless)': 'T1620 - Reflective Code Loading',
    'Process memory manipulation':               'T1055 - Process Injection',
    'Hardcoded AES key detected':                'T1027 - Obfuscated Files or Information',
    'Large Base64 payload - likely encrypted executable': 'T1027 - Obfuscated Files or Information',
    'AES encryption/decryption':                 'T1140 - Deobfuscate/Decode Files or Information',
    'Drops files to public directory':           'T1105 - Ingress Tool Transfer',
    'File system access':                        'T1083 - File and Directory Discovery',
}


def map_to_mitre(behaviors: list) -> list:
    return list(set(BEHAVIOR_TO_MITRE[b] for b in behaviors if b in BEHAVIOR_TO_MITRE))


def score_and_level(behaviors: list) -> tuple:
    high = {
        'Process injection', 'AMSI bypass - antivirus evasion',
        'ETW patching - event log evasion', 'Shadow copy deletion (ransomware)',
        'Reflective .NET assembly loading (fileless)', 'Process memory manipulation',
    }
    medium = {
        'PowerShell execution', 'Cryptographic operations', 'Dynamic code loading',
        'Hardcoded AES key detected', 'Packed or encrypted section (obfuscation)',
        'Binary file write to disk', 'AES encryption/decryption', 'Network C2 communication',
    }
    score = sum(3 if b in high else 2 if b in medium else 1 for b in behaviors)
    level = 'CRITICAL' if score >= 8 else 'HIGH' if score >= 5 else 'MEDIUM' if score >= 3 else 'LOW'
    return score, level


# ─── PE analysis entry point ─────────────────────────────────────────────────

def analyze_pe(filepath: str) -> dict:
    with open(filepath, 'rb') as f:
        raw = f.read()

    strings_list = run_strings(filepath)
    pe_data      = run_pefile(filepath)
    exif_data    = run_exiftool(filepath)
    binwalk_sigs = run_binwalk(filepath)
    yara_matches = run_yara(filepath)
    dotnet       = run_dotnet_analysis(filepath)

    all_imports = pe_data.get('imports', [])
    suspicious_imports = [i for i in all_imports
                          if any(s.lower() in i.lower() for s in SUSPICIOUS_API)]

    behaviors = classify_pe_behaviors_extended(pe_data, strings_list, dotnet)
    mitre     = map_to_mitre(behaviors)
    score, threat_level = score_and_level(behaviors)

    strings_text = ' '.join(strings_list)
    iocs = extract_iocs(strings_text)

    # Merge any emails found in .NET strings into IOCs
    all_emails = list(set(iocs.get('emails', []) + dotnet.get('email_addresses', [])))

    return {
        'file_type':           'PE64' if pe_data.get('architecture') == 'x64' else 'PE32',
        'file_size_kb':        len(raw) // 1024,
        'sha256':              get_sha256(filepath),
        'entropy':             calculate_entropy(raw),
        'is_obfuscated':       any(s.get('entropy', 0) > 7.0 for s in pe_data.get('sections', [])),
        'pe_info':             pe_data,
        'dotnet':              dotnet,
        'suspicious_imports':  suspicious_imports[:30],
        'strings_sample':      [s for s in strings_list if len(s) > 8][:60],
        'yara_matches':        yara_matches,
        'binwalk_signatures':  binwalk_sigs,
        'exif_data':           exif_data,
        'urls_found':          iocs['urls'],
        'ips_found':           iocs['ips'],
        'domains_found':       iocs['domains'],
        'registry_keys':       iocs['registry_keys'],
        'dropped_files':       iocs['dropped_files'],
        'email_addresses':     all_emails,
        'credential_targets':  dotnet.get('credential_targets', []),
        'behaviors':           behaviors,
        'mitre_techniques':    mitre,
        'threat_level':        threat_level,
        'threat_score':        score,
        'dangerous_functions': suspicious_imports[:20],
    }


# ─── .NET-specific analysis ───────────────────────────────────────────────────

# Known Agent Tesla / infostealer credential targets
CREDENTIAL_TARGETS = [
    # Browsers
    'opera', 'chrome', 'firefox', 'chromium', 'edge', 'brave', 'vivaldi',
    'iexplore', 'internet explorer',
    # FTP clients
    'filezilla', 'winscp', 'coreftp', 'smartftp', 'ftp commander',
    'flashfxp', 'ftpgetter', 'ftpinfo', 'ws_ftp', 'cuteftp',
    # Email clients
    'outlook', 'foxmail', 'thunderbird', 'pocomail', 'eudora', 'thebat',
    'incredimail', 'mailbird', 'claws mail',
    # VPN / Remote
    'openvpn', 'realvnc', 'tightvnc', 'ultravnc', 'teamviewer',
    'nordvpn', 'expressvpn',
    # Crypto wallets
    'bitcoin', 'electrum', 'exodus', 'metamask', 'coinbase', 'ledger',
    'mymonero', 'jaxx',
    # System tools
    'keepass', 'lastpass', 'dashlane', '1password',
]

ANTI_ANALYSIS_STRINGS = [
    # Anti-VM
    'vmware', 'virtualbox', 'vbox', 'qemu', 'hyper-v', 'parallels',
    'vmtoolsd', 'vmsrvc', 'vmusrvc',
    # Anti-sandbox
    'sbiedll', 'snxhk', 'cuckoomon', 'pstorec', 'avghookx', 'avghooka',
    'gapz', 'wpespy', 'cmdvrt32', 'cmdvrt64',
    # Sandboxie / analysis tools
    'sandboxie', 'wireshark', 'procmon', 'procexp', 'ollydbg', 'x64dbg',
    'ida pro', 'immunity debugger', 'pestudio',
    # Anti-debug
    'isdebuggerpresent', 'checkremotedebuggerpresent',
]

KEYLOGGER_APIS = [
    'getkeystate', 'getasynckeystate', 'setwindowshookex',
    'callnexthookex', 'getforegroundwindow', 'getwindowtext',
]

SCREENSHOT_APIS = [
    'bitblt', 'getdc', 'createdca', 'createcompatiblebitmap',
    'getdibits', 'stretchblt',
]

CLIPBOARD_APIS = [
    'openclipboard', 'getclipboarddata', 'setclipboarddata', 'emptyclipboard',
]

EXFIL_APIS = [
    'send', 'smtpclient', 'mailmessage', 'networkcredential',
    'ftpwebrequest', 'httpwebrequest', 'webclient',
]


def run_dotnet_analysis(filepath: str) -> dict:
    """Extract .NET metadata using dnfile + monodis."""
    result = {
        'is_dotnet': False,
        'namespaces': [],
        'type_names': [],
        'method_names': [],
        'string_constants': [],
        'credential_targets': [],
        'anti_analysis': [],
        'keylogger_apis': [],
        'screenshot_apis': [],
        'clipboard_apis': [],
        'exfil_apis': [],
        'email_addresses': [],
        'suspicious_namespaces': [],
    }

    # dnfile for .NET metadata
    try:
        import dnfile
        dn = dnfile.dnPE(filepath)
        result['is_dotnet'] = True

        # Extract type/class names
        if hasattr(dn.net, 'mdtables'):
            td = dn.net.mdtables.TypeDef
            if td:
                for row in td:
                    ns   = str(row.TypeNamespace) if row.TypeNamespace else ''
                    name = str(row.TypeName)       if row.TypeName else ''
                    if ns and ns not in result['namespaces']:
                        result['namespaces'].append(ns)
                    if name and name not in result['type_names']:
                        result['type_names'].append(name)

            md = dn.net.mdtables.MethodDef
            if md:
                for row in md:
                    name = str(row.Name) if row.Name else ''
                    if name:
                        result['method_names'].append(name)

            us = dn.net.mdtables.UserString
            if us:
                for row in us:
                    s = str(row.String) if hasattr(row, 'String') else ''
                    if s and len(s) > 4:
                        result['string_constants'].append(s[:200])

    except ImportError:
        pass
    except Exception:
        pass

    # monodis fallback for string constants
    try:
        r = subprocess.run(
            ['monodis', '--string', filepath],
            capture_output=True, text=True, timeout=30
        )
        for line in r.stdout.splitlines():
            line = line.strip().strip('"')
            if len(line) > 4:
                result['string_constants'].append(line[:200])
    except Exception:
        pass

    # Deduplicate string constants
    result['string_constants'] = list(dict.fromkeys(result['string_constants']))[:100]

    # Now scan all extracted text for specific indicators
    all_text = ' '.join(
        result['namespaces'] + result['type_names'] +
        result['method_names'] + result['string_constants']
    ).lower()

    result['credential_targets'] = [t for t in CREDENTIAL_TARGETS if t in all_text]
    result['anti_analysis']      = [a for a in ANTI_ANALYSIS_STRINGS if a in all_text]
    result['keylogger_apis']     = [k for k in KEYLOGGER_APIS if k in all_text]
    result['screenshot_apis']    = [s for s in SCREENSHOT_APIS if s in all_text]
    result['clipboard_apis']     = [c for c in CLIPBOARD_APIS if c in all_text]
    result['exfil_apis']         = [e for e in EXFIL_APIS if e in all_text]

    # Extract email addresses
    emails = re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
                        ' '.join(result['string_constants']))
    result['email_addresses'] = list(set(emails))

    # Flag suspicious namespace patterns (obfuscated = short random names)
    result['suspicious_namespaces'] = [
        ns for ns in result['namespaces']
        if len(ns) < 6 or re.match(r'^[A-Z][a-z]{1,4}$', ns)
    ]

    return result


def classify_pe_behaviors_extended(pe_data: dict, strings_list: list,
                                    dotnet: dict) -> list:
    """Extends classify_pe_behaviors with .NET-specific indicators."""
    behaviors = classify_pe_behaviors(pe_data, strings_list)
    all_text = ' '.join(strings_list).lower()

    if dotnet.get('is_dotnet'):
        behaviors.append('.NET assembly detected')
    if dotnet.get('credential_targets'):
        behaviors.append(f"Credential harvesting: {', '.join(dotnet['credential_targets'][:5])}")
    if dotnet.get('keylogger_apis'):
        behaviors.append('Keylogging capability detected')
    if dotnet.get('screenshot_apis'):
        behaviors.append('Screen capture capability detected')
    if dotnet.get('clipboard_apis'):
        behaviors.append('Clipboard access/theft detected')
    if dotnet.get('exfil_apis'):
        behaviors.append('Data exfiltration capability (SMTP/HTTP)')
    if dotnet.get('anti_analysis'):
        behaviors.append(f"Anti-VM/sandbox evasion: {', '.join(dotnet['anti_analysis'][:3])}")
    if dotnet.get('email_addresses'):
        behaviors.append(f"Hardcoded exfil email: {dotnet['email_addresses'][0]}")
    if dotnet.get('suspicious_namespaces'):
        behaviors.append('Obfuscated .NET type names detected')
    if any(t in all_text for t in ['ip-api.com', 'checkip', 'ipinfo.io', 'myexternalip']):
        behaviors.append('External IP geolocation lookup (victim fingerprinting)')
    # NOTE: pe_data never sets a 'notes' key (run_pefile() has no such field), so
    # this check is always False / dead code. Left as-is rather than guessing
    # what should populate 'notes'.
    if 'fake_extension' in (pe_data.get('notes') or ''):
        behaviors.append('Fake file extension (masquerade)')

    return list(set(behaviors))


# ─── Script/JS analysis entry point ──────────────────────────────────────────

def analyze_script(filepath: str, file_type: str) -> dict:
    import jsbeautifier

    with open(filepath, 'r', errors='ignore') as f:
        raw_code = f.read()

    # Deobfuscation passes
    deobfuscated = raw_code.replace('IMLRHNEGA', '')
    deobfuscated = re.sub(r'%{2,}', '', deobfuscated)
    deobfuscated = deobfuscated.replace('\\x5c', '\\')
    beautified = jsbeautifier.beautify(deobfuscated)

    iocs = extract_iocs(beautified)

    possible_aes_keys = list(set(re.findall(r'["\']([A-Za-z0-9+/]{43}=)["\']', beautified)))
    possible_aes_ivs  = list(set(re.findall(r'["\']([A-Za-z0-9+/]{24})["\']', beautified)))
    b64_blobs = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', beautified)
    decoded_b64 = _decode_b64_blobs(b64_blobs[:3])

    avg_line_len = sum(len(l) for l in raw_code.split('\n')) / max(len(raw_code.split('\n')), 1)

    dangerous = [
        'eval', 'exec', 'spawn', 'XMLHttpRequest', 'fetch',
        'base64', 'atob', 'btoa', 'unescape', 'fromCharCode',
        'WScript.Shell', 'ActiveXObject', 'Scripting.FileSystemObject',
        'ADODB.Stream', 'powershell', 'cmd.exe', 'Invoke-Expression',
        'iex', 'FromBase64String', 'VirtualAlloc', 'WriteProcessMemory',
        'AmsiScanBuffer', 'EtwEventWrite', 'Reflection.Assembly',
    ]
    found_dangerous = [d for d in dangerous if d.lower() in beautified.lower()]

    behaviors = _classify_script_behaviors(beautified, found_dangerous)
    mitre     = map_to_mitre(behaviors)
    _, threat_level = score_and_level(behaviors)

    yara_matches = run_yara(filepath)

    return {
        'file_type':            file_type,
        'file_size_kb':         len(raw_code.encode()) // 1024,
        'sha256':               get_sha256(filepath),
        'entropy':              _entropy_str(raw_code),
        'is_obfuscated':        avg_line_len > 500,
        'raw_length':           len(raw_code),
        'deobfuscated_length':  len(deobfuscated),
        'deobfuscation_applied': 'IMLRHNEGA removal + %% strip + \\x5c unescape',
        'urls_found':           iocs['urls'],
        'ips_found':            iocs['ips'],
        'domains_found':        iocs['domains'],
        'registry_keys':        iocs['registry_keys'],
        'dropped_files':        iocs['dropped_files'],
        'possible_aes_keys':    possible_aes_keys,
        'possible_aes_ivs':     possible_aes_ivs,
        'base64_blobs_found':   len(b64_blobs),
        'decoded_base64_preview': decoded_b64,
        'yara_matches':         yara_matches,
        'dangerous_functions':  found_dangerous,
        'behaviors':            behaviors,
        'mitre_techniques':     mitre,
        'threat_level':         threat_level,
    }


def _entropy_str(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0.0
    for x in range(256):
        p = data.count(chr(x)) / len(data)
        if p > 0:
            entropy -= p * math.log2(p)
    return round(entropy, 2)


def _decode_b64_blobs(blobs: list) -> list:
    decoded = []
    for blob in blobs:
        try:
            text = base64.b64decode(blob).decode('utf-8', errors='ignore')
            readable = ''.join(c for c in text if 32 <= ord(c) < 127)
            if len(readable) > 20:
                decoded.append(readable[:300])
        except Exception:
            pass
    return decoded


def _classify_script_behaviors(code: str, funcs: list) -> list:
    behaviors = []
    cl = code.lower()
    func_lower = [f.lower() for f in funcs]

    if 'eval' in func_lower or 'invoke-expression' in cl or 'iex' in cl:
        behaviors.append('Dynamic code execution')
    if 'wscript.shell' in cl or 'activexobject' in cl:
        behaviors.append('Windows scripting host abuse')
    if 'powershell' in cl:
        behaviors.append('PowerShell execution')
    if 'frombase64string' in cl or 'atob' in cl:
        behaviors.append('Base64 decoding')
    if 'adodb.stream' in cl:
        behaviors.append('Binary file write to disk')
    if 'scripting.filesystem' in cl:
        behaviors.append('File system access')
    if 'reflection.assembly' in cl:
        behaviors.append('Reflective .NET assembly loading (fileless)')
    if 'amsi' in cl or 'amsiscanbuffer' in cl:
        behaviors.append('AMSI bypass - antivirus evasion')
    if 'etweventwrite' in cl:
        behaviors.append('ETW patching - event log evasion')
    if 'virtualalloc' in cl or 'writeprocessmemory' in cl:
        behaviors.append('Process memory manipulation')
    if re.search(r'[A-Za-z0-9+/]{43}=', code):
        behaviors.append('Hardcoded AES key detected')
    if len(re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', code)) > 0:
        behaviors.append('Large Base64 payload - likely encrypted executable')
    if 'aes' in cl and ('cbc' in cl or 'key' in cl):
        behaviors.append('AES encryption/decryption')
    if 'c:\\users\\public' in cl or '%public%' in cl:
        behaviors.append('Drops files to public directory')

    return behaviors


# ─── Main entry point ─────────────────────────────────────────────────────────

def analyze_file(filepath: str) -> dict:
    file_type = detect_file_type(filepath)
    file_name = Path(filepath).name

    if file_type == 'PE':
        result = analyze_pe(filepath)
    else:
        result = analyze_script(filepath, file_type)

    # Always include these top-level fields
    result['file_name'] = file_name
    result['analysis_type'] = 'static + tools'
    result['sandbox'] = 'Docker (strings + pefile + exiftool + binwalk + YARA)'
    result['classification'] = _guess_classification(result.get('behaviors', []),
                                                      result.get('yara_matches', []))
    return result


def _guess_classification(behaviors: list, yara: list) -> str:
    bstr = ' '.join(behaviors).lower()
    ystr = ' '.join(yara).lower()
    if 'shadow copy deletion' in bstr or 'ransomware' in ystr:
        return 'Ransomware'
    if 'reflective .net' in bstr or 'reflective_loader' in ystr:
        return 'Fileless Loader'
    if 'process injection' in bstr:
        return 'Injector / Loader'
    if 'credential harvesting' in bstr or 'keylogging' in bstr or 'agent_tesla' in ystr:
        return 'Infostealer / Keylogger'
    if 'network c2' in bstr or 'c2_communication' in ystr:
        return 'Backdoor / RAT'
    if 'powershell execution' in bstr or 'powershell_encoded' in ystr:
        return 'PowerShell Dropper'
    if 'base64 decoding' in bstr or 'large base64' in bstr:
        return 'Dropper / Downloader'
    if 'registry persistence' in bstr:
        return 'Persistent Malware'
    return 'Suspicious File'


if __name__ == '__main__':
    if len(sys.argv) < 2:
        print('Usage: python3 analyze.py <filepath>')
        sys.exit(1)
    output = analyze_file(sys.argv[1])
    print(json.dumps(output, indent=2))
