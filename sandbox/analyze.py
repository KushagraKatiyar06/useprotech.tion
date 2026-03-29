import jsbeautifier
import re
import math
import json
import sys
import base64

def analyze_js(filepath):
    result = {}
    
    with open(filepath, 'r', errors='ignore') as f:
        raw_code = f.read()
    
    deobfuscated = raw_code.replace('IMLRHNEGA', '')
    deobfuscated = re.sub(r'%{2,}', '', deobfuscated)
    deobfuscated = deobfuscated.replace('\\x5c', '\\')
    beautified = jsbeautifier.beautify(deobfuscated)

    result["raw_length"] = len(raw_code)
    result["deobfuscated_length"] = len(deobfuscated)
    result["deobfuscation_applied"] = "IMLRHNEGA removal + %% padding strip + \\x5c unescape"
    result["is_obfuscated"] = detect_obfuscation(raw_code)
    result["entropy"] = calculate_entropy(raw_code)
    result["urls_found"] = re.findall(r'https?://[^\s\'"]+', beautified)
    result["ips_found"] = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', beautified)
    result["file_paths"] = list(set(re.findall(
        r'[A-Za-z]:\\[^\s\'"<>|)]+|%[A-Z]+%\\[^\s\'"<>|)]+', beautified
    )))
    result["possible_aes_keys"] = list(set(re.findall(
        r'["\']([A-Za-z0-9+/]{43}=)["\']', beautified
    )))
    result["possible_aes_ivs"] = list(set(re.findall(
        r'["\']([A-Za-z0-9+/]{24})["\']', beautified
    )))
    b64_blobs = re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', beautified)
    result["base64_blobs_found"] = len(b64_blobs)
    result["decoded_base64_preview"] = decode_base64_blobs(b64_blobs[:3])
    result["dropped_files"] = extract_dropped_files(beautified)
    result["registry_keys"] = list(set(re.findall(
        r'HK[A-Z]{2,}\\[^\s\'"<>|)]+', beautified
    )))

    dangerous = [
        "eval", "exec", "spawn",
        "XMLHttpRequest", "fetch",
        "base64", "atob", "btoa",
        "unescape", "fromCharCode",
        "WScript.Shell", "ActiveXObject",
        "Scripting.FileSystemObject",
        "ADODB.Stream", "powershell",
        "cmd.exe", "Invoke-Expression",
        "iex", "FromBase64String",
        "VirtualAlloc", "WriteProcessMemory",
        "AmsiScanBuffer", "EtwEventWrite",
        "Reflection.Assembly"
    ]
    result["dangerous_functions"] = [d for d in dangerous if d.lower() in beautified.lower()]
    result["behaviors"] = classify_behaviors(beautified, result["dangerous_functions"])
    result["mitre_techniques"] = map_to_mitre(result["behaviors"])
    result["dropped_files"] = extract_dropped_files(beautified)
    result["threat_level"] = calculate_threat_level(result)
    result["classification"] = "Dropper/Loader with fileless execution"
    result["sandbox"] = "E2B cloud sandbox"
    result["analysis_type"] = "static + deobfuscation"

    return result


def decode_base64_blobs(blobs):
    decoded = []
    for blob in blobs:
        try:
            text = base64.b64decode(blob).decode('utf-8', errors='ignore')
            readable = ''.join(c for c in text if 32 <= ord(c) < 127)
            if len(readable) > 20:
                decoded.append(readable[:300])
        except:
            pass
    return decoded


def extract_dropped_files(code):
    paths = re.findall(
        r'(?:C:\\Users\\Public\\|%PUBLIC%\\|%TEMP%\\|%APPDATA%\\)[^\s\'"<>|,)]+',
        code, re.IGNORECASE
    )
    return list(set(paths))


def classify_behaviors(code, funcs):
    behaviors = []
    code_lower = code.lower()
    if "eval" in funcs or "invoke-expression" in code_lower or "iex" in code_lower:
        behaviors.append("Dynamic code execution")
    if "wscript.shell" in code_lower or "activexobject" in code_lower:
        behaviors.append("Windows scripting host abuse")
    if "powershell" in code_lower:
        behaviors.append("PowerShell execution")
    if "frombase64string" in code_lower or "atob" in code_lower:
        behaviors.append("Base64 decoding")
    if "adodb.stream" in code_lower:
        behaviors.append("Binary file write to disk")
    if "scripting.filesystem" in code_lower:
        behaviors.append("File system access")
    if "reflection.assembly" in code_lower:
        behaviors.append("Reflective .NET assembly loading (fileless)")
    if "amsi" in code_lower or "amsiscanbuffer" in code_lower:
        behaviors.append("AMSI bypass - antivirus evasion")
    if "etweventwrite" in code_lower or "etweve" in code_lower:
        behaviors.append("ETW patching - event log evasion")
    if "virtualalloc" in code_lower or "writeprocessmemory" in code_lower:
        behaviors.append("Process memory manipulation")
    if re.search(r'[A-Za-z0-9+/]{43}=', code):
        behaviors.append("Hardcoded AES key detected")
    if len(re.findall(r'[A-Za-z0-9+/]{100,}={0,2}', code)) > 0:
        behaviors.append("Large Base64 payload - likely encrypted executable")
    if "aes" in code_lower and ("cbc" in code_lower or "key" in code_lower):
        behaviors.append("AES encryption/decryption")
    if "c:\\users\\public" in code_lower or "%public%" in code_lower:
        behaviors.append("Drops files to public directory")
    return behaviors


def map_to_mitre(behaviors):
    behavior_map = {
        "Dynamic code execution": "T1059.007 - JavaScript/Command Scripting",
        "PowerShell execution": "T1059.001 - PowerShell",
        "Base64 decoding": "T1140 - Deobfuscate/Decode Files",
        "Binary file write to disk": "T1105 - Ingress Tool Transfer",
        "Reflective .NET assembly loading (fileless)": "T1620 - Reflective Code Loading",
        "AMSI bypass - antivirus evasion": "T1562.001 - Disable Security Tools",
        "ETW patching - event log evasion": "T1562.006 - Indicator Blocking",
        "Process memory manipulation": "T1055 - Process Injection",
        "Hardcoded AES key detected": "T1027 - Obfuscated Files",
        "Windows scripting host abuse": "T1059.005 - WScript Abuse",
        "Large Base64 payload - likely encrypted executable": "T1027 - Obfuscated Files",
        "File system access": "T1083 - File and Directory Discovery",
        "AES encryption/decryption": "T1140 - Deobfuscate/Decode Files",
        "Drops files to public directory": "T1105 - Ingress Tool Transfer",
    }
    return list(set([behavior_map[b] for b in behaviors if b in behavior_map]))


def calculate_threat_level(result):
    score = 0
    high_risk = [
        "Reflective .NET assembly loading (fileless)",
        "AMSI bypass - antivirus evasion",
        "ETW patching - event log evasion",
        "Process memory manipulation"
    ]
    medium_risk = [
        "PowerShell execution",
        "Binary file write to disk",
        "Hardcoded AES key detected",
        "Large Base64 payload - likely encrypted executable",
        "AES encryption/decryption"
    ]
    for b in result.get("behaviors", []):
        if b in high_risk:
            score += 3
        elif b in medium_risk:
            score += 2
        else:
            score += 1
    if score >= 8:
        return "CRITICAL"
    elif score >= 5:
        return "HIGH"
    elif score >= 3:
        return "MEDIUM"
    return "LOW"


def detect_obfuscation(code):
    lines = code.split('\n')
    avg = sum(len(l) for l in lines) / max(len(lines), 1)
    return avg > 500


def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = data.count(chr(x)) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return round(entropy, 2)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <filepath>")
        sys.exit(1)
    result = analyze_js(sys.argv[1])
    print(json.dumps(result, indent=2))