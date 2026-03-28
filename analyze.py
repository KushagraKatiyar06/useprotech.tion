import jsbeautifier
import re
import math
import json
import sys

def analyze_js(filepath):
    result = {}
    
    with open(filepath, 'r', errors='ignore') as f:
        raw_code = f.read()
    
    #Deobfuscate/beautify
    beautified = jsbeautifier.beautify(raw_code)
    result["raw_length"] = len(raw_code)
    result["is_obfuscated"] = detect_obfuscation(raw_code)
    
    #Extracts suspicious strings
    urls = re.findall(r'https?://[^\s\'"]+', beautified)
    ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', beautified)
    result["urls_found"] = urls
    result["ips_found"] = ips
    
    #Flags dangerous functions
    dangerous = [
        "eval", "exec", "spawn",
        "XMLHttpRequest", "fetch",
        "require('child_process')",
        "require('fs')",
        "base64", "atob", "btoa",
        "unescape", "fromCharCode"
    ]
    found_dangerous = [d for d in dangerous if d in beautified]
    result["dangerous_functions"] = found_dangerous
    
    result["entropy"] = calculate_entropy(raw_code)
    
    #Behavior classification
    result["behaviors"] = classify_behaviors(found_dangerous, urls, ips)
    
    return result

def detect_obfuscation(code):
    lines = code.split('\n')
    avg_line_length = sum(len(l) for l in lines) / max(len(lines), 1)
    return avg_line_length > 500

def classify_behaviors(funcs, urls, ips):
    behaviors = []
    if "eval" in funcs:
        behaviors.append("Dynamic code execution")
    if "spawn" in funcs or "child_process" in str(funcs):
        behaviors.append("Command execution")
    if urls or ips:
        behaviors.append("Network communication")
    if "fs" in str(funcs):
        behaviors.append("File system access")
    if "base64" in str(funcs) or "fromCharCode" in str(funcs):
        behaviors.append("Encoding/obfuscation")
    return behaviors

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
    
    filepath = sys.argv[1]
    result = analyze_js(filepath)
    print(json.dumps(result, indent=2))