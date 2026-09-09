import os
import re
import zipfile
import shutil
from pathlib import Path
from typing import List, Dict, Any

STATIC_RULES = [
    # Python
    {
        "lang": "python",
        "extensions": [".py"],
        "pattern": r'\bexec\s*\(',
        "severity": "Critical",
        "title": "Dangerous 'exec()' Execution in Python",
        "desc": "Using exec() allows arbitrary dynamic code execution if input is tainted.",
        "cvss": 9.5,
        "cwe": "CWE-95"
    },
    {
        "lang": "python",
        "extensions": [".py"],
        "pattern": r'pickle\.loads?\s*\(',
        "severity": "Critical",
        "title": "Insecure Deserialization via 'pickle.loads()'",
        "desc": "Pickle deserialization of untrusted data can lead to Remote Code Execution (RCE).",
        "cvss": 9.8,
        "cwe": "CWE-502"
    },
    {
        "lang": "python",
        "extensions": [".py"],
        "pattern": r'subprocess\.(?:Popen|call|run|check_output)\s*\(.*shell\s*=\s*True',
        "severity": "High",
        "title": "Subprocess Command Execution with 'shell=True'",
        "desc": "Spawning subprocesses with shell=True is prone to shell injection attacks.",
        "cvss": 8.8,
        "cwe": "CWE-78"
    },
    {
        "lang": "python",
        "extensions": [".py"],
        "pattern": r'(?:execute|raw)\s*\(\s*f["\']|\.format\s*\(|\s*%\s*\(',
        "severity": "High",
        "title": "Potential SQL Injection via String Formatting",
        "desc": "Dynamic formatting used in database query construction instead of parameterized arguments.",
        "cvss": 8.6,
        "cwe": "CWE-89"
    },

    # JavaScript / Node
    {
        "lang": "javascript",
        "extensions": [".js", ".jsx", ".ts", ".tsx", ".vue"],
        "pattern": r'\beval\s*\(',
        "severity": "High",
        "title": "Dangerous 'eval()' in JavaScript",
        "desc": "Evaluating arbitrary strings in JavaScript poses high risk of code injection and XSS.",
        "cvss": 8.0,
        "cwe": "CWE-95"
    },
    {
        "lang": "javascript",
        "extensions": [".js", ".jsx", ".ts", ".tsx", ".html"],
        "pattern": r'innerHTML\s*=',
        "severity": "Medium",
        "title": "Direct 'innerHTML' Assignment",
        "desc": "Assigning untrusted data directly to innerHTML can lead to Cross-Site Scripting.",
        "cvss": 6.5,
        "cwe": "CWE-79"
    },
    {
        "lang": "javascript",
        "extensions": [".js", ".jsx", ".ts", ".tsx"],
        "pattern": r'child_process\.exec\s*\(',
        "severity": "High",
        "title": "Node.js 'child_process.exec()' Invocation",
        "desc": "Executing shell commands directly in Node.js backend can lead to Command Injection.",
        "cvss": 8.7,
        "cwe": "CWE-78"
    },

    # PHP
    {
        "lang": "php",
        "extensions": [".php", ".phtml"],
        "pattern": r'\b(?:system|exec|shell_exec|passthru|popen|proc_open)\s*\(',
        "severity": "Critical",
        "title": "Dangerous System Command Execution in PHP",
        "desc": "Direct invocation of system binaries or shell execution functions.",
        "cvss": 9.5,
        "cwe": "CWE-78"
    },
    {
        "lang": "php",
        "extensions": [".php"],
        "pattern": r'\bunserialize\s*\(',
        "severity": "High",
        "title": "PHP Insecure Object Deserialization ('unserialize')",
        "desc": "Unserializing untrusted user objects can invoke PHP magic methods and trigger POP chains.",
        "cvss": 8.9,
        "cwe": "CWE-502"
    },

    # General Secrets
    {
        "lang": "general",
        "extensions": [".py", ".js", ".php", ".env", ".json", ".yaml", ".yml"],
        "pattern": r'(?i)(?:password|secret|jwt_secret|api_key)\s*[:=]\s*["\'][a-zA-Z0-9_\-@#$%^&*]{8,}["\']',
        "severity": "High",
        "title": "Hardcoded Secret / Credential in Source Code",
        "desc": "Plaintext secret or password found directly hardcoded inside repository file.",
        "cvss": 7.9,
        "cwe": "CWE-798"
    }
]

def build_file_tree(root_dir: str) -> Dict[str, Any]:
    tree = {"name": os.path.basename(root_dir), "type": "directory", "children": []}
    for entry in sorted(os.scandir(root_dir), key=lambda e: (not e.is_dir(), e.name)):
        if entry.name.startswith(".") or entry.name in ["node_modules", "venv", "__pycache__", "dist", "build"]:
            continue
        if entry.is_dir():
            tree["children"].append(build_file_tree(entry.path))
        else:
            tree["children"].append({
                "name": entry.name,
                "type": "file",
                "path": entry.path,
                "size": entry.stat().st_size
            })
    return tree

def analyze_source_directory(root_dir: str, log_callback=None) -> Dict[str, Any]:
    findings = []
    total_files = 0
    scanned_lines = 0

    if log_callback:
        log_callback(f"Starting SAST Static Code Analysis on project directory: {root_dir}")

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Ignore common non-source folders
        dirnames[:] = [d for d in dirnames if d not in ["node_modules", ".git", "venv", "__pycache__", "dist", "build"]]

        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            rel_path = os.path.relpath(file_path, root_dir)
            ext = os.path.splitext(filename)[1].lower()

            total_files += 1
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                    scanned_lines += len(lines)

                    for line_idx, line in enumerate(lines, start=1):
                        for rule in STATIC_RULES:
                            if ext in rule["extensions"] or rule["extensions"] == []:
                                if re.search(rule["pattern"], line):
                                    snippet = line.strip()
                                    findings.append({
                                        "category": "static",
                                        "owasp_category": "A06:2021-Vulnerable and Outdated Components",
                                        "severity": rule["severity"],
                                        "title": rule["title"],
                                        "description": rule["desc"],
                                        "endpoint": f"file://{rel_path}:{line_idx}",
                                        "parameter": "Source Code",
                                        "payload": snippet,
                                        "evidence": f"Line {line_idx}: {snippet}",
                                        "cvss_score": rule["cvss"],
                                        "cve_id": rule["cwe"],
                                        "remediation": "Refactor unsafe code construct, sanitize dynamic parameters, and avoid embedding secrets.",
                                        "file_path": rel_path,
                                        "line_number": line_idx
                                    })
            except Exception as e:
                pass

    tree = build_file_tree(root_dir)

    return {
        "findings": findings,
        "file_tree": tree,
        "total_files": total_files,
        "scanned_lines": scanned_lines
    }

def extract_and_analyze_zip(zip_path: str, extract_to: str, log_callback=None) -> Dict[str, Any]:
    if os.path.exists(extract_to):
        shutil.rmtree(extract_to)
    os.makedirs(extract_to, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_to)

    return analyze_source_directory(extract_to, log_callback)
