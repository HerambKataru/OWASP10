import re
from typing import List, Dict, Any
import requests

EXPOSURE_REGEXES = [
    {
        "name": "AWS Access Key ID",
        "pattern": r'(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}',
        "severity": "Critical",
        "cvss": 9.3,
        "cwe": "CWE-798"
    },
    {
        "name": "Generic High-Entropy API Key / Secret",
        "pattern": r'(?i)(?:api_key|apikey|secret_key|app_secret|auth_token)\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,64})["\']',
        "severity": "High",
        "cvss": 8.5,
        "cwe": "CWE-798"
    },
    {
        "name": "JSON Web Token (JWT)",
        "pattern": r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}',
        "severity": "Medium",
        "cvss": 6.5,
        "cwe": "CWE-312"
    },
    {
        "name": "Slack API / Webhook Token",
        "pattern": r'xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}',
        "severity": "High",
        "cvss": 8.0,
        "cwe": "CWE-798"
    },
    {
        "name": "Google Cloud API Key",
        "pattern": r'AIza[0-9A-Za-z\\-_]{35}',
        "severity": "High",
        "cvss": 7.8,
        "cwe": "CWE-798"
    },
    {
        "name": "Hardcoded Password Assignment",
        "pattern": r'(?i)(?:password|passwd|pwd)\s*=\s*["\']([^"\']{6,})["\']',
        "severity": "High",
        "cvss": 8.2,
        "cwe": "CWE-798"
    }
]

def scan_exposure(endpoints: List[Dict[str, Any]], js_files: List[str], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    checked_urls = set()

    all_targets = [ep.get("url") for ep in endpoints if ep.get("url")] + list(js_files)

    for url in all_targets[:30]:
        if not url or url in checked_urls: continue
        checked_urls.add(url)

        if log_callback:
            log_callback(f"Scanning for Sensitive Data Exposure & Leaked Secrets in: {url}")

        try:
            res = requests.get(url, headers=headers, timeout=timeout, verify=False)
            text_body = res.text

            # 1. Regex Secret Matching
            for item in EXPOSURE_REGEXES:
                matches = list(re.finditer(item["pattern"], text_body))
                for match in matches[:3]: # Cap at 3 per regex
                    matched_val = match.group(0)
                    # Obfuscate middle characters
                    obfuscated = matched_val[:6] + "..." + matched_val[-4:] if len(matched_val) > 10 else "***"
                    
                    findings.append({
                        "category": "exposure",
                        "owasp_category": "A02:2025-Cryptographic Failures",
                        "severity": item["severity"],
                        "title": f"Hardcoded {item['name']} Exposed in Client Asset",
                        "description": f"A potential sensitive credential matching pattern for {item['name']} was identified in the HTTP response or script file.",
                        "endpoint": url,
                        "parameter": "Exposed Secret",
                        "payload": obfuscated,
                        "evidence": f"Pattern matched: {obfuscated} in {url}",
                        "cvss_score": item["cvss"],
                        "cve_id": item["cwe"],
                        "remediation": "Revoke the exposed key immediately. Store secrets securely on backend server environment variables or secret vaults (e.g. AWS Secrets Manager, HashiCorp Vault)."
                    })

            # 2. Mixed Content Check (HTTP links in HTTPS page)
            if url.startswith("https://"):
                insecure_links = re.findall(r'http://[a-zA-Z0-9_\-\./]+', text_body)
                if insecure_links:
                    sample = insecure_links[0]
                    findings.append({
                        "category": "exposure",
                        "owasp_category": "A02:2025-Cryptographic Failures",
                        "severity": "Low",
                        "title": "Mixed Content (Insecure HTTP Resource in HTTPS)",
                        "description": f"The HTTPS page references resources over plain unencrypted HTTP ({sample}).",
                        "endpoint": url,
                        "parameter": "Mixed Content",
                        "payload": sample,
                        "evidence": f"Found unencrypted URL reference: {sample}",
                        "cvss_score": 3.7,
                        "cve_id": "CWE-319",
                        "remediation": "Ensure all external assets, scripts, stylesheets, and images are loaded via HTTPS."
                    })

        except Exception:
            pass

    return findings
