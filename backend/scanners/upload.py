import io
import urllib.parse
from typing import List, Dict, Any
import requests

SAFE_UPLOAD_PROBES = [
    {"filename": "sentinelx_probe.txt", "mime": "text/plain", "content": b"SentinelX harmless upload audit"},
    {"filename": "sentinelx_probe.svg", "mime": "image/svg+xml", "content": b'<svg xmlns="http://www.w3.org/2000/svg"><text>Probe</text></svg>'},
    {"filename": "sentinelx_probe.php.png", "mime": "image/png", "content": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDRSentinelX"}
]

COMMON_UPLOAD_PATHS = ["/upload", "/api/upload", "/api/v1/upload", "/file-upload"]

def scan_upload(endpoints: List[Dict[str, Any]], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    audited_actions = set()

    for ep in endpoints:
        forms = ep.get("forms", [])
        page_url = ep.get("url", "")
        if not page_url: continue

        for form in forms:
            action_url = form.get("action", page_url)
            inputs = form.get("inputs", [])

            # Check if form contains file inputs
            file_inputs = [inp for inp in inputs if inp.get("type") == "file"]
            if not file_inputs:
                continue

            if action_url in audited_actions: continue
            audited_actions.add(action_url)

            if log_callback:
                log_callback(f"Auditing File Upload handler on form: {action_url}")

            for f_inp in file_inputs:
                f_name = f_inp.get("name", "file")

                for probe in SAFE_UPLOAD_PROBES:
                    files = {f_name: (probe["filename"], probe["content"], probe["mime"])}
                    data = {i.get("name"): "test" for i in inputs if i.get("type") != "file" and i.get("name")}

                    try:
                        res = requests.post(action_url, data=data, files=files, headers=headers, timeout=timeout, verify=False)
                        
                        # Check double extension acceptance
                        if "php.png" in probe["filename"] and res.status_code in [200, 201]:
                            findings.append({
                                "category": "upload",
                                "owasp_category": "A04:2025-Insecure Architecture & Design",
                                "severity": "Medium",
                                "title": f"Potential Unrestricted File Upload / Double Extension Handling on '{f_name}'",
                                "description": f"The form accepted a double extension payload ({probe['filename']}) without explicit rejection.",
                                "endpoint": action_url,
                                "parameter": f_name,
                                "payload": probe["filename"],
                                "evidence": f"Server responded with HTTP {res.status_code} for upload probe.",
                                "cvss_score": 6.8,
                                "cve_id": "CWE-434",
                                "remediation": "Validate file extensions against a strict whitelist. Re-encode uploaded files or store them with randomized alphanumeric names in non-executable storage."
                            })

                        # Check SVG upload acceptance (potential Stored SVG XSS)
                        if ".svg" in probe["filename"] and res.status_code in [200, 201]:
                            findings.append({
                                "category": "upload",
                                "owasp_category": "A04:2025-Insecure Architecture & Design",
                                "severity": "Low",
                                "title": f"SVG File Upload Allowed on '{f_name}'",
                                "description": f"The server accepted an SVG image. SVGs can embed inline JavaScript payloads leading to Stored XSS if served directly.",
                                "endpoint": action_url,
                                "parameter": f_name,
                                "payload": probe["filename"],
                                "evidence": f"Server accepted MIME {probe['mime']} with HTTP {res.status_code}",
                                "cvss_score": 4.7,
                                "cve_id": "CWE-434",
                                "remediation": "Sanitize SVG files with an XML/SVG sanitizer before storing or serving them with Content-Disposition: attachment."
                            })
                    except Exception:
                        pass

    return findings
