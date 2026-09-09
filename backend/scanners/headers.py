import re
from typing import List, Dict, Any

SECURITY_HEADERS = [
    {
        "header": "Content-Security-Policy",
        "severity": "Medium",
        "cvss": 5.7,
        "title": "Missing Content Security Policy (CSP)",
        "desc": "CSP protects against Cross-Site Scripting (XSS) and data injection attacks by restricting resource load origins.",
        "remediation": "Configure a strict Content-Security-Policy header restricting script-src, object-src, and default-src."
    },
    {
        "header": "Strict-Transport-Security",
        "severity": "Medium",
        "cvss": 5.4,
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "desc": "HSTS enforces HTTPS connections and prevents SSL-stripping and man-in-the-middle attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload'."
    },
    {
        "header": "X-Frame-Options",
        "severity": "Medium",
        "cvss": 5.3,
        "title": "Missing Anti-Clickjacking Header (X-Frame-Options)",
        "desc": "X-Frame-Options prevents the application from being embedded in iframes on malicious third-party sites.",
        "remediation": "Set 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
    },
    {
        "header": "X-Content-Type-Options",
        "severity": "Low",
        "cvss": 3.7,
        "title": "Missing MIME-Sniffing Protection (X-Content-Type-Options)",
        "desc": "Prevents browsers from MIME-sniffing a response away from the declared content-type.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' header."
    },
    {
        "header": "Referrer-Policy",
        "severity": "Low",
        "cvss": 3.1,
        "title": "Missing Referrer-Policy Header",
        "desc": "Referrer-Policy controls how much referrer information is included with requests.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
    },
    {
        "header": "Permissions-Policy",
        "severity": "Low",
        "cvss": 2.8,
        "title": "Missing Permissions-Policy Header",
        "desc": "Permissions-Policy allows developers to selectively enable, disable, and modify browser features like camera and geolocation.",
        "remediation": "Define a Permissions-Policy header specifying allowed browser feature origins."
    }
]

def scan_headers(target_url: str, headers: Dict[str, str], log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    headers_lower = {k.lower(): v for k, v in headers.items()}

    if log_callback:
        log_callback(f"Auditing HTTP Security Headers and Server Misconfigurations for {target_url}")

    # 1. Missing Security Headers
    for item in SECURITY_HEADERS:
        h_name = item["header"].lower()
        if h_name not in headers_lower:
            findings.append({
                "category": "headers",
                "owasp_category": "A05:2021-Security Misconfiguration",
                "severity": item["severity"],
                "title": item["title"],
                "description": item["desc"],
                "endpoint": target_url,
                "parameter": item["header"],
                "payload": "N/A (Header Check)",
                "evidence": f"Header '{item['header']}' was not present in the server HTTP response.",
                "cvss_score": item["cvss"],
                "cve_id": "CWE-16",
                "remediation": item["remediation"]
            })

    # 2. Server Banner Disclosure
    server_banner = headers_lower.get("server", "")
    if server_banner and (re.search(r'[\d\.]+', server_banner) or "apache" in server_banner or "nginx" in server_banner):
        findings.append({
            "category": "headers",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "Low",
            "title": f"Detailed Server Software Version Disclosure ({server_banner})",
            "description": "The server exposes its detailed software name and version in the 'Server' header, aiding attackers in vulnerability targeting.",
            "endpoint": target_url,
            "parameter": "Server",
            "payload": server_banner,
            "evidence": f"Server: {server_banner}",
            "cvss_score": 3.5,
            "cve_id": "CWE-200",
            "remediation": "Suppress detailed server banners in web server configuration (e.g., 'server_tokens off;' in Nginx, 'ServerTokens Prod' in Apache)."
        })

    # 3. X-Powered-By Banner
    powered_by = headers_lower.get("x-powered-by", "")
    if powered_by:
        findings.append({
            "category": "headers",
            "owasp_category": "A05:2021-Security Misconfiguration",
            "severity": "Low",
            "title": f"Framework Technology Disclosure ({powered_by})",
            "description": "The application returns 'X-Powered-By' disclosing underlying backend framework details.",
            "endpoint": target_url,
            "parameter": "X-Powered-By",
            "payload": powered_by,
            "evidence": f"X-Powered-By: {powered_by}",
            "cvss_score": 3.2,
            "cve_id": "CWE-200",
            "remediation": "Disable the X-Powered-By header in your application framework settings."
        })

    return findings
