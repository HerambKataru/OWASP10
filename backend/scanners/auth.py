import urllib.parse
from typing import List, Dict, Any
import requests

AUTH_PATH_CANDIDATES = ["/login", "/signin", "/auth", "/session", "/admin", "/api/auth", "/api/login"]

def scan_auth(endpoints: List[Dict[str, Any]], cookies: Dict[str, str], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    audited_urls = set()

    # 1. Cookie Security Flags Analysis
    for ep in endpoints:
        url = ep.get("url", "")
        if not url or url in audited_urls: continue
        audited_urls.add(url)

        try:
            res = requests.get(url, headers=headers, timeout=timeout, verify=False)
            set_cookie_headers = [v for k, v in res.raw.headers.items() if k.lower() == "set-cookie"] if hasattr(res, 'raw') and hasattr(res.raw, 'headers') else res.headers.get("Set-Cookie", "").split(",")

            for cookie_str in set_cookie_headers:
                if not cookie_str.strip(): continue
                
                cookie_lower = cookie_str.lower()
                cookie_name = cookie_str.split("=")[0].strip()

                if "httponly" not in cookie_lower:
                    findings.append({
                        "category": "auth",
                        "owasp_category": "A07:2025-Identification and Authentication Failures",
                        "severity": "Medium",
                        "title": f"Missing 'HttpOnly' flag on Cookie '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' is set without the HttpOnly attribute, making it accessible to client-side scripts via document.cookie during XSS attacks.",
                        "endpoint": url,
                        "parameter": cookie_name,
                        "payload": cookie_str[:120],
                        "evidence": f"Set-Cookie header missing HttpOnly flag: '{cookie_str[:100]}'",
                        "cvss_score": 5.3,
                        "cve_id": "CWE-1004",
                        "remediation": "Add the 'HttpOnly' flag to all session and authentication cookies in Set-Cookie headers."
                    })

                if "secure" not in cookie_lower:
                    findings.append({
                        "category": "auth",
                        "owasp_category": "A07:2025-Identification and Authentication Failures",
                        "severity": "Medium",
                        "title": f"Missing 'Secure' flag on Cookie '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' lacks the Secure flag and may be transmitted over unencrypted HTTP channels.",
                        "endpoint": url,
                        "parameter": cookie_name,
                        "payload": cookie_str[:120],
                        "evidence": f"Set-Cookie header missing Secure flag: '{cookie_str[:100]}'",
                        "cvss_score": 5.0,
                        "cve_id": "CWE-614",
                        "remediation": "Always set the 'Secure' attribute on cookies to ensure transmission occurs only via HTTPS."
                    })

                if "samesite" not in cookie_lower:
                    findings.append({
                        "category": "auth",
                        "owasp_category": "A07:2025-Identification and Authentication Failures",
                        "severity": "Low",
                        "title": f"Missing 'SameSite' attribute on Cookie '{cookie_name}'",
                        "description": f"The cookie '{cookie_name}' does not specify SameSite=Strict or SameSite=Lax, increasing susceptibility to Cross-Site Request Forgery (CSRF).",
                        "endpoint": url,
                        "parameter": cookie_name,
                        "payload": cookie_str[:120],
                        "evidence": f"No SameSite directive found in cookie: '{cookie_str[:100]}'",
                        "cvss_score": 4.2,
                        "cve_id": "CWE-1275",
                        "remediation": "Set SameSite=Lax or SameSite=Strict on all state-changing or session cookies."
                    })
        except Exception:
            pass

    # 2. Rate-Limiting Check on Login / Auth Endpoints
    tested_auth_endpoints = set()
    endpoints_to_test = [ep.get("url", "") for ep in endpoints if ep.get("url")]
    
    # Also check base origin with candidate auth paths
    if endpoints_to_test:
        base_origin = urllib.parse.urlsplit(endpoints_to_test[0])
        for auth_candidate in AUTH_PATH_CANDIDATES[:3]:
            candidate_url = urllib.parse.urlunsplit((base_origin.scheme, base_origin.netloc, auth_candidate, "", ""))
            if candidate_url not in endpoints_to_test:
                endpoints_to_test.append(candidate_url)

    for url in endpoints_to_test:
        if any(auth_path in url.lower() for auth_path in ["login", "signin", "auth", "session", "token", "admin"]):
            if url in tested_auth_endpoints: continue
            tested_auth_endpoints.add(url)

            if log_callback:
                log_callback(f"Auditing Authentication Rate Limiting on: {url}")
            
            # Send 5 rapid requests
            rate_limit_triggered = False
            try:
                base_check = requests.get(url, headers=headers, timeout=3, verify=False)
                if base_check.status_code in [200, 401, 403]:
                    for i in range(5):
                        r = requests.get(url, headers=headers, timeout=3, verify=False)
                        if r.status_code == 429 or "retry-after" in r.headers:
                            rate_limit_triggered = True
                            break
                    
                    if not rate_limit_triggered:
                        findings.append({
                            "category": "auth",
                            "owasp_category": "A07:2025-Identification and Authentication Failures",
                            "severity": "Medium",
                            "title": f"Missing Rate Limiting on Authentication Endpoint '{url}'",
                            "description": f"The authentication endpoint at {url} does not enforce rate limiting (HTTP 429) against repeated rapid requests, exposing it to brute force and credential stuffing attacks.",
                            "endpoint": url,
                            "parameter": "Rate-Limiting",
                            "payload": "5 Rapid Burst Requests",
                            "evidence": f"All 5 sequential requests returned HTTP {base_check.status_code} without throttling headers (X-RateLimit-*, Retry-After).",
                            "cvss_score": 5.9,
                            "cve_id": "CWE-307",
                            "remediation": "Implement rate limiting using Redis/token bucket algorithms and return HTTP 429 Too Many Requests when thresholds are exceeded."
                        })
            except Exception:
                pass

    return findings
