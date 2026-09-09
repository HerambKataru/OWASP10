import re
import urllib.parse
from typing import List, Dict, Any
import requests

COMMON_DIRECTORIES = [
    "/admin", "/login", "/wp-admin", "/dashboard", "/api", "/api/v1",
    "/swagger", "/docs", "/openapi.json", "/graphql", "/upload",
    "/.env", "/.git/config", "/backup.zip", "/config.php"
]

TECH_SIGNATURES = {
    "React": [r'react\.production\.min\.js', r'data-reactroot', r'_reactRootContainer', r'__REACT_DEVTOOLS_GLOBAL_HOOK__'],
    "Vue.js": [r'vue\.min\.js', r'vue\.runtime', r'data-v-[a-f0-9]+', r'__VUE__'],
    "Angular": [r'ng-version', r'ng-app', r'zone\.js', r'angular\.min\.js'],
    "Laravel": [r'laravel_session', r'XSRF-TOKEN', r'laravel'],
    "Django": [r'csrftoken', r'__admin__', r'django'],
    "Flask": [r'session=\.eJ', r'werkzeug'],
    "Express / Node.js": [r'connect\.sid', r'express'],
    "WordPress": [r'/wp-content/', r'/wp-includes/', r'wp-embed\.min\.js'],
    "Bootstrap": [r'bootstrap(?:\.min)?\.css', r'bootstrap(?:\.min)?\.js'],
    "jQuery": [r'jquery(?:\.min)?\.js', r'jQuery v[0-9\.]+']
}

def fingerprint_technologies(html_content: str, headers: Dict[str, str], cookies: Dict[str, str]) -> List[str]:
    detected = set()
    
    # Check headers
    server = headers.get("Server", "") or headers.get("server", "")
    powered_by = headers.get("X-Powered-By", "") or headers.get("x-powered-by", "")
    
    if "nginx" in server.lower(): detected.add("Nginx Web Server")
    if "apache" in server.lower(): detected.add("Apache HTTPD")
    if "cloudflare" in server.lower(): detected.add("Cloudflare CDN")
    if "express" in powered_by.lower(): detected.add("Express / Node.js")
    if "php" in powered_by.lower(): detected.add("PHP")
    if "asp.net" in powered_by.lower(): detected.add("ASP.NET")

    # Check cookies
    for c in cookies.keys():
        if "laravel_session" in c or "XSRF-TOKEN" in c: detected.add("Laravel")
        if "csrftoken" in c or "sessionid" in c: detected.add("Django")
        if "connect.sid" in c: detected.add("Express / Node.js")
        if "PHPSESSID" in c: detected.add("PHP Session")

    # Check HTML & Scripts
    for tech, patterns in TECH_SIGNATURES.items():
        for pat in patterns:
            if re.search(pat, html_content, re.IGNORECASE):
                detected.add(tech)
                break

    return list(detected)

def discover_sensitive_paths(base_url: str, headers: Dict[str, str], timeout: int = 5) -> List[Dict[str, Any]]:
    results = []
    for path in COMMON_DIRECTORIES:
        url = urllib.parse.urljoin(base_url, path)
        try:
            res = requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)
            if res.status_code in [200, 301, 302, 401, 403]:
                results.append({
                    "path": path,
                    "url": url,
                    "status_code": res.status_code,
                    "length": len(res.content)
                })
        except Exception:
            pass
    return results
