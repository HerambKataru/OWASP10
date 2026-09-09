import re
import urllib.parse
from typing import List, Dict, Any
import requests

XSS_PAYLOADS = [
    "<script>alert('SX_XSS')</script>",
    "<img src=x onerror=alert('SX_XSS')>",
    "'\"><svg/onload=alert('SX_XSS')>",
    "javascript:alert('SX_XSS')"
]

COMMON_XSS_PARAMS = ["q", "search", "name", "msg", "redirect", "input", "query", "comment", "user", "keyword", "term", "filter"]

DOM_SINKS = [
    r'document\.write\s*\(',
    r'innerHTML\s*=',
    r'outerHTML\s*=',
    r'eval\s*\(',
    r'setTimeout\s*\([^,]+,',
    r'document\.location\s*=',
    r'window\.location\s*=',
    r'location\.hash',
    r'location\.search',
    r'location\.href\s*='
]

def scan_xss(endpoints: List[Dict[str, Any]], js_files: List[str], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    tested_targets = set()
    
    # 1. Reflected XSS Testing in Parameters
    for ep in endpoints:
        url = ep.get("url", "")
        if not url: continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        params_to_test = {}
        if params:
            for k, v in params.items():
                params_to_test[k] = v[0] if v else ""
        else:
            for p in COMMON_XSS_PARAMS[:4]:
                params_to_test[p] = ""

        for param_name in params_to_test.keys():
            probe_key = f"{parsed.netloc}{parsed.path}:{param_name}"
            if probe_key in tested_targets: continue
            tested_targets.add(probe_key)

            for payload in XSS_PAYLOADS:
                test_params = dict(params) if params else {}
                test_params[param_name] = payload
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

                if log_callback:
                    log_callback(f"Testing XSS on {parsed.path} (param: '{param_name}') with payload: {payload}")

                try:
                    res = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                    if payload in res.text:
                        idx = res.text.find(payload)
                        start = max(0, idx - 40)
                        end = min(len(res.text), idx + len(payload) + 40)
                        evidence_snippet = res.text[start:end].replace("\n", " ")

                        findings.append({
                            "category": "xss",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "High",
                            "title": f"Reflected Cross-Site Scripting (XSS) in '{param_name}'",
                            "description": f"The parameter '{param_name}' reflects unsanitized user-supplied JavaScript payload directly into the DOM response.",
                            "endpoint": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Reflected in response: ...{evidence_snippet}...",
                            "cvss_score": 7.5,
                            "cve_id": "CWE-79",
                            "remediation": "Contextually encode all untrusted output (HTML, attribute, JS context) and implement a robust Content Security Policy (CSP)."
                        })
                        break
                except Exception:
                    pass

        # Test Forms for XSS
        forms = ep.get("forms", [])
        for form in forms:
            action_url = form.get("action", url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            for inp in inputs:
                inp_name = inp.get("name")
                if not inp_name: continue

                payload = "<script>alert('SX_XSS')</script>"
                post_data = {i.get("name"): (payload if i.get("name") == inp_name else "test") for i in inputs if i.get("name")}
                
                if log_callback:
                    log_callback(f"Testing XSS on Form {action_url} [{method}] (field: '{inp_name}')")

                try:
                    if method == "POST":
                        res = requests.post(action_url, data=post_data, headers=headers, timeout=timeout, verify=False)
                    else:
                        res = requests.get(action_url, params=post_data, headers=headers, timeout=timeout, verify=False)

                    if payload in res.text:
                        findings.append({
                            "category": "xss",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "High",
                            "title": f"Reflected XSS in Form Field '{inp_name}'",
                            "description": f"Form at {action_url} reflected unencoded script tag from input '{inp_name}'.",
                            "endpoint": action_url,
                            "parameter": inp_name,
                            "payload": payload,
                            "evidence": f"Unsanitized payload returned in response body from {action_url}",
                            "cvss_score": 7.4,
                            "cve_id": "CWE-79",
                            "remediation": "Sanitize and HTML-entity-encode all user input values rendered into HTML templates."
                        })
                except Exception:
                    pass

    # 2. DOM XSS Sink Detection in JS Files & Page HTML
    for ep in endpoints:
        content_type = ep.get("content_type", "")
        url = ep.get("url", "")
        if "text/html" in content_type:
            try:
                res = requests.get(url, headers=headers, timeout=timeout, verify=False)
                for sink_pat in DOM_SINKS:
                    matches = list(re.finditer(sink_pat, res.text))
                    if matches:
                        match_text = matches[0].group(0)
                        findings.append({
                            "category": "xss",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "Medium",
                            "title": f"Dangerous DOM XSS Sink detected ({match_text})",
                            "description": f"The page uses dangerous DOM manipulation sink '{match_text}' which may permit DOM-based XSS when handling user inputs or location hashes.",
                            "endpoint": url,
                            "parameter": "DOM Sink",
                            "payload": "N/A (Sink Analysis)",
                            "evidence": f"Pattern '{sink_pat}' detected in inline JavaScript.",
                            "cvss_score": 6.1,
                            "cve_id": "CWE-79",
                            "remediation": "Avoid using innerHTML, eval(), or document.write. Use safe APIs like textContent, createElement, or modern frontend frameworks."
                        })
                        break
            except Exception:
                pass

    for js_url in js_files[:10]:
        try:
            res = requests.get(js_url, headers=headers, timeout=timeout, verify=False)
            for sink_pat in DOM_SINKS:
                if re.search(sink_pat, res.text):
                    findings.append({
                        "category": "xss",
                        "owasp_category": "A03:2025-Injection & Execution",
                        "severity": "Low",
                        "title": f"DOM XSS Sink Pattern in Static Script ({js_url.split('/')[-1]})",
                        "description": f"The JavaScript file at {js_url} contains potentially insecure sinks matching {sink_pat}.",
                        "endpoint": js_url,
                        "parameter": "JS Sink",
                        "payload": "Static Sink",
                        "evidence": f"Script contains sink pattern {sink_pat}",
                        "cvss_score": 4.3,
                        "cve_id": "CWE-79",
                        "remediation": "Refactor DOM sinks to use safe DOM manipulation methods."
                    })
                    break
        except Exception:
            pass

    return findings
