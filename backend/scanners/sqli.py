import re
import urllib.parse
from typing import List, Dict, Any
import requests
import time

SQLI_PAYLOADS = [
    # Error based
    {"payload": "' OR '1'='1", "type": "boolean"},
    {"payload": "admin' --", "type": "auth_bypass"},
    {"payload": "' UNION SELECT NULL, NULL, NULL--", "type": "union"},
    {"payload": "\"'`", "type": "error_syntax"},
    {"payload": "1' ORDER BY 1--+", "type": "order_by"},
    {"payload": "1' AND SLEEP(2)--", "type": "time_based"}
]

SQL_ERROR_PATTERNS = [
    r"you have an error in your sql syntax",
    r"warning: mysql_",
    r"unclosed quotation mark after the character string",
    r"quoted string not properly terminated",
    r"postgresql.*?error",
    r"sqlite3::sqlexception",
    r"sqlite_error",
    r"syntax error in string in query expression",
    r"microsoft ole db provider for sql server",
    r"ora-[0-9]{5}",
    r"pg_query\(\): query failed"
]

COMMON_SQLI_PARAMS = ["id", "user", "q", "search", "cat", "page", "category", "item", "query", "name", "filter", "view"]

def check_sqli_errors(text: str) -> str:
    for pat in SQL_ERROR_PATTERNS:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            return match.group(0)
    return ""

def scan_sqli(endpoints: List[Dict[str, Any]], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    tested_targets = set()
    
    for ep in endpoints:
        url = ep.get("url", "")
        if not url: continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # Build list of parameters to test: either existing query params or standard fallback probe params
        params_to_test = {}
        if params:
            for k, v in params.items():
                params_to_test[k] = v[0] if v else "1"
        else:
            # Fuzz common candidate parameters on endpoints
            for p in COMMON_SQLI_PARAMS[:4]:
                params_to_test[p] = "1"

        # 1. Test Query Parameters
        for param_name, orig_val in params_to_test.items():
            probe_key = f"{parsed.netloc}{parsed.path}:{param_name}"
            if probe_key in tested_targets: continue
            tested_targets.add(probe_key)

            # Baseline request
            try:
                base_query = urllib.parse.urlencode({param_name: orig_val})
                base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, base_query, ""))
                baseline_res = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
                base_len = len(baseline_res.text)
                base_status = baseline_res.status_code
            except Exception:
                continue

            for p_data in SQLI_PAYLOADS:
                payload = p_data["payload"]
                p_type = p_data["type"]
                
                test_params = dict(params) if params else {}
                test_params[param_name] = orig_val + payload
                new_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

                if log_callback:
                    log_callback(f"Testing SQLi on {parsed.path} (param: '{param_name}') with payload: {payload}")

                start_time = time.time()
                try:
                    res = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                    elapsed = time.time() - start_time
                    
                    # Check for error patterns
                    err_match = check_sqli_errors(res.text)
                    if err_match:
                        findings.append({
                            "category": "sqli",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "Critical",
                            "title": f"Error-Based SQL Injection in parameter '{param_name}'",
                            "description": f"The parameter '{param_name}' reflected database error messages when injected with SQL syntax.",
                            "endpoint": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Matched database error: '{err_match}' (HTTP {res.status_code}, Length {len(res.text)})",
                            "cvss_score": 9.8,
                            "cve_id": "CWE-89",
                            "remediation": "Use parameterized queries (Prepared Statements) or an ORM. Never concatenate user input directly into SQL strings."
                        })
                        break # Found critical flaw on this param

                    # Check for Boolean differential
                    if p_type == "boolean" and abs(len(res.text) - base_len) > 200 and res.status_code == 200:
                        findings.append({
                            "category": "sqli",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "High",
                            "title": f"Boolean-Based SQL Injection in parameter '{param_name}'",
                            "description": f"Injecting boolean true payload altered the response size significantly from baseline ({len(res.text)} vs {base_len}).",
                            "endpoint": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Response size changed from {base_len} to {len(res.text)} bytes.",
                            "cvss_score": 8.5,
                            "cve_id": "CWE-89",
                            "remediation": "Use prepared statements with parameterized queries."
                        })
                        break

                except requests.exceptions.Timeout:
                    if p_type == "time_based":
                        findings.append({
                            "category": "sqli",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "High",
                            "title": f"Time-Based Blind SQL Injection in parameter '{param_name}'",
                            "description": f"The application delayed response execution upon processing time delay payload.",
                            "endpoint": url,
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": f"Request timed out / delayed > {timeout}s.",
                            "cvss_score": 8.6,
                            "cve_id": "CWE-89",
                            "remediation": "Ensure parameterized queries are used in all database abstraction layers."
                        })
                except Exception:
                    pass

        # 2. Test Forms (POST / GET)
        forms = ep.get("forms", [])
        for form in forms:
            action_url = form.get("action", url)
            method = form.get("method", "GET").upper()
            inputs = form.get("inputs", [])

            for inp in inputs:
                inp_name = inp.get("name")
                if not inp_name: continue

                payload = "' OR '1'='1"
                post_data = {i.get("name"): (payload if i.get("name") == inp_name else "test") for i in inputs if i.get("name")}
                
                if log_callback:
                    log_callback(f"Testing SQLi on Form {action_url} [{method}] (field: '{inp_name}')")

                try:
                    if method == "POST":
                        res = requests.post(action_url, data=post_data, headers=headers, timeout=timeout, verify=False)
                    else:
                        res = requests.get(action_url, params=post_data, headers=headers, timeout=timeout, verify=False)

                    err = check_sqli_errors(res.text)
                    if err:
                        findings.append({
                            "category": "sqli",
                            "owasp_category": "A03:2025-Injection & Execution",
                            "severity": "Critical",
                            "title": f"SQL Injection in Form Input '{inp_name}'",
                            "description": f"Form at {action_url} is vulnerable to SQL injection on input field '{inp_name}'.",
                            "endpoint": action_url,
                            "parameter": inp_name,
                            "payload": payload,
                            "evidence": f"Error signature detected: {err}",
                            "cvss_score": 9.5,
                            "cve_id": "CWE-89",
                            "remediation": "Implement parameterized database statements on backend form handlers."
                        })
                except Exception:
                    pass

    return findings
