import re
import urllib.parse
from typing import List, Dict, Any
import requests

ID_PARAM_PATTERNS = [r'id', r'user_?id', r'account_?id', r'order_?id', r'doc_?id', r'file_?id', r'uid', r'item_?id']
PATH_NUMERIC_PATTERN = r'(/\w+/)([0-9]+)(/?.*)'
COMMON_IDOR_PROBES = ["id", "user_id", "uid", "account_id"]

def scan_idor(endpoints: List[Dict[str, Any]], headers: Dict[str, str], timeout: int = 6, log_callback=None) -> List[Dict[str, Any]]:
    findings = []
    tested_targets = set()
    
    for ep in endpoints:
        url = ep.get("url", "")
        if not url: continue
        parsed = urllib.parse.urlparse(url)
        params = urllib.parse.parse_qs(parsed.query)

        # 1. Test Query Parameters containing numeric IDs or probe common ID params
        params_to_test = {}
        if params:
            for p_name, vals in params.items():
                params_to_test[p_name] = vals[0]
        else:
            for p_name in COMMON_IDOR_PROBES[:2]:
                params_to_test[p_name] = "1"

        for p_name, val in params_to_test.items():
            probe_key = f"{parsed.netloc}{parsed.path}:{p_name}"
            if probe_key in tested_targets: continue
            tested_targets.add(probe_key)

            if val.isdigit() or any(re.match(f"^{pat}$", p_name, re.I) for pat in ID_PARAM_PATTERNS):
                if log_callback:
                    log_callback(f"Checking Broken Access Control (IDOR) on {parsed.path} (param: '{p_name}'={val})")

                try:
                    test_base_params = dict(params) if params else {p_name: val}
                    base_query = urllib.parse.urlencode(test_base_params, doseq=True)
                    base_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, base_query, ""))
                    base_res = requests.get(base_url, headers=headers, timeout=timeout, verify=False)
                    
                    current_num = int(val) if val.isdigit() else 1
                    neighbor_ids = [current_num + 1, max(1, current_num - 1), 0, 9999]

                    for test_id in neighbor_ids:
                        if str(test_id) == val: continue
                        test_params = dict(params) if params else {}
                        test_params[p_name] = str(test_id)
                        new_query = urllib.parse.urlencode(test_params, doseq=True)
                        test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, ""))
                        
                        test_res = requests.get(test_url, headers=headers, timeout=timeout, verify=False)
                        
                        # If neighboring ID returns 200 OK with distinct payload without authorization check
                        if test_res.status_code == 200 and base_res.status_code == 200 and len(test_res.text) > 50 and abs(len(test_res.text) - len(base_res.text)) < 500:
                            findings.append({
                                "category": "idor",
                                "owasp_category": "A01:2025-Broken Access Control",
                                "severity": "High",
                                "title": f"Insecure Direct Object Reference (IDOR) in parameter '{p_name}'",
                                "description": f"Accessing object ID '{test_id}' instead of '{val}' returned a successful HTTP 200 response without requiring object-level permission validation.",
                                "endpoint": url,
                                "parameter": p_name,
                                "payload": f"{p_name}={test_id}",
                                "evidence": f"Baseline ID {val} (HTTP {base_res.status_code}, {len(base_res.text)} bytes) -> Neighbor ID {test_id} (HTTP {test_res.status_code}, {len(test_res.text)} bytes)",
                                "cvss_score": 8.1,
                                "cve_id": "CWE-639",
                                "remediation": "Implement strict server-side authorization checks on every request. Validate that the authenticated session owns or is authorized to access the requested object."
                            })
                            break
                except Exception:
                    pass

        # 2. Test Path-Based Numeric IDs (e.g., /api/user/10)
        path_match = re.search(PATH_NUMERIC_PATTERN, parsed.path)
        if path_match:
            prefix, num_id, suffix = path_match.groups()
            current_num = int(num_id)
            neighbor_id = current_num + 1
            new_path = f"{prefix}{neighbor_id}{suffix}"
            test_url = urllib.parse.urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, ""))

            if log_callback:
                log_callback(f"Testing Path IDOR: {parsed.path} -> {new_path}")

            try:
                base_res = requests.get(url, headers=headers, timeout=timeout, verify=False)
                test_res = requests.get(test_url, headers=headers, timeout=timeout, verify=False)

                if test_res.status_code == 200 and base_res.status_code == 200:
                    findings.append({
                        "category": "idor",
                        "owasp_category": "A01:2025-Broken Access Control",
                        "severity": "Medium",
                        "title": f"Potential Path-Based IDOR on '{parsed.path}'",
                        "description": f"Directly altering numeric ID from {num_id} to {neighbor_id} on path '{parsed.path}' yielded valid response.",
                        "endpoint": url,
                        "parameter": "URL Path ID",
                        "payload": new_path,
                        "evidence": f"Original: {parsed.path} (HTTP {base_res.status_code}) | Test: {new_path} (HTTP {test_res.status_code})",
                        "cvss_score": 7.3,
                        "cve_id": "CWE-639",
                        "remediation": "Enforce role-based access control (RBAC) and object-level authorization across RESTful endpoints."
                    })
            except Exception:
                pass

    return findings
