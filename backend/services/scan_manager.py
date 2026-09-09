import asyncio
import json
import time
from datetime import datetime
from typing import Dict, Any, List
from database.session import SessionLocal
from database.models import Scan, Finding, Endpoint
from services.crawler import WebCrawler
from services.risk_engine import RiskEngine
from services.ai_advisor import AISecurityAdvisor
from services.websocket_manager import ws_manager
from scanners.recon import fingerprint_technologies, discover_sensitive_paths
from scanners.sqli import scan_sqli
from scanners.xss import scan_xss
from scanners.idor import scan_idor
from scanners.auth import scan_auth
from scanners.upload import scan_upload
from scanners.headers import scan_headers
from scanners.exposure import scan_exposure

class ScanManager:
    @staticmethod
    async def execute_website_scan(scan_id: int):
        db = SessionLocal()
        scan = db.query(Scan).filter(Scan.id == scan_id).first()
        if not scan:
            db.close()
            return

        target_url = scan.target
        scan.status = "running"
        db.commit()

        # Helper for WS logging
        def log_cb(msg: str, level="INFO", comp="SCANNER"):
            asyncio.create_task(ws_manager.broadcast_log(scan_id, msg, level, comp))

        try:
            log_cb(f"🚀 Initializing SentinelX VAPT Assessment Suite for target: {target_url}", "INFO", "CORE")
            log_cb(f"⚙️ Scan Configuration: Depth={scan.crawl_depth}, Threads={scan.threads}, Timeout={scan.timeout}s, User-Agent='{scan.user_agent}'", "INFO", "CONFIG")
            await ws_manager.broadcast_progress(scan_id, "Reconnaissance & Surface Mapping", 5)

            # 1. Crawler & Reconnaissance Phase
            log_cb(f"🔍 [RECON] Starting recursive domain crawler against {target_url}...", "INFO", "RECON")
            crawler = WebCrawler(
                base_url=target_url,
                max_depth=scan.crawl_depth,
                timeout=scan.timeout,
                user_agent=scan.user_agent
            )
            
            log_cb("📡 [RECON] Inspecting robots.txt and sitemap.xml directives...", "INFO", "RECON")
            crawl_results = crawler.start_crawl(log_callback=log_cb)

            discovered_endpoints = crawl_results["endpoints"]
            discovered_forms = crawl_results["forms"]
            headers = crawl_results["headers"]
            cookies = crawl_results["cookies"]
            js_files = crawl_results["js_files"]

            log_cb(f"✅ [RECON] Discovered {len(discovered_endpoints)} distinct URI routes and {len(discovered_forms)} HTML forms.", "SUCCESS", "RECON")
            await ws_manager.broadcast_progress(scan_id, "Reconnaissance Complete", 15)

            # Save endpoints to DB
            for ep in discovered_endpoints:
                endpoint_row = Endpoint(
                    scan_id=scan_id,
                    url=ep.get("url"),
                    method=ep.get("method", "GET"),
                    status_code=ep.get("status_code", 200),
                    content_type=ep.get("content_type", "text/html"),
                    response_time=ep.get("response_time", 0.0),
                    parameters=json.dumps(ep.get("parameters", [])),
                    forms=json.dumps(ep.get("forms", []))
                )
                db.add(endpoint_row)
            db.commit()

            # 2. Technology Fingerprinting
            log_cb("🔬 [FINGERPRINT] Analyzing response headers, cookie structures, and DOM script signatures...", "INFO", "FINGERPRINT")
            sample_html = ""
            if discovered_endpoints:
                try:
                    import requests
                    sample_html = requests.get(target_url, timeout=5, verify=False).text
                except Exception:
                    pass
            techs = fingerprint_technologies(sample_html, headers, cookies)
            scan.technologies = json.dumps(techs)
            log_cb(f"✅ [FINGERPRINT] Identified Technologies: {', '.join(techs) if techs else 'Standard HTTP Web Architecture'}", "SUCCESS", "FINGERPRINT")

            # Sensitive directory brute
            log_cb("📂 [RECON] Probing sensitive administration and configuration paths (/.env, /admin, /api)...", "INFO", "RECON")
            sensitive_dirs = discover_sensitive_paths(target_url, headers)
            for s_dir in sensitive_dirs:
                log_cb(f"⚠️ [RECON] Sensitive path status {s_dir['status_code']} found on {s_dir['url']}", "WARN", "RECON")
                discovered_endpoints.append({
                    "url": s_dir["url"],
                    "method": "GET",
                    "status_code": s_dir["status_code"],
                    "content_type": "text/html",
                    "parameters": [],
                    "forms": []
                })

            all_findings: List[Dict[str, Any]] = []

            # 3. Security Headers & Misconfiguration Audit (OWASP A05)
            await ws_manager.broadcast_progress(scan_id, "OWASP A05: Security Misconfiguration Audit", 25)
            log_cb("🛡️ [A05:MISCONFIG] Auditing HTTP hardening headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)...", "INFO", "HEADERS")
            h_findings = scan_headers(target_url, headers, log_callback=log_cb)
            all_findings.extend(h_findings)
            for hf in h_findings:
                log_cb(f"⚠️ [A05:MISCONFIG] {hf['title']} on {hf['endpoint']}", "WARN", "HEADERS")

            # 4. Sensitive Data & Secret Exposure (OWASP A02)
            await ws_manager.broadcast_progress(scan_id, "OWASP A02: Sensitive Data & Secret Leaks", 38)
            log_cb(f"🔑 [A02:CRYPTO] Scanning {len(discovered_endpoints) + len(js_files)} assets for high-entropy API keys, JWT tokens, AWS credentials...", "INFO", "EXPOSURE")
            exp_findings = scan_exposure(discovered_endpoints, js_files, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(exp_findings)
            for ef in exp_findings:
                log_cb(f"🚨 [A02:CRYPTO] {ef['title']} identified in {ef['endpoint']}", "ALERT", "EXPOSURE")

            # 5. SQL Injection Testing (OWASP A03)
            await ws_manager.broadcast_progress(scan_id, "OWASP A03: SQL Injection (SQLi) Audit", 52)
            log_cb(f"💉 [A03:SQLI] Injecting Error-based, Boolean-differential, and Time-delay SQLi test vectors across {len(discovered_endpoints)} endpoints...", "INFO", "SQLI")
            sqli_findings = scan_sqli(discovered_endpoints, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(sqli_findings)
            for sf in sqli_findings:
                log_cb(f"🔥 [A03:SQLI] CRITICAL VULNERABILITY DETECTED: {sf['title']} ({sf['parameter']})", "CRITICAL", "SQLI")

            # 6. Cross-Site Scripting (XSS) Testing (OWASP A03)
            await ws_manager.broadcast_progress(scan_id, "OWASP A03: Cross-Site Scripting (XSS) Audit", 66)
            log_cb("⚡ [A03:XSS] Evaluating Reflected Script execution and auditing client JavaScript DOM sinks (innerHTML, eval)...", "INFO", "XSS")
            xss_findings = scan_xss(discovered_endpoints, js_files, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(xss_findings)
            for xf in xss_findings:
                log_cb(f"🚨 [A03:XSS] HIGH VULNERABILITY: {xf['title']} ({xf['parameter']})", "ALERT", "XSS")

            # 7. Broken Access Control / IDOR (OWASP A01)
            await ws_manager.broadcast_progress(scan_id, "OWASP A01: Broken Access Control (IDOR)", 78)
            log_cb("🔒 [A01:ACCESS] Mutating numeric object parameters and verifying authorization boundaries...", "INFO", "IDOR")
            idor_findings = scan_idor(discovered_endpoints, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(idor_findings)
            for idf in idor_findings:
                log_cb(f"🚨 [A01:ACCESS] IDOR VULNERABILITY: {idf['title']} on {idf['endpoint']}", "ALERT", "IDOR")

            # 8. Authentication & Session Testing (OWASP A07)
            await ws_manager.broadcast_progress(scan_id, "OWASP A07: Authentication & Session Audit", 86)
            log_cb("🍪 [A07:AUTH] Auditing cookie security flags (HttpOnly, Secure, SameSite) & burst-request rate-limiting...", "INFO", "AUTH")
            auth_findings = scan_auth(discovered_endpoints, cookies, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(auth_findings)
            for af in auth_findings:
                log_cb(f"⚠️ [A07:AUTH] {af['title']}", "WARN", "AUTH")

            # 9. File Upload Testing (OWASP A04)
            await ws_manager.broadcast_progress(scan_id, "OWASP A04: Insecure File Upload Probes", 92)
            log_cb("📤 [A04:UPLOAD] Executing safe non-destructive upload probes (MIME, double-extension, SVG)...", "INFO", "UPLOAD")
            upload_findings = scan_upload(discovered_endpoints, headers, timeout=scan.timeout, log_callback=log_cb)
            all_findings.extend(upload_findings)

            # 10. AI Security Advisor Synthesis & Mathematical Risk Evaluation
            await ws_manager.broadcast_progress(scan_id, "AI Security Reasoning & Risk Evaluation", 96)
            log_cb("🤖 [AI_ADVISOR] Running AI threat correlation, attack path modeling, and remediation prioritization...", "INFO", "AI")
            
            # Save Findings to DB
            for f in all_findings:
                finding_row = Finding(
                    scan_id=scan_id,
                    category=f.get("category", "general"),
                    owasp_category=f.get("owasp_category", "A05:2025-Security Misconfiguration"),
                    severity=f.get("severity", "Medium"),
                    title=f.get("title", ""),
                    description=f.get("description", ""),
                    endpoint=f.get("endpoint", ""),
                    parameter=f.get("parameter", ""),
                    payload=f.get("payload", ""),
                    evidence=f.get("evidence", ""),
                    cvss_score=f.get("cvss_score", 5.0),
                    cve_id=f.get("cve_id", ""),
                    remediation=f.get("remediation", ""),
                    file_path=f.get("file_path", ""),
                    line_number=f.get("line_number")
                )
                db.add(finding_row)
                asyncio.create_task(ws_manager.broadcast_finding(scan_id, f))

            # Real Mathematical Risk Evaluation
            stats = RiskEngine.get_summary_stats(
                all_findings,
                endpoints_count=len(discovered_endpoints),
                forms_count=len(discovered_forms)
            )

            # Generate AI Assessment
            ai_data = AISecurityAdvisor.generate_ai_assessment(
                target=target_url,
                technologies=techs,
                findings=all_findings,
                risk_stats=stats
            )
            scan.threat_intel = json.dumps(ai_data)

            scan.risk_score = stats["risk_score"]
            scan.critical_count = stats["critical_count"]
            scan.high_count = stats["high_count"]
            scan.medium_count = stats["medium_count"]
            scan.low_count = stats["low_count"]
            scan.info_count = stats["info_count"]
            scan.endpoints_count = len(discovered_endpoints)
            scan.forms_count = len(discovered_forms)
            scan.status = "completed"
            scan.completed_at = datetime.utcnow()
            db.commit()

            log_cb(
                f"🎉 [COMPLETE] Assessment finished! Calculated Risk Score: {scan.risk_score}/100 ({stats['risk_level']}) | CVSS Avg: {stats['cvss_average']} | Exploitability Index: {stats['exploitability_index']}/10",
                "SUCCESS",
                "CORE"
            )
            await ws_manager.broadcast_progress(scan_id, "Completed", 100, stats)

        except Exception as e:
            scan.status = "failed"
            db.commit()
            log_cb(f"❌ [CRITICAL_ERROR] Assessment halted unexpectedly: {str(e)}", "CRITICAL", "CORE")
            await ws_manager.broadcast_progress(scan_id, f"Failed: {str(e)}", 100)
        finally:
            db.close()
