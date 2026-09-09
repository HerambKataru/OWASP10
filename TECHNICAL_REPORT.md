# SentinelX: Technical Architecture, Methodology & Vulnerability Assessment Report

**System Name:** SentinelX — Local AI-Powered OWASP Top 10 VAPT & Threat Intelligence Suite  
**Author / Team:** SentinelX Security Engineering Team  
**Classification:** Technical Documentation & Architectural Reference  
**Standard Compliance:** OWASP Top 10:2021, NIST SP 800-115, CWE/SANS Top 25  
**Execution Environment:** 100% Localhost Air-Gapped / Isolated Operation  

---

## 1. Executive Overview

Modern web applications present increasingly complex attack surfaces due to distributed architectures, dynamic client-side rendering, and multifaceted third-party integrations. **SentinelX** was architected as an all-in-one local security assessment workstation providing unified **Dynamic Application Security Testing (DAST)**, **Static Application Security Testing (SAST)**, **Reconnaissance**, **HTTP Analysis & Replay (Burp-like Repeater)**, and **Multi-Source Threat Intelligence Correlation**.

SentinelX operates under a strictly **non-destructive paradigm**, meaning that while active heuristics and probes are executed to identify vulnerabilities, the engine avoids irreversible data manipulation or disruptive denial-of-service behaviors.

```
+-----------------------------------------------------------------------------------+
|                                 SENTINELX WORKSTATION                             |
+-----------------------------------------------------------------------------------+
|  [ FRONTEND - React + Vite + Tailwind + Recharts + Monaco Telemetry ]             |
|    - 15 Dedicated Cyberpunk Navigation Views (Dashboard, Scanners, Intel, SAST)   |
|    - Real-time WebSocket Live Telemetry Feed (ws://localhost:8000/ws/logs)       |
+-----------------------------------------------------------------------------------+
                                         │  HTTP / JSON & WebSocket Events
                                         ▼
+-----------------------------------------------------------------------------------+
|  [ BACKEND ENGINE - FastAPI + SQLite + SQLAlchemy + Asyncio Task Workers ]        |
|    - Scan Manager & Crawler Service (Recursive BFS, Form Parser, Tech Signature)  |
|    - Risk Scoring Engine (0-100 Consolidated Heuristic with CVSS v3.1 Mapping)    |
|    - ReportLab 14-Section PDF & Machine-Readable JSON Export Pipelines            |
+-----------------------------------------------------------------------------------+
       │                   │                      │                     │
       ▼                   ▼                      ▼                     ▼
 ┌───────────┐      ┌──────────────┐      ┌───────────────┐     ┌───────────────┐
 │ DAST CORE │      │  SAST ENGINE │      │ HTTP ANALYZER │     │  THREAT INTEL │
 │ - SQLi    │      │ - ZIP Parser │      │ - Repeater    │     │ - VirusTotal  │
 │ - XSS     │      │ - AST / Regex│      │ - JWT Decoder │     │ - AbuseIPDB   │
 │ - IDOR    │      │ - Code Line  │      │ - Diff Engine │     │ - Shodan      │
 │ - Auth    │      │   Highlighter│      │ - History DB  │     │ - NVD NIST CVE│
 │ - Upload  │      │ - Secret Hunt│      └───────────────┘     │ - WHOIS / DNS │
 │ - Headers │      └──────────────┘                            └───────────────┘
 └───────────┘
```

---

## 2. System Architecture & Component Design

The SentinelX application is partitioned into two decoupled tiers:

### 2.1 Backend Architecture (FastAPI & SQLite)
1. **Core Service Layer (`backend/services/`):**
   - **`crawler.py`**: High-performance recursive HTTP crawler with same-domain constraint enforcement, robots.txt & sitemap.xml auto-discovery, form input parameter extraction, and JavaScript script asset mapping.
   - **`scan_manager.py`**: Asynchronous task orchestrator executing scanners sequentially or in parallel while publishing structured live telemetry logs to the WebSocket bus.
   - **`risk_engine.py`**: Mathematical weighted scoring model translating raw findings into a standardized 0–100 risk score and CVSS severity distribution.
   - **`websocket_manager.py`**: Multi-client event multiplexer broadcasting real-time progress percentages and log messages.

2. **Scanner Modular Engine (`backend/scanners/`):**
   - Each OWASP Top 10 category is isolated into dedicated, modular Python routines with standardized signatures returning normalized `Finding` structures.

3. **Threat Intelligence Layer (`backend/intelligence/`):**
   - Standardized client wrappers for VirusTotal v3, AbuseIPDB v2, Shodan REST API, and NIST NVD CVE 2.0 API with local fallback mechanisms.

4. **Persistence & Encryption Layer (`backend/database/`, `backend/config.py`):**
   - SQLite persistence layer with SQLAlchemy ORM storing scans, endpoints, findings, HTTP history, and encrypted API key settings.

---

### 2.2 Frontend Architecture (React + Vite + Tailwind CSS)
- **Aesthetic Philosophy:** Dark Cyberpunk theme (`#080C14`, `#0C1220`) with neon cyan (`#00F0FF`), emerald green (`#00FF9D`), and warning amber/red accents.
- **Interactive Visualizations:** Radial SVG Risk Gauge, Recharts Pie & Radar charts displaying OWASP Top 10 coverage, and real-time streaming terminal log with ANSI-inspired severity coloring.
- **Navigation Topology:** 15 distinct views covering Dashboard, New Scan, Recon, HTTP Repeater, 7 OWASP scanner modules, SAST Code Viewer, Threat Intel, CVE Database, Reports, and Key Settings.

---

## 3. OWASP Top 10:2021 Detection Methodologies & Heuristics

| OWASP Category | Module | Testing Mechanism & Heuristics |
| :--- | :--- | :--- |
| **A01:2021 - Broken Access Control** | `idor.py` | Detects numeric object parameters (`/user/1`, `?id=10`) and generates adjacent probes (`n+1`, `n-1`, `0`). Compares status codes, body lengths, and headers to identify unauthorized horizontal privilege escalation. |
| **A02:2021 - Cryptographic Failures** | `exposure.py` | Employs high-entropy regex pattern matching against HTML responses and JavaScript assets to detect exposed AWS Access Keys, Google Cloud Keys, Slack Webhooks, JWT tokens, and hardcoded credentials. Also flags insecure HTTP references in HTTPS contexts. |
| **A03:2021 - Injection (SQLi & XSS)** | `sqli.py` & `xss.py` | **SQLi:** Evaluates database error signatures across MySQL, PostgreSQL, SQLite, MSSQL, and Oracle; checks Boolean response size differences; evaluates time-based sleep delays.<br/>**XSS:** Injects benign script tags and checks for unsanitized reflection in HTML context; audits JavaScript source files for dangerous DOM sinks (`innerHTML`, `eval`, `document.write`, `location.hash`). |
| **A04:2021 - Insecure Design** | `upload.py` | Detects `<input type="file">` upload forms and sends harmless probes (`test.php.png`, `.svg` with XML text) to check MIME validation, double extension acceptance, and SVG execution hazards. |
| **A05:2021 - Security Misconfiguration** | `headers.py` | Audits HTTP responses for missing headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Flags server banner version leaks (Server, X-Powered-By). |
| **A06:2021 - Vulnerable Components** | `static.py` & `cve.py` | Static code analysis scanning Python (`exec`, `pickle.loads`, `subprocess`), JavaScript (`eval`, `child_process`), and PHP (`system`, `shell_exec`, `unserialize`). Cross-references detected technologies against NIST NVD CVE database. |
| **A07:2021 - Auth Failures** | `auth.py` | Audits `Set-Cookie` directives for missing `HttpOnly`, `Secure`, and `SameSite` flags. Executes burst requests against authentication endpoints to verify rate-limiting protection against brute-force credential stuffing. |

---

## 4. Mathematical Risk Engine Formulation

The overall application Risk Score ($R$) is calculated as an aggregated weighted function bounded between $0.0$ and $100.0$:

$$R = \min\left(100.0, \sum_{i=1}^{N} W(S_i)\right)$$

Where $S_i$ denotes the severity classification of finding $i$, and the weight function $W(S)$ is defined as:

$$W(\text{Critical}) = 25.0$$
$$W(\text{High}) = 15.0$$
$$W(\text{Medium}) = 8.0$$
$$W(\text{Low}) = 3.0$$
$$W(\text{Informational}) = 0.5$$

Qualitative risk tiering is categorized as:
- **$R \ge 75.0$:** Critical Risk (Immediate remediation mandatory)
- **$50.0 \le R < 75.0$:** High Risk (Significant exploitable attack surface)
- **$25.0 \le R < 50.0$:** Moderate Risk (Security misconfigurations present)
- **$0.0 < R < 25.0$:** Low Risk (Minor hygiene & informational findings)
- **$R = 0.0$:** Clean (No vulnerabilities identified)

---

## 5. Threat Intelligence Enrichment Pipeline

```
                     ┌──────────────────┐
                     │ Target Domain/IP │
                     └────────┬─────────┘
                              │
         ┌────────────────────┼────────────────────┐
         ▼                    ▼                    ▼
 ┌───────────────┐    ┌───────────────┐    ┌───────────────┐
 │  VirusTotal   │    │   AbuseIPDB   │    │    Shodan     │
 │ - Reputation  │    │ - Abuse Score │    │ - Open Ports  │
 │ - Detection % │    │ - ISP / Geo   │    │ - SSL Certs   │
 │ - Hash Lookup │    │ - Report Hist │    │ - Svc Banners │
 └───────┬───────┘    └───────┬───────┘    └───────┬───────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              ▼
                     ┌──────────────────┐
                     │ SentinelX Engine │
                     │ Multi-Factor     │
                     │ Correlation Card │
                     └──────────────────┘
```

1. **VirusTotal v3:** Aggregates reputation scores across 70+ security vendors, providing malicious/suspicious detection ratios and domain categorization.
2. **AbuseIPDB v2:** Calculates real-time IP abuse confidence percentages, identifies hosting provider/ISP ASN details, and checks historical incident reports.
3. **Shodan:** Passively collects open listening ports, running services, and server banners without direct intrusive port scanning.
4. **NIST NVD CVE v2.0:** Live query client retrieving CVSS v3.1 base metrics, published dates, and official vulnerability references for detected software stacks.

---

## 6. HTTP Request Analyzer & Repeater Specifications

The built-in HTTP Analyzer replicates essential workflows of enterprise proxy tools (e.g., Burp Suite Repeater):
- **Ad-hoc Request Dispatcher:** Custom crafting of HTTP verbs (`GET`, `POST`, `PUT`, `PATCH`, `DELETE`, `OPTIONS`), arbitrary headers, and body payloads with sub-millisecond round-trip timing.
- **JWT Cryptographic Claims Decoder:** Parses Base64-URL encoded JSON Web Tokens into Header, Payload claims, and Signature segments, displaying expiration status (`exp`) and active signing algorithms (`alg`).
- **Response Difference Engine:** Executes sequence matching algorithms (`difflib`) to generate side-by-side delta views and compute response similarity percentages during parameter tampering tests.

---

## 7. Reporting & Compliance Deliverables

SentinelX generates formal 14-section assessment reports via ReportLab:

1. **Cover Page:** Formal classification, target metadata, assessment timestamps, and confidentiality notices.
2. **Executive Summary:** Consolidated risk metrics and severity distribution tables.
3. **Target Scope:** Documented URI boundaries and crawl depth limits.
4. **Methodology:** OWASP OTG v4 and NIST SP 800-115 testing framework references.
5. **Reconnaissance Results:** Discovered URI routes and input parameter matrices.
6. **Technology Stack:** Fingerprinted backend frameworks, web servers, and client libraries.
7. **Threat Intelligence:** Correlated external domain reputation and IP history.
8. **Detailed OWASP Findings:** Individual findings formatted with CVSS badges, vulnerable parameters, payload strings, proof-of-concept evidence, and specific remediation advice.
9. **Payloads Used:** Summary of non-destructive verification strings.
10. **HTTP Evidence:** Request/response snippets and headers.
11. **Screenshots / Visual Telemetry:** Telemetry data mapping.
12. **CVE & CWE Mapping:** Standard compliance categorization.
13. **Remediation Roadmap:** Prioritized developer action plan.
14. **Appendix:** Assessment tool versioning and methodology sign-off.

---

## 8. Conclusion & Security Recommendations

SentinelX provides security engineers, developers, and penetration testers with a unified local workstation for discovering, validating, and remediating OWASP Top 10 vulnerabilities before deployment. By integrating DAST automation, SAST inspection, and threat intelligence in an air-gapped, non-destructive architecture, SentinelX establishes a defensible security baseline for modern web applications.
