# SentinelX: Technical Architecture, Methodology & Vulnerability Assessment Report

**System Name:** SentinelX — Local AI-Powered OWASP Top 10:2025 VAPT & Threat Intelligence Suite  
**Author / Team:** SentinelX Security Engineering Team  
**Classification:** Technical Documentation & Architectural Reference  
**Standard Compliance:** OWASP Top 10:2025, NIST SP 800-115, CWE/SANS Top 25  
**Execution Environment:** Localhost Isolated & Production Hybrid (Docker / Render / Vercel / Firebase)  

---

## 1. Executive Overview

Modern web applications present increasingly complex attack surfaces due to distributed microservices, single-page client rendering (SPA), API gateways, and dynamic cloud integrations. **SentinelX** was architected as a comprehensive, production-grade security assessment workstation providing unified **Dynamic Application Security Testing (DAST)**, **Static Application Security Testing (SAST)**, **Reconnaissance**, **HTTP Analysis & Replay (Burp-like Repeater)**, **AI Security Reasoning**, and **Multi-Source Threat Intelligence Correlation**.

SentinelX operates under a strictly **non-destructive verification paradigm**, meaning that while rigorous active heuristics, parameter fuzzing, and boundary probes are executed to identify vulnerabilities, the engine avoids disruptive denial-of-service behaviors or persistent database destruction.

```
+-----------------------------------------------------------------------------------+
|                                 SENTINELX WORKSTATION                             |
+-----------------------------------------------------------------------------------+
|  [ FRONTEND - React + Vite + Tailwind + Recharts + Monaco Telemetry ]             |
|    - 15 Dedicated Cyberpunk Navigation Views (Dashboard, Scanners, Intel, SAST)   |
|    - Firebase Authentication (Secure JWT & Session State)                         |
|    - Real-time WebSocket Live Telemetry Feed (ws://localhost:8000/ws/logs)       |
+-----------------------------------------------------------------------------------+
                                         │  HTTP / JSON & WebSocket Events
                                         ▼
+-----------------------------------------------------------------------------------+
|  [ BACKEND ENGINE - FastAPI + SQLite / PostgreSQL + Asyncio Task Workers ]        |
|    - Scan Manager & Crawler Service (Recursive BFS, Form Parser, Tech Signature)  |
|    - Risk Scoring Engine (Multi-Parametric CVSS v3.1 + OWASP 2025 Weighting)      |
|    - AI Security Advisor (Chained Attack Paths, Root Cause Triage, P0-P3 Timeline)|
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

### 2.1 Backend Architecture (FastAPI & SQLAlchemy)
1. **Core Service Layer (`backend/services/`):**
   - **`crawler.py`**: High-performance recursive HTTP crawler with same-domain constraint enforcement, `robots.txt` & `sitemap.xml` auto-discovery, form input parameter extraction, and JavaScript script asset mapping.
   - **`scan_manager.py`**: Asynchronous task orchestrator executing scanners sequentially or in parallel while publishing structured live telemetry logs and progress percentages to the WebSocket bus.
   - **`risk_engine.py`**: Mathematical multi-parametric scoring model translating raw findings into a standardized 0–100 risk score, exploitability index, and CVSS severity distribution.
   - **`ai_advisor.py`**: AI threat modeling engine synthesizing root cause analysis, multi-stage chained attack paths, and prioritized remediation plans.
   - **`websocket_manager.py`**: Multi-client event multiplexer broadcasting real-time progress percentages and log messages.

2. **Scanner Modular Engine (`backend/scanners/`):**
   - Each OWASP Top 10:2025 category is isolated into dedicated, modular Python routines with standardized signatures returning normalized `Finding` structures.

3. **Threat Intelligence Layer (`backend/intelligence/`):**
   - Standardized client wrappers for VirusTotal v3, AbuseIPDB v2, Shodan REST API, and NIST NVD CVE 2.0 API with local fallback mechanisms.

4. **Persistence Layer (`backend/database/`):**
   - SQLite / PostgreSQL persistence layer with SQLAlchemy ORM storing scans, endpoints, findings, HTTP history, and encrypted API key settings.

---

## 3. OWASP Top 10:2025 Detection Methodologies & Heuristics

| OWASP Top 10:2025 Category | Module | Testing Mechanism & Heuristics |
| :--- | :--- | :--- |
| **A01:2025 - Broken Access Control** | `idor.py` | Detects numeric object parameters (`/user/1`, `?id=10`) and executes neighbor boundary probes (`n+1`, `n-1`, `0`, `99999`). Compares status codes, body lengths, and headers to identify unauthorized horizontal/vertical privilege escalation. |
| **A02:2025 - Cryptographic Failures** | `exposure.py` | Employs high-entropy regex pattern matching against HTML responses and JavaScript assets to detect exposed AWS Access Keys, Google Cloud Keys, Slack Webhooks, JWT tokens, and hardcoded credentials. Also audits mixed content (insecure HTTP resources on HTTPS pages). |
| **A03:2025 - Injection & Execution** | `sqli.py` & `xss.py` | **SQLi:** Evaluates database error signatures across MySQL, PostgreSQL, SQLite, MSSQL, and Oracle; checks Boolean response size differences; evaluates time-based sleep delays. Actively fuzzes discovered query parameters, form fields, and fallback probe parameters (`id`, `user`, `q`, `search`, `cat`, `page`).<br/>**XSS:** Injects benign script tags and checks for unsanitized reflection in HTML context; audits JavaScript source files and inline scripts for dangerous DOM sinks (`innerHTML`, `eval`, `document.write`, `location.hash`, `location.search`). |
| **A04:2025 - Insecure Architecture & Design** | `upload.py` | Detects `<input type="file">` upload forms and candidate upload endpoints (`/upload`, `/api/upload`), sending harmless probes (`test.php.png`, `.svg` with XML text) to check MIME validation, double extension acceptance, and SVG execution hazards. |
| **A05:2025 - Security Misconfiguration** | `headers.py` | Audits HTTP responses for missing headers: Content-Security-Policy (CSP), Strict-Transport-Security (HSTS), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy. Flags server banner version leaks (`Server`, `X-Powered-By`). |
| **A06:2025 - Vulnerable & Outdated Dependencies** | `static.py` & `cve.py` | Static code analysis scanning Python (`exec`, `pickle.loads`, `subprocess`), JavaScript (`eval`, `child_process`), and PHP (`system`, `shell_exec`, `unserialize`). Cross-references detected technologies against NIST NVD CVE database. |
| **A07:2025 - Identification & Authentication Failures** | `auth.py` | Audits `Set-Cookie` directives for missing `HttpOnly`, `Secure`, and `SameSite` flags. Executes burst requests against authentication endpoints (`/login`, `/signin`, `/admin`, `/api/auth`) to verify rate-limiting protection against brute-force credential stuffing. |
| **A08:2025 - Software and Data Integrity Failures** | `static.py` | Flags unsafe dynamic deserialization (`pickle.loads`, `unserialize`) and dynamic code execution patterns in source code archives. |
| **A09:2025 - Security Logging & Anomaly Failures** | `risk_engine.py` | Identifies missing rate limit response headers (`X-RateLimit-*`, `Retry-After`) and unhandled stack trace disclosures. |
| **A10:2025 - Server-Side Request Forgery (SSRF)** | `recon.py` | Audits URL redirect parameters (`?redirect=`, `?url=`, `?dest=`) and probes internal network boundary references. |

---

## 4. Advanced Multi-Parametric Risk Scoring Model

SentinelX implements a real mathematical risk evaluation model based on multi-factorial aggregation:

### 4.1 Base Weighted Formulation
The raw weighted vulnerability score ($S_{\text{raw}}$) is computed from severity counts and categorical weights:

$$S_{\text{raw}} = \sum_{k \in \text{Findings}} W(\text{Severity}_k) \cdot W_{\text{OWASP}}(\text{Category}_k)$$

Where base severity weights $W(\text{Severity})$ are defined as:
- $\text{Critical} = 25.0$
- $\text{High} = 15.0$
- $\text{Medium} = 8.0$
- $\text{Low} = 3.0$
- $\text{Informational} = 0.5$

### 4.2 Compounding Attack Surface Multipliers
1. **Categorical Diversity Factor ($F_{\text{div}}$):** Having multiple distinct vulnerability classes (e.g. SQLi + Auth Bypass + IDOR) creates synergistic exploitation opportunities:
   $$F_{\text{div}} = 1.0 + (\min(|\text{Categories}|, 6) \times 0.08)$$

2. **Attack Surface Multiplier ($F_{\text{surface}}$):** Scaled against the number of accessible endpoints ($E$) and form inputs ($I$):
   $$F_{\text{surface}} = 1.0 + \min\left(0.35, (E \times 0.015) + (I \times 0.025)\right)$$

3. **Threat Intelligence Factor ($F_{\text{threat}}$):** Enriches internal findings with external threat reputation scores ($T_{\text{intel}} \in [0, 100]$):
   $$F_{\text{threat}} = 1.0 + \min\left(0.20, \frac{T_{\text{intel}}}{100.0} \times 0.20\right)$$

### 4.3 Sigmoid Bounding & Floor Calculation
The final risk score ($R \in [0.0, 100.0]$) is calculated with severity floor enforcement:

$$R_{\text{combined}} = S_{\text{raw}} \cdot F_{\text{div}} \cdot F_{\text{surface}} \cdot F_{\text{threat}}$$

$$\text{Final Risk Score } R = 
\begin{cases} 
\max(70.0, \min(100.0, 70.0 + 0.35 \cdot R_{\text{combined}})), & \text{if } N_{\text{crit}} > 0 \\
\max(45.0, \min(89.0, 45.0 + 0.45 \cdot R_{\text{combined}})), & \text{if } N_{\text{high}} > 0 \\
\max(20.0, \min(65.0, 20.0 + 0.55 \cdot R_{\text{combined}})), & \text{if } N_{\text{med}} > 0 \\
\min(35.0, 0.8 \cdot R_{\text{combined}}), & \text{otherwise}
\end{cases}$$

### 4.4 Qualitative Tiering
- **$R \ge 75.0$:** **CRITICAL RISK** (Immediate remediation mandatory before production)
- **$50.0 \le R < 75.0$:** **HIGH RISK** (Significant exploitable attack surface)
- **$25.0 \le R < 50.0$:** **MODERATE RISK** (Security misconfigurations present)
- **$0.0 < R < 25.0$:** **LOW RISK** (Minor hygiene & informational findings)
- **$R = 0.0$:** **CLEAN** (No vulnerabilities identified)

---

## 5. AI Security Advisor Engine

The SentinelX AI Security Advisor synthesizes multi-dimensional telemetry into actionable executive intelligence:
1. **Executive Threat Summary:** Generates contextual natural-language assessments detailing organizational exposure and compliance implications.
2. **Chained Attack Path Modeling:** Maps how an adversary can chain low/medium findings (e.g. Server Banner Leak $\rightarrow$ Known CVE $\rightarrow$ Reflected XSS $\rightarrow$ Session Hijacking $\rightarrow$ IDOR) into full system compromise.
3. **Remediation Prioritization Timeline (P0–P3):**
   - **P0 - Immediate (< 24h):** SQL Injection, RCE, Deserialization, Unauthenticated IDOR.
   - **P1 - High (< 48h):** Reflected XSS, Hardcoded High-Entropy Secrets, Auth Rate Limiting.
   - **P2 - Medium (< 1 Week):** Cookie Security Flags (`HttpOnly`, `Secure`, `SameSite`), Missing CSP/HSTS.
   - **P3 - Hardening (< 2 Weeks):** Server Banner Suppression, Mixed Content Remediation.

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
4. **Methodology:** OWASP Top 10:2025 and NIST SP 800-115 testing framework references.
5. **Reconnaissance Results:** Discovered URI routes and input parameter matrices.
6. **Technology Stack:** Fingerprinted backend frameworks, web servers, and client libraries.
7. **Threat Intelligence:** Correlated external domain reputation and IP history.
8. **Detailed OWASP Findings:** Individual findings formatted with CVSS badges, vulnerable parameters, payload strings, proof-of-concept evidence, and specific remediation advice.
9. **Payloads Used:** Summary of non-destructive verification strings.
10. **HTTP Evidence:** Request/response snippets and headers.
11. **Visual Telemetry:** Telemetry data mapping.
12. **CVE & CWE Mapping:** Standard compliance categorization.
13. **Remediation Roadmap:** Prioritized developer action plan.
14. **Appendix:** Assessment tool versioning and methodology sign-off.

---

## 8. Conclusion & Operational Baseline

SentinelX provides security engineers, developers, and penetration testers with a unified workstation for discovering, validating, and remediating OWASP Top 10:2025 vulnerabilities before deployment. By integrating DAST parameter fuzzing, SAST inspection, AI threat correlation, and threat intelligence in a modular architecture, SentinelX establishes a defensible, production-ready security baseline for modern web applications.
