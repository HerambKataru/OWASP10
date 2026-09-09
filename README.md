# SentinelX — Local AI-Powered OWASP Top 10 VAPT & Threat Intelligence Suite

> **Local Web Application Security Assessment Platform for Authorized Diagnostic & Educational Testing**

SentinelX is a full-stack cybersecurity assessment workstation designed to run **100% locally on localhost**. It combines automated OWASP Top 10 vulnerability scanning, static source code analysis (SAST), deep reconnaissance, a Burp-like HTTP Request Analyzer / Repeater, multi-source Threat Intelligence (VirusTotal, AbuseIPDB, Shodan, NVD CVE, WHOIS/DNS), and 14-section executive PDF and JSON reporting.

---

## Architecture Overview

```
sentinelx/
├── backend/                  # Python FastAPI, SQLAlchemy, SQLite, ReportLab, Scanners
│   ├── api/                  # Modular REST endpoints (Scans, Recon, Scanners, Analyzer, SAST, Intel, Reports, Settings)
│   ├── database/             # SQLite models & database session
│   ├── intelligence/         # Threat Intel Clients (VirusTotal, AbuseIPDB, Shodan, NVD CVE, WHOIS)
│   ├── reports/              # 14-Section ReportLab PDF & JSON generator
│   ├── scanners/             # Modular OWASP Top 10 Scanners (SQLi, XSS, IDOR, Auth, Upload, Headers, Exposure, SAST)
│   ├── services/             # Crawler, Scan Manager, Risk Engine, WebSocket live telemetry
│   ├── main.py               # FastAPI entrypoint & WebSocket endpoint
│   └── requirements.txt      # Python dependencies
│
└── frontend/                 # React (Vite) + Tailwind CSS + Lucide + Recharts
    ├── src/
    │   ├── components/       # Sidebar, Header, LiveTerminal, RiskGauge, FindingCard
    │   ├── pages/            # 15 Complete Cybersecurity views
    │   └── services/         # Axios API client & WebSocket listener
```

---

## Quick Start & Installation

### 1. Prerequisites
- Python 3.9+ installed
- Node.js 18+ and npm installed

---

### 2. Backend Setup & Run

Open a terminal and navigate to the backend folder:

```bash
cd sentinelx/backend

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate    # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Start FastAPI server
python3 main.py
```

The backend server will start on: **`http://localhost:8000`**  
Interactive Swagger API documentation is available at: **`http://localhost:8000/docs`**

---

### 3. Frontend Setup & Run

Open a second terminal window and navigate to the frontend folder:

```bash
cd sentinelx/frontend

# Install dependencies
npm install

# Start Vite dev server
npm run dev
```

The frontend web workstation will open on: **`http://localhost:5173`**

---

## 🔐 Firebase Authentication & Access Control

SentinelX is protected by a secure authentication layer powered by **Firebase Auth**:

1. **Accessing the Workstation**:
   - Navigate to `http://localhost:5173/login`
   - You can sign in using **Email & Password**, **Sign in with Google**, or click **1-Click Instant Analyst Access (Demo)** for immediate local diagnostic testing.
2. **Connecting your own Firebase Project (Optional)**:
   - In `sentinelx/frontend/`, copy `.env.example` to `.env`:
     ```bash
     cp sentinelx/frontend/.env.example sentinelx/frontend/.env
     ```
   - Paste your Firebase Web App credentials (`VITE_FIREBASE_API_KEY`, `VITE_FIREBASE_AUTH_DOMAIN`, `VITE_FIREBASE_PROJECT_ID`, etc.) from your Firebase Console.
   - Restart the frontend dev server (`npm run dev`).

---

## 🔑 Where and How to Add Threat Intelligence API Keys

SentinelX supports seamless threat intelligence enrichment through **VirusTotal**, **AbuseIPDB**, and **Shodan**. You can configure your API keys using **either of two convenient methods**:

### Method 1: Directly via the SentinelX Web UI (Recommended)
1. Launch SentinelX and open the web dashboard (`http://localhost:5173`).
2. Click on **Settings** in the bottom of the left sidebar navigation.
3. In the **Workstation Configuration & API Key Vault**, enter your API keys for:
   - **VirusTotal API Key** (Domain reputation, URL scanning, File hash lookup)
   - **AbuseIPDB API Key** (IP reputation scoring and malicious host history)
   - **Shodan API Key** (Passive port recon, SSL certs, and banner grabbing)
   - **NVD NIST API Key** (Optional - Increases CVE rate limits)
4. Click **Save Key**. The key will be stored securely and encrypted in the local SQLite database.

---

### Method 2: Via Environment Variables (`.env`)
1. In the `sentinelx/backend/` directory, create a `.env` file (or copy `.env.example`):
   ```bash
   cp sentinelx/backend/.env.example sentinelx/backend/.env
   ```
2. Open `sentinelx/backend/.env` in any text editor and paste your keys:
   ```env
   SENTINELX_SECRET_KEY=your_custom_secret_key_here
   VIRUSTOTAL_API_KEY=your_virustotal_api_key
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key
   SHODAN_API_KEY=your_shodan_api_key
   NVD_API_KEY=your_nvd_api_key
   ```
3. Restart the backend server. The application will automatically pick up the configured keys.

> **Note**: SentinelX includes a built-in intelligent fallback mode. If no external API keys are configured, all modules continue to operate safely with local simulated intelligence.

---

## Primary Modules & Features

| Module | Description |
| :--- | :--- |
| **Dashboard** | Consolidated 0-100 Risk Gauge, Severity charts, OWASP coverage radar, technology tags, and live WebSocket telemetry. |
| **New Scan** | **Mode 1 (Website)**: Configurable crawler depth, threads, timeout, custom User-Agent.<br/>**Mode 2 (SAST ZIP)**: Local extraction and static analysis of Python, JS, PHP, and secrets. |
| **Reconnaissance** | Automatic endpoint indexing, sitemap tree hierarchy, parameter matrix, technology fingerprinting, and DNS/WHOIS records. |
| **HTTP Analyzer** | Burp-like HTTP Repeater supporting GET/POST/PUT/PATCH/DELETE, live history feed, JWT claims decoder, and response diff comparison. |
| **SQL Injection** | Automated heuristic scanning for Error-based, Boolean differentials, Time-based blind delays, and Auth bypass vectors. |
| **Cross-Site Scripting** | Reflected XSS payload reflection detection and dangerous DOM sink analyzers (`innerHTML`, `eval`, `document.write`). |
| **Broken Access Control** | Direct Object Reference (IDOR) mutation testing across numerical identifiers (`/user/1`, `?id=10`). |
| **Authentication** | Audit of cookie security attributes (`HttpOnly`, `Secure`, `SameSite`) and login endpoint rate-limiting checks. |
| **File Upload Testing** | Safe non-destructive probes verifying MIME whitelisting, double extension bypasses, and SVG XML upload handling. |
| **Security Misconfiguration** | Audits CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and server banner leaks. |
| **Sensitive Data Exposure** | High-entropy regex scanner detecting exposed AWS keys, Slack tokens, API secrets, JWTs, and mixed content links. |
| **Static Code Analysis** | Line-by-line SAST scanner with code snippet viewer, vulnerability explanations, and secure coding remediation. |
| **Threat Intelligence** | VirusTotal reputation, AbuseIPDB confidence score, Shodan open ports and banners, WHOIS records. |
| **CVE Intelligence** | NIST NVD CVE keyword and software version lookup with CVSS v3 ratings and official references. |
| **Reports Engine** | 14-section ReportLab executive PDF generation with cover page and severity palettes, plus machine-readable JSON exports. |
| **Settings Vault** | Encrypted local SQLite key management with real-time masked status indicators. |

---

## Verification & Legal Disclaimer

**Disclaimer**: SentinelX is designed strictly for **authorized educational testing, defensive auditing, and diagnostic vulnerability assessment**. Never target systems, applications, or infrastructure without explicit written authorization from the owner.
