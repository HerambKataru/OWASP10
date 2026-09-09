# SentinelX Cloud Deployment Guide 🚀
## Backend on Render + Frontend on Vercel + Database on Firebase

This document provides step-by-step instructions to deploy SentinelX across a distributed cloud architecture:
- **Backend API & WebSocket Telemetry**: [Render.com](https://render.com) (FastAPI Python Web Service)
- **Frontend SPA**: [Vercel](https://vercel.com) (React + Vite SPA)
- **Authentication & Cloud Database**: [Firebase](https://firebase.google.com) (Auth + Firestore Database)

---

## 🏗️ Architecture Flow

```
+---------------------------+             +---------------------------+
|      VERCEL FRONTEND      | ────REST───▶|       RENDER BACKEND      |
|  (React + Vite SPA + WSS) | ◀──WS Logs─ |   (FastAPI + Scanners)    |
+---------------------------+             +---------------------------+
              │                                         │
              ▼                                         ▼
+---------------------------+             +---------------------------+
|    FIREBASE CLOUD DB      |             |     LOCAL SQLITE VAULT    |
|   (Auth + Firestore Sync) |             |  (Persistent Encrypted DB)|
+---------------------------+             +---------------------------+
```

---

## ⚡ Step 1: Deploy Backend on Render (Python FastAPI)

1. Log into your [Render Dashboard](https://dashboard.render.com).
2. Click **New +** and select **Web Service**.
3. Connect your GitHub repository:
   `https://github.com/HerambKataru/OWASP10.git`
4. Configure the service settings:
   - **Name**: `sentinelx-backend`
   - **Root Directory**: `sentinelx/backend`
   - **Runtime**: `Python 3`
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`
   - **Instance Type**: `Free`
5. Add Environment Variables (under **Advanced**):
   - `SENTINELX_SECRET_KEY` = `sentinelx_secret_master_vapt_key_2026`
   - `VIRUSTOTAL_API_KEY` = `your_virustotal_key` (Optional)
   - `ABUSEIPDB_API_KEY` = `your_abuseipdb_key` (Optional)
   - `SHODAN_API_KEY` = `your_shodan_key` (Optional)
6. Click **Create Web Service**.
7. Once deployed, copy your Render Service URL (e.g. `https://sentinelx-backend.onrender.com`).

---

## ⚡ Step 2: Set up Firebase Authentication & Firestore

1. Go to the [Firebase Console](https://console.firebase.google.com).
2. Click **Add project** and name it `sentinelx-vapt`.
3. In the project dashboard:
   - Go to **Build > Authentication** > Click **Get Started**.
   - Enable **Email/Password** and **Google** sign-in providers.
   - Go to **Build > Firestore Database** > Click **Create Database** (Start in production or test mode).
4. Go to **Project Settings** (gear icon) > Scroll to **Your apps** > Click the **Web (</>)** icon.
5. Register app name (e.g. `SentinelX Web`) and copy the `firebaseConfig` keys:
   ```javascript
   apiKey: "AIzaSy...",
   authDomain: "sentinelx-vapt.firebaseapp.com",
   projectId: "sentinelx-vapt",
   storageBucket: "sentinelx-vapt.appspot.com",
   messagingSenderId: "123456789",
   appId: "1:123456789:web:..."
   ```

---

## ⚡ Step 3: Deploy Frontend on Vercel (React Vite)

1. Log into your [Vercel Dashboard](https://vercel.com).
2. Click **Add New... > Project**.
3. Import your GitHub repository:
   `https://github.com/HerambKataru/OWASP10.git`
4. Configure project settings:
   - **Project Name**: `sentinelx-vapt`
   - **Framework Preset**: `Vite`
   - **Root Directory**: Click **Edit** and select `sentinelx/frontend`
   - **Build Command**: `npm run build`
   - **Output Directory**: `dist`
5. Expand **Environment Variables** and add:
   - `VITE_API_BASE_URL` = `https://sentinelx-backend.onrender.com` (Your Render URL from Step 1)
   - `VITE_WS_BASE_URL` = `wss://sentinelx-backend.onrender.com` (Your WebSocket Render URL)
   - `VITE_FIREBASE_API_KEY` = `your_firebase_api_key`
   - `VITE_FIREBASE_AUTH_DOMAIN` = `your_project.firebaseapp.com`
   - `VITE_FIREBASE_PROJECT_ID` = `your_project_id`
   - `VITE_FIREBASE_STORAGE_BUCKET` = `your_project.appspot.com`
   - `VITE_FIREBASE_MESSAGING_SENDER_ID` = `your_sender_id`
   - `VITE_FIREBASE_APP_ID` = `your_app_id`
6. Click **Deploy**.
7. Vercel will build and assign your production domain (e.g. `https://sentinelx-vapt.vercel.app`).

---

## 🔄 Step 4: Verification & Live Health Check

1. Open your Vercel URL in your browser: `https://sentinelx-vapt.vercel.app/login`
2. Sign in using your **Firebase credentials**, **Google Sign-In**, or the **1-Click Demo Analyst Access**.
3. Start a new scan:
   - Target: `https://example.com`
   - Verify that the live telemetry logs and progress bar stream via WebSocket from your Render backend.
   - Verify that findings, risk scores, and AI recommendations display on the dashboard.

---

## 🛠️ Summary of Deployment Artifacts in Repository

| File | Purpose |
| :--- | :--- |
| **`sentinelx/render.yaml`** | Blueprint for Render automated 1-click backend deployment |
| **`sentinelx/frontend/vercel.json`** | Vercel SPA routing rewrites and asset cache headers |
| **`sentinelx/frontend/src/services/firebase.js`** | Firebase Auth client initialization with fallback |
| **`sentinelx/frontend/src/services/firebaseDb.js`** | Firestore real-time cloud scan data synchronization |
| **`sentinelx/Dockerfile`** & **`docker-compose.yml`** | Local / Docker containerized alternative deployment |
