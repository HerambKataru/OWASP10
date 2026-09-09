# SentinelX Deployment Guide 🚀

This guide details all deployment workflows for **SentinelX** — including 1-command Docker containers, Linux VPS (Nginx + Systemd), and Cloud PaaS providers (Render, Railway, Fly.io, AWS, GCP).

---

## 📦 Option 1: 1-Command Docker & Docker Compose (Recommended)

The easiest and cleanest way to deploy SentinelX in a self-contained container.

### 1. Build and Run Container
From the `sentinelx/` root directory:

```bash
docker-compose up -d --build
```

### 2. Access Workstation
Open your browser and navigate to:
**`http://localhost:8000`**

### 3. Container Management Commands
```bash
# View live logs
docker-compose logs -f

# Stop container
docker-compose down

# Restart container
docker-compose restart
```

---

## ☁️ Option 2: Cloud PaaS Deployment (Render / Railway / Fly.io)

### Deploying via Docker on Render / Railway:
1. Connect your GitHub repository: `https://github.com/HerambKataru/OWASP10.git`
2. Set **Root Directory**: `sentinelx`
3. Set **Environment**: `Docker`
4. Set **Port**: `8000`
5. Configure Environment Variables (Optional):
   - `SENTINELX_SECRET_KEY` = `your_secret_key`
   - `VIRUSTOTAL_API_KEY` = `your_vt_key`
   - `ABUSEIPDB_API_KEY` = `your_abuseipdb_key`
   - `SHODAN_API_KEY` = `your_shodan_key`
6. Click **Deploy**.

---

## 🖥️ Option 3: Dedicated Linux VPS / Server Deployment (Ubuntu / Debian)

### 1. Clone & Setup Environment
```bash
# Clone repository
git clone https://github.com/HerambKataru/OWASP10.git
cd OWASP10/sentinelx

# Install Python & Node.js
sudo apt update && sudo apt install -y python3 python3-pip python3-venv nodejs npm nginx

# Build Frontend
cd frontend
npm install
npm run build
cd ..

# Setup Python Backend
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd ..
```

---

### 2. Configure Systemd Service (`/etc/systemd/system/sentinelx.service`)
Create the system service unit:

```ini
[Unit]
Description=SentinelX VAPT Backend Engine
After=network.target

[Service]
User=ubuntu
WorkingDirectory=/home/ubuntu/OWASP10/sentinelx/backend
ExecStart=/home/ubuntu/OWASP10/sentinelx/backend/venv/bin/uvicorn main:app --host 127.0.0.1 --port 8000 --workers 4
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start the service:
```bash
sudo systemctl daemon-reload
sudo systemctl enable sentinelx
sudo systemctl start sentinelx
```

---

### 3. Configure Nginx Reverse Proxy (`/etc/nginx/sites-available/sentinelx`)
Create Nginx reverse proxy configuration:

```nginx
server {
    listen 80;
    server_name your-server-ip-or-domain.com;

    # Frontend Static SPA & API Proxy
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # WebSocket Telemetry Stream Proxy
    location /ws/ {
        proxy_pass http://127.0.0.1:8000/ws/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }
}
```

Enable site and restart Nginx:
```bash
sudo ln -s /etc/nginx/sites-available/sentinelx /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

---

## 🔒 Security Best Practices for Production Deployment

1. **Firewall Rules**: If running on a remote cloud instance, ensure port `8000` is kept internal and traffic is routed via port `80`/`443` through HTTPS.
2. **HTTPS / SSL Encryption**: Set up a free Let's Encrypt certificate:
   ```bash
   sudo certbot --nginx -d your-domain.com
   ```
3. **Authorized Scope Only**: SentinelX is designed for testing systems you have written permission to audit. Never run active scans against unauthorized hosts.
