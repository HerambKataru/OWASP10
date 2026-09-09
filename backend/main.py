import os
import logging
from pathlib import Path
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from database.session import init_db
from services.websocket_manager import ws_manager

# Import API Routers
from api.scans import router as scans_router
from api.recon import router as recon_router
from api.scanners import router as scanners_router
from api.http_analyzer import router as http_router
from api.static_analysis import router as static_router
from api.intelligence import router as intel_router
from api.reports import router as reports_router
from api.settings import router as settings_router

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("sentinelx")

app = FastAPI(
    title="SentinelX — Local OWASP Top 10 VAPT & Threat Intelligence Suite",
    description="Local full-stack cybersecurity workstation for authorized penetration testing, SAST, threat intelligence, and reporting.",
    version="1.0.0"
)

# Enable CORS for Frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize Database tables on startup
@app.on_event("startup")
def on_startup():
    logger.info("Initializing SentinelX SQLite Database...")
    init_db()
    logger.info("SentinelX Backend Engine Initialized Successfully on port 8000")

# WebSocket for real-time live terminal & progress
@app.websocket("/ws/logs")
async def websocket_logs_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)

# Mount API Routers
app.include_router(scans_router)
app.include_router(recon_router)
app.include_router(scanners_router)
app.include_router(http_router)
app.include_router(static_router)
app.include_router(intel_router)
app.include_router(reports_router)
app.include_router(settings_router)

# Production Static File Mounting (if frontend build dist exists)
BASE_DIR = Path(__file__).resolve().parent
DIST_DIRS = [
    BASE_DIR.parent / "frontend_dist",
    BASE_DIR.parent / "frontend" / "dist"
]

frontend_dist = next((d for d in DIST_DIRS if d.exists() and (d / "index.html").exists()), None)

if frontend_dist:
    logger.info(f"Mounting production frontend build from: {frontend_dist}")
    app.mount("/assets", StaticFiles(directory=str(frontend_dist / "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_frontend_spa(full_path: str):
        file_path = frontend_dist / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(file_path)
        return FileResponse(frontend_dist / "index.html")
else:
    @app.get("/")
    def root():
        return {
            "name": "SentinelX Local Security Workstation",
            "status": "online",
            "docs": "/docs",
            "version": "1.0.0"
        }

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
