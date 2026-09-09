from typing import List, Dict, Any
from fastapi import WebSocket
import json
import logging
from datetime import datetime

logger = logging.getLogger("sentinelx.ws")

class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast_log(self, scan_id: int, message: str, level: str = "INFO", component: str = "ENGINE"):
        """Broadcast live terminal log to all connected clients"""
        timestamp = datetime.utcnow().strftime("%H:%M:%S")
        payload = {
            "type": "log",
            "scan_id": scan_id,
            "timestamp": timestamp,
            "level": level, # INFO, WARN, ALERT, CRITICAL, SUCCESS
            "component": component,
            "message": message
        }
        await self.broadcast_json(payload)

    async def broadcast_progress(self, scan_id: int, step: str, percentage: int, stats: Dict[str, Any] = None):
        payload = {
            "type": "progress",
            "scan_id": scan_id,
            "step": step,
            "percentage": percentage,
            "stats": stats or {}
        }
        await self.broadcast_json(payload)

    async def broadcast_finding(self, scan_id: int, finding: Dict[str, Any]):
        payload = {
            "type": "finding",
            "scan_id": scan_id,
            "finding": finding
        }
        await self.broadcast_json(payload)

    async def broadcast_json(self, data: dict):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(data)
            except Exception:
                disconnected.append(connection)
        for d in disconnected:
            self.disconnect(d)

ws_manager = ConnectionManager()
