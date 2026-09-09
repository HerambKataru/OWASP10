import json
import urllib.parse
from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Scan, Endpoint

router = APIRouter(prefix="/api/recon", tags=["Reconnaissance"])

@router.get("/{scan_id}/endpoints")
def get_recon_endpoints(scan_id: int, db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    res = []
    for ep in endpoints:
        try:
            params = json.loads(ep.parameters) if ep.parameters else []
            forms = json.loads(ep.forms) if ep.forms else []
        except Exception:
            params, forms = [], []
        res.append({
            "id": ep.id,
            "url": ep.url,
            "method": ep.method,
            "status_code": ep.status_code,
            "content_type": ep.content_type,
            "response_time": ep.response_time,
            "parameters": params,
            "forms": forms,
            "created_at": ep.created_at
        })
    return res

@router.get("/{scan_id}/sitemap")
def get_recon_sitemap(scan_id: int, db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    if not endpoints:
        return {"name": "Root", "children": []}

    tree: Dict[str, Any] = {"name": "/", "path": "/", "children": []}

    for ep in endpoints:
        parsed = urllib.parse.urlparse(ep.url)
        path_segments = [seg for seg in parsed.path.split("/") if seg]
        
        current_level = tree["children"]
        current_path = ""
        for seg in path_segments:
            current_path += f"/{seg}"
            existing = next((item for item in current_level if item["name"] == seg), None)
            if not existing:
                new_node = {
                    "name": seg,
                    "path": current_path,
                    "url": ep.url if current_path == parsed.path else "",
                    "status_code": ep.status_code if current_path == parsed.path else 200,
                    "children": []
                }
                current_level.append(new_node)
                current_level = new_node["children"]
            else:
                current_level = existing["children"]

    return tree

@router.get("/{scan_id}/parameters")
def get_recon_parameters(scan_id: int, db: Session = Depends(get_db)):
    endpoints = db.query(Endpoint).filter(Endpoint.scan_id == scan_id).all()
    param_map: Dict[str, List[str]] = {}
    
    for ep in endpoints:
        try:
            params = json.loads(ep.parameters) if ep.parameters else []
            for p in params:
                if p not in param_map:
                    param_map[p] = []
                param_map[p].append(ep.url)
        except Exception:
            pass

    return [{"name": k, "endpoints": v, "count": len(v)} for k, v in param_map.items()]
