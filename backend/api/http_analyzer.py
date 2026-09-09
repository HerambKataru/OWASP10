import json
import base64
import time
import difflib
from typing import Dict, Any, List, Optional
import requests
from fastapi import APIRouter, Depends, HTTPException, Body
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import HTTPHistory
from models.schemas import HTTPRequestReplay

router = APIRouter(prefix="/api/http-analyzer", tags=["HTTP Analyzer"])

@router.get("/history")
def get_http_history(scan_id: Optional[int] = None, limit: int = 50, db: Session = Depends(get_db)):
    q = db.query(HTTPHistory)
    if scan_id:
        q = q.filter(HTTPHistory.scan_id == scan_id)
    history = q.order_by(HTTPHistory.id.desc()).limit(limit).all()
    
    res = []
    for h in history:
        try:
            req_h = json.loads(h.request_headers) if h.request_headers else {}
            res_h = json.loads(h.response_headers) if h.response_headers else {}
        except Exception:
            req_h, res_h = {}, {}
        res.append({
            "id": h.id,
            "scan_id": h.scan_id,
            "method": h.method,
            "url": h.url,
            "request_headers": req_h,
            "request_body": h.request_body,
            "response_status": h.response_status,
            "response_headers": res_h,
            "response_body": h.response_body,
            "response_time_ms": h.response_time_ms,
            "timestamp": h.timestamp
        })
    return res

@router.post("/replay")
def replay_request(req: HTTPRequestReplay, db: Session = Depends(get_db)):
    """Burp Repeater Engine: execute ad-hoc HTTP request and record in history"""
    try:
        start_time = time.time()
        res = requests.request(
            method=req.method.upper(),
            url=req.url,
            headers=req.headers,
            data=req.body.encode('utf-8') if req.body else None,
            timeout=15,
            verify=False,
            allow_redirects=True
        )
        elapsed_ms = round((time.time() - start_time) * 1000, 2)

        resp_headers_dict = dict(res.headers)
        
        # Save to history
        hist = HTTPHistory(
            method=req.method.upper(),
            url=req.url,
            request_headers=json.dumps(req.headers),
            request_body=req.body or "",
            response_status=res.status_code,
            response_headers=json.dumps(resp_headers_dict),
            response_body=res.text[:50000], # Cap at 50KB for DB
            response_time_ms=elapsed_ms
        )
        db.add(hist)
        db.commit()
        db.refresh(hist)

        return {
            "id": hist.id,
            "status_code": res.status_code,
            "status_text": res.reason,
            "headers": resp_headers_dict,
            "body": res.text,
            "elapsed_ms": elapsed_ms,
            "length": len(res.content)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Request failed: {str(e)}")

@router.post("/decode-jwt")
def decode_jwt(payload: Dict[str, str] = Body(...)):
    token = payload.get("token", "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Token is required")

    parts = token.split(".")
    if len(parts) < 2:
        raise HTTPException(status_code=400, detail="Invalid JWT structure (must have header.payload.signature)")

    def b64_decode(segment: str):
        # Add padding if needed
        rem = len(segment) % 4
        if rem > 0:
            segment += "=" * (4 - rem)
        try:
            return json.loads(base64.urlsafe_b64decode(segment.encode()).decode())
        except Exception as e:
            return {"error": f"Failed to parse segment: {str(e)}"}

    header = b64_decode(parts[0])
    claims = b64_decode(parts[1])
    signature = parts[2] if len(parts) > 2 else ""

    return {
        "header": header,
        "payload": claims,
        "signature": signature,
        "algorithm": header.get("alg", "Unknown") if isinstance(header, dict) else "Unknown",
        "expired": claims.get("exp", 0) < time.time() if isinstance(claims, dict) and "exp" in claims else None
    }

@router.post("/compare")
def compare_responses(payload: Dict[str, str] = Body(...)):
    body1 = payload.get("body1", "")
    body2 = payload.get("body2", "")
    
    diff = list(difflib.unified_diff(
        body1.splitlines(keepends=True),
        body2.splitlines(keepends=True),
        fromfile='Response A',
        tofile='Response B',
        n=3
    ))
    return {
        "diff_lines": diff,
        "diff_text": "".join(diff),
        "similarity_ratio": round(difflib.SequenceMatcher(None, body1, body2).ratio() * 100, 2)
    }
