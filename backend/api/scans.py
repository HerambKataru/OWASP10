import asyncio
import json
from typing import List
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Scan, Finding, Endpoint
from models.schemas import ScanCreateRequest, ScanResponse, FindingResponse
from services.scan_manager import ScanManager

router = APIRouter(prefix="/api/scans", tags=["Scans"])

@router.get("", response_model=List[ScanResponse])
def get_all_scans(db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(Scan.id.desc()).all()
    res = []
    for s in scans:
        try:
            techs = json.loads(s.technologies) if s.technologies else []
        except Exception:
            techs = []
        res.append(ScanResponse(
            id=s.id,
            target=s.target,
            scan_type=s.scan_type,
            status=s.status,
            crawl_depth=s.crawl_depth,
            threads=s.threads,
            timeout=s.timeout,
            risk_score=s.risk_score,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            info_count=s.info_count,
            endpoints_count=s.endpoints_count,
            forms_count=s.forms_count,
            technologies=techs,
            created_at=s.created_at,
            completed_at=s.completed_at
        ))
    return res

@router.post("", response_model=ScanResponse)
def create_scan(req: ScanCreateRequest, background_tasks: BackgroundTasks, db: Session = Depends(get_db)):
    scan = Scan(
        target=req.target,
        scan_type=req.scan_type,
        crawl_depth=req.crawl_depth,
        threads=req.threads,
        timeout=req.timeout,
        user_agent=req.user_agent,
        status="pending"
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Launch background scan asynchronously
    if req.scan_type == "website":
        background_tasks.add_task(asyncio.run, ScanManager.execute_website_scan(scan.id))

    return ScanResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        crawl_depth=scan.crawl_depth,
        threads=scan.threads,
        timeout=scan.timeout,
        risk_score=scan.risk_score,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        endpoints_count=scan.endpoints_count,
        forms_count=scan.forms_count,
        technologies=[],
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )

@router.get("/{scan_id}", response_model=ScanResponse)
def get_scan_by_id(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        techs = json.loads(scan.technologies) if scan.technologies else []
    except Exception:
        techs = []
    return ScanResponse(
        id=scan.id,
        target=scan.target,
        scan_type=scan.scan_type,
        status=scan.status,
        crawl_depth=scan.crawl_depth,
        threads=scan.threads,
        timeout=scan.timeout,
        risk_score=scan.risk_score,
        critical_count=scan.critical_count,
        high_count=scan.high_count,
        medium_count=scan.medium_count,
        low_count=scan.low_count,
        info_count=scan.info_count,
        endpoints_count=scan.endpoints_count,
        forms_count=scan.forms_count,
        technologies=techs,
        created_at=scan.created_at,
        completed_at=scan.completed_at
    )

@router.get("/{scan_id}/findings", response_model=List[FindingResponse])
def get_scan_findings(scan_id: int, category: str = None, severity: str = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.scan_id == scan_id)
    if category:
        q = q.filter(Finding.category == category)
    if severity:
        q = q.filter(Finding.severity == severity)
    return q.order_by(Finding.id.desc()).all()

@router.get("/{scan_id}/ai-advisor")
def get_scan_ai_advisor(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    try:
        if scan.threat_intel:
            return json.loads(scan.threat_intel)
    except Exception:
        pass
    return {"message": "AI analysis generating or not available"}

@router.delete("/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted successfully"}
