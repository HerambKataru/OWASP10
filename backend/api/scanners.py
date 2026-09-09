from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Finding
from models.schemas import FindingResponse

router = APIRouter(prefix="/api/scanners", tags=["Dedicated Scanners"])

@router.get("/sqli", response_model=List[FindingResponse])
def get_sqli_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "sqli")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/xss", response_model=List[FindingResponse])
def get_xss_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "xss")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/idor", response_model=List[FindingResponse])
def get_idor_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "idor")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/auth", response_model=List[FindingResponse])
def get_auth_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "auth")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/upload", response_model=List[FindingResponse])
def get_upload_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "upload")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/headers", response_model=List[FindingResponse])
def get_headers_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "headers")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()

@router.get("/exposure", response_model=List[FindingResponse])
def get_exposure_findings(scan_id: Optional[int] = None, db: Session = Depends(get_db)):
    q = db.query(Finding).filter(Finding.category == "exposure")
    if scan_id:
        q = q.filter(Finding.scan_id == scan_id)
    return q.order_by(Finding.id.desc()).all()
