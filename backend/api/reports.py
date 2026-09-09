import json
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import FileResponse, Response
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Scan, Finding
from config import REPORTS_DIR
from reports.pdf_generator import generate_pdf_report

router = APIRouter(prefix="/api/reports", tags=["Reports"])

@router.get("/pdf/{scan_id}")
def export_pdf_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()
    
    scan_dict = {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "risk_score": scan.risk_score,
        "crawl_depth": scan.crawl_depth,
        "endpoints_count": scan.endpoints_count,
        "forms_count": scan.forms_count,
        "created_at": scan.created_at.strftime("%Y-%m-%d %H:%M:%S") if scan.created_at else "",
        "technologies": json.loads(scan.technologies) if scan.technologies else []
    }

    findings_list = [
        {
            "id": f.id,
            "category": f.category,
            "owasp_category": f.owasp_category,
            "severity": f.severity,
            "title": f.title,
            "description": f.description,
            "endpoint": f.endpoint,
            "parameter": f.parameter,
            "payload": f.payload,
            "evidence": f.evidence,
            "cvss_score": f.cvss_score,
            "cve_id": f.cve_id,
            "remediation": f.remediation,
            "file_path": f.file_path,
            "line_number": f.line_number
        }
        for f in findings
    ]

    pdf_filename = f"SentinelX_Report_Scan_{scan_id}.pdf"
    pdf_path = REPORTS_DIR / pdf_filename

    generate_pdf_report(scan_dict, findings_list, str(pdf_path))

    return FileResponse(
        path=str(pdf_path),
        filename=pdf_filename,
        media_type="application/pdf"
    )

@router.get("/json/{scan_id}")
def export_json_report(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    findings = db.query(Finding).filter(Finding.scan_id == scan_id).all()

    report_payload = {
        "sentinelx_version": "1.0",
        "generated_at": scan.completed_at.isoformat() if scan.completed_at else "",
        "scan": {
            "id": scan.id,
            "target": scan.target,
            "scan_type": scan.scan_type,
            "risk_score": scan.risk_score,
            "status": scan.status,
            "endpoints_count": scan.endpoints_count,
            "forms_count": scan.forms_count,
            "technologies": json.loads(scan.technologies) if scan.technologies else []
        },
        "findings_count": len(findings),
        "findings": [
            {
                "id": f.id,
                "category": f.category,
                "owasp_category": f.owasp_category,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "endpoint": f.endpoint,
                "parameter": f.parameter,
                "payload": f.payload,
                "evidence": f.evidence,
                "cvss_score": f.cvss_score,
                "cve_id": f.cve_id,
                "remediation": f.remediation,
                "file_path": f.file_path,
                "line_number": f.line_number
            }
            for f in findings
        ]
    }

    return Response(
        content=json.dumps(report_payload, indent=2),
        media_type="application/json",
        headers={"Content-Disposition": f"attachment; filename=SentinelX_Scan_{scan_id}.json"}
    )
