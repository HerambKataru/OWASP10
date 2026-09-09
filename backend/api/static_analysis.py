import os
import shutil
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import Scan, Finding
from config import UPLOADS_DIR
from scanners.static import extract_and_analyze_zip
from services.risk_engine import RiskEngine

router = APIRouter(prefix="/api/static-analysis", tags=["Static Source Code Analysis"])

@router.post("/upload")
async def upload_and_analyze_project(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="Only .zip project archives are supported")

    timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    zip_path = UPLOADS_DIR / f"{timestamp_str}_{file.filename}"
    extract_dir = UPLOADS_DIR / f"extracted_{timestamp_str}"

    try:
        with open(zip_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        # Run SAST
        results = extract_and_analyze_zip(str(zip_path), str(extract_dir))
        findings = results.get("findings", [])
        stats = RiskEngine.get_summary_stats(findings)

        # Create Scan record in DB
        scan = Scan(
            target=file.filename,
            scan_type="project",
            status="completed",
            risk_score=stats["risk_score"],
            critical_count=stats["critical_count"],
            high_count=stats["high_count"],
            medium_count=stats["medium_count"],
            low_count=stats["low_count"],
            info_count=stats["info_count"],
            endpoints_count=results.get("total_files", 0),
            forms_count=results.get("scanned_lines", 0),
            technologies="[\"Source Code SAST\"]",
            completed_at=datetime.utcnow()
        )
        db.add(scan)
        db.commit()
        db.refresh(scan)

        # Save findings
        for f in findings:
            finding_row = Finding(
                scan_id=scan.id,
                category="static",
                owasp_category=f.get("owasp_category", "A06:2021-Vulnerable and Outdated Components"),
                severity=f.get("severity", "Medium"),
                title=f.get("title", ""),
                description=f.get("description", ""),
                endpoint=f.get("endpoint", ""),
                parameter="Source Code",
                payload=f.get("payload", ""),
                evidence=f.get("evidence", ""),
                cvss_score=f.get("cvss_score", 5.0),
                cve_id=f.get("cve_id", "CWE-95"),
                remediation=f.get("remediation", ""),
                file_path=f.get("file_path", ""),
                line_number=f.get("line_number")
            )
            db.add(finding_row)
        db.commit()

        return {
            "scan_id": scan.id,
            "filename": file.filename,
            "total_files": results.get("total_files"),
            "scanned_lines": results.get("scanned_lines"),
            "risk_score": scan.risk_score,
            "findings_count": len(findings),
            "file_tree": results.get("file_tree"),
            "findings": findings
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"SAST analysis failed: {str(e)}")
    finally:
        # Cleanup zip file
        if os.path.exists(zip_path):
            try:
                os.remove(zip_path)
            except Exception:
                pass
