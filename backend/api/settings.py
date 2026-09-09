from typing import Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import AppSetting
from config import simple_encrypt, simple_decrypt
from models.schemas import SettingUpdateRequest

router = APIRouter(prefix="/api/settings", tags=["Settings"])

SUPPORTED_KEYS = [
    {"key": "virustotal_key", "name": "VirusTotal API Key", "desc": "Used for domain reputation, URL scans, and file hash threat analysis."},
    {"key": "abuseipdb_key", "name": "AbuseIPDB API Key", "desc": "Used for IP reputation scoring and malicious host detection."},
    {"key": "shodan_key", "name": "Shodan API Key", "desc": "Used for passive infrastructure recon, port scanning, and banner discovery."}
]

@router.get("")
def get_all_settings(db: Session = Depends(get_db)):
    results = []
    for item in SUPPORTED_KEYS:
        setting = db.query(AppSetting).filter(AppSetting.key == item["key"]).first()
        is_configured = bool(setting and setting.value)
        masked_val = ""
        if is_configured:
            dec = simple_decrypt(setting.value)
            if len(dec) > 8:
                masked_val = dec[:4] + "••••••••" + dec[-4:]
            else:
                masked_val = "••••••••"

        results.append({
            "key": item["key"],
            "name": item["name"],
            "description": item["desc"],
            "is_configured": is_configured,
            "masked_value": masked_val
        })
    return results

@router.post("/update")
def update_setting(req: SettingUpdateRequest, db: Session = Depends(get_db)):
    setting = db.query(AppSetting).filter(AppSetting.key == req.key).first()
    encrypted_val = simple_encrypt(req.value.strip())
    
    if not setting:
        setting = AppSetting(
            key=req.key,
            value=encrypted_val,
            description=req.description or ""
        )
        db.add(setting)
    else:
        setting.value = encrypted_val
        if req.description:
            setting.description = req.description
            
    db.commit()
    return {"success": True, "message": f"Updated setting '{req.key}' securely."}

@router.post("/delete/{key_name}")
def delete_setting(key_name: str, db: Session = Depends(get_db)):
    setting = db.query(AppSetting).filter(AppSetting.key == key_name).first()
    if setting:
        setting.value = ""
        db.commit()
    return {"success": True, "message": f"Removed key '{key_name}'."}
