from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from database.session import get_db
from database.models import AppSetting
from config import (
    DEFAULT_VIRUSTOTAL_KEY, DEFAULT_ABUSEIPDB_KEY, DEFAULT_SHODAN_KEY,
    simple_decrypt
)
from intelligence.virustotal import VirusTotalClient
from intelligence.abuseipdb import AbuseIPDBClient
from intelligence.shodan import ShodanClient
from intelligence.cve import CVEClient
from intelligence.whois_dns import get_dns_and_whois_info

router = APIRouter(prefix="/api/intelligence", tags=["Threat Intelligence"])

def get_key_from_db_or_env(key_name: str, default_env: str, db: Session) -> str:
    setting = db.query(AppSetting).filter(AppSetting.key == key_name).first()
    if setting and setting.value:
        dec = simple_decrypt(setting.value)
        if dec: return dec
    return default_env

@router.get("/virustotal/domain")
def query_virustotal_domain(domain: str, db: Session = Depends(get_db)):
    key = get_key_from_db_or_env("virustotal_key", DEFAULT_VIRUSTOTAL_KEY, db)
    client = VirusTotalClient(api_key=key)
    return client.scan_domain(domain)

@router.get("/virustotal/url")
def query_virustotal_url(target_url: str, db: Session = Depends(get_db)):
    key = get_key_from_db_or_env("virustotal_key", DEFAULT_VIRUSTOTAL_KEY, db)
    client = VirusTotalClient(api_key=key)
    return client.scan_url(target_url)

@router.get("/virustotal/hash")
def query_virustotal_hash(file_hash: str, db: Session = Depends(get_db)):
    key = get_key_from_db_or_env("virustotal_key", DEFAULT_VIRUSTOTAL_KEY, db)
    client = VirusTotalClient(api_key=key)
    return client.lookup_hash(file_hash)

@router.get("/abuseipdb")
def query_abuseipdb(ip: str, db: Session = Depends(get_db)):
    key = get_key_from_db_or_env("abuseipdb_key", DEFAULT_ABUSEIPDB_KEY, db)
    client = AbuseIPDBClient(api_key=key)
    return client.check_ip(ip)

@router.get("/shodan")
def query_shodan(ip: str, db: Session = Depends(get_db)):
    key = get_key_from_db_or_env("shodan_key", DEFAULT_SHODAN_KEY, db)
    client = ShodanClient(api_key=key)
    return client.host_info(ip)

@router.get("/cve")
def query_cve(keyword: str = Query("apache")):
    client = CVEClient()
    return client.search_cves(keyword)

@router.get("/whois-dns")
def query_whois_dns(target: str):
    return get_dns_and_whois_info(target)
