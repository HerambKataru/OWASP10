from typing import List, Optional, Dict, Any
from pydantic import BaseModel, HttpUrl
from datetime import datetime

class ScanCreateRequest(BaseModel):
    target: str
    scan_type: str = "website" # website | project
    crawl_depth: int = 2
    threads: int = 5
    timeout: int = 10
    user_agent: str = "SentinelX-VAPT-Agent/1.0"
    selected_scanners: Optional[List[str]] = [
        "recon", "sqli", "xss", "idor", "auth", "upload", "headers", "exposure"
    ]

class FindingResponse(BaseModel):
    id: int
    scan_id: int
    category: str
    owasp_category: str
    severity: str
    title: str
    description: str
    endpoint: str
    parameter: Optional[str] = ""
    payload: Optional[str] = ""
    evidence: Optional[str] = ""
    cvss_score: float
    cve_id: Optional[str] = ""
    remediation: Optional[str] = ""
    file_path: Optional[str] = ""
    line_number: Optional[int] = None
    created_at: datetime

    class Config:
        from_attributes = True

class EndpointResponse(BaseModel):
    id: int
    scan_id: int
    url: str
    method: str
    status_code: int
    content_type: str
    response_time: float
    parameters: Any
    forms: Any
    created_at: datetime

    class Config:
        from_attributes = True

class ScanResponse(BaseModel):
    id: int
    target: str
    scan_type: str
    status: str
    crawl_depth: int
    threads: int
    timeout: int
    risk_score: float
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    endpoints_count: int
    forms_count: int
    technologies: Any
    created_at: datetime
    completed_at: Optional[datetime] = None

    class Config:
        from_attributes = True

class HTTPRequestReplay(BaseModel):
    method: str = "GET"
    url: str
    headers: Dict[str, str] = {}
    body: Optional[str] = ""

class SettingUpdateRequest(BaseModel):
    key: str
    value: str
    description: Optional[str] = ""
