from datetime import datetime
from sqlalchemy import Column, Integer, String, Text, Float, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import relationship
from database.session import Base

class Scan(Base):
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    target = Column(String(500), nullable=False)
    scan_type = Column(String(50), default="website") # website | project
    status = Column(String(50), default="pending") # pending | running | completed | failed
    crawl_depth = Column(Integer, default=2)
    threads = Column(Integer, default=5)
    timeout = Column(Integer, default=10)
    user_agent = Column(String(255), default="SentinelX-VAPT-Agent/1.0")
    
    # Risk Metrics
    risk_score = Column(Float, default=0.0) # 0 to 100
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    info_count = Column(Integer, default=0)
    endpoints_count = Column(Integer, default=0)
    forms_count = Column(Integer, default=0)
    
    # Metadata in JSON text
    technologies = Column(Text, default="[]")
    recon_data = Column(Text, default="{}")
    threat_intel = Column(Text, default="{}")
    
    created_at = Column(DateTime, default=datetime.utcnow)
    completed_at = Column(DateTime, nullable=True)

    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    endpoints = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    http_history = relationship("HTTPHistory", back_populates="scan", cascade="all, delete-orphan")

class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    category = Column(String(100), nullable=False) # sqli, xss, idor, auth, upload, headers, exposure, static
    owasp_category = Column(String(100), default="A01:2025-Broken Access Control")
    severity = Column(String(20), default="Medium") # Critical, High, Medium, Low, Informational
    title = Column(String(255), nullable=False)
    description = Column(Text, default="")
    endpoint = Column(String(500), default="")
    parameter = Column(String(100), default="")
    payload = Column(Text, default="")
    evidence = Column(Text, default="")
    cvss_score = Column(Float, default=5.0)
    cve_id = Column(String(50), default="")
    remediation = Column(Text, default="")
    file_path = Column(String(500), default="") # For SAST
    line_number = Column(Integer, nullable=True) # For SAST
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="findings")

class Endpoint(Base):
    __tablename__ = "endpoints"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=False)
    url = Column(String(500), nullable=False)
    method = Column(String(10), default="GET")
    status_code = Column(Integer, default=200)
    content_type = Column(String(100), default="text/html")
    response_time = Column(Float, default=0.0)
    parameters = Column(Text, default="[]") # JSON list of query/post params
    forms = Column(Text, default="[]") # JSON list of forms
    created_at = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="endpoints")

class HTTPHistory(Base):
    __tablename__ = "http_history"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scans.id"), nullable=True)
    method = Column(String(10), default="GET")
    url = Column(String(500), nullable=False)
    request_headers = Column(Text, default="{}")
    request_body = Column(Text, default="")
    response_status = Column(Integer, default=200)
    response_headers = Column(Text, default="{}")
    response_body = Column(Text, default="")
    response_time_ms = Column(Float, default=0.0)
    timestamp = Column(DateTime, default=datetime.utcnow)

    scan = relationship("Scan", back_populates="http_history")

class AppSetting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, index=True, nullable=False)
    value = Column(Text, default="")
    description = Column(String(255), default="")
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
