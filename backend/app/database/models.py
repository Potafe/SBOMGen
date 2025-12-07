from sqlalchemy import Column, String, Text, DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class ScanResultsDB(Base):
    __tablename__ = "scan_results"
    
    scan_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    repo_url = Column(String)
    tech_stack = Column(JSONB)
    trivy_sbom = Column(JSONB)
    syft_sbom = Column(JSONB) 
    cdxgen_sbom = Column(JSONB)
    ghas_sbom = Column(JSONB)
    bd_sbom = Column(JSONB)
    uploaded_sbom = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))
    
class UploadedScanResultsDB(Base):
    __tablename__ = "uploaded_scan_results"
    
    scan_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    filename = Column(String)
    original_format = Column(String)
    uploaded_sbom = Column(JSONB)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    completed_at = Column(DateTime(timezone=True))

class Package(Base):
    __tablename__ = "packages"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    scanner_name = Column(String, nullable=False, index=True)
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False, index=True)
    purl = Column(String)
    cpe = Column(String)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
