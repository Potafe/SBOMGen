"""
Database models for SBOM storage
"""
from sqlalchemy import Column, String, Text, DateTime, Integer, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.sql import func
from datetime import datetime

Base = declarative_base()

class ScanResultsDB(Base):
    __tablename__ = "scan_results"
    
    scan_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    repo_url = Column(String)
    tech_stack = Column(JSON)
    trivy_sbom = Column(JSON)
    syft_sbom = Column(JSON) 
    cdxgen_sbom = Column(JSON)
    uploaded_sbom = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime)
    
class UploadedScanResultsDB(Base):
    __tablename__ = "uploaded_scan_results"
    
    scan_id = Column(String, primary_key=True)
    status = Column(String, nullable=False)
    filename = Column(String)
    original_format = Column(String)
    uploaded_sbom = Column(JSON)
    created_at = Column(DateTime, default=func.now())
    completed_at = Column(DateTime)