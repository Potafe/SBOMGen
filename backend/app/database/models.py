from sqlalchemy import Column, String, Text, DateTime, Integer, ForeignKey, Index
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
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
    merged_sbom = Column(JSONB)
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
    
    # Internal reference for merge - original BOM-REF or SPDXID
    original_ref = Column(String, nullable=False, index=True)
    
    # Core identification fields
    name = Column(String, nullable=False, index=True)
    version = Column(String, nullable=False, index=True)
    purl = Column(String, index=True)
    cpe = Column(String)
    
    # Additional CycloneDX metadata
    licenses = Column(Text)  # Store as JSON string
    component_type = Column(String, default="library")
    description = Column(Text)
    
    # Match status for merge logic
    match_status = Column(String, nullable=False, index=True, default="unique")
    
    # Relationships
    dependencies = relationship("Dependency", foreign_keys='Dependency.parent_id', back_populates="parent")
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())


class Dependency(Base):
    __tablename__ = "dependencies"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    scan_id = Column(String, nullable=False, index=True)
    scanner_name = Column(String, nullable=False, index=True)
    
    # Parent package (the one that depends)
    parent_id = Column(Integer, ForeignKey("packages.id"), nullable=False, index=True)
    # Child package (the dependency)
    child_id = Column(Integer, ForeignKey("packages.id"), nullable=False, index=True)
    
    # Relationship type
    original_type = Column(String, nullable=False)
    normalized_type = Column(String, nullable=False, index=True)
    
    # Relationships
    parent = relationship("Package", foreign_keys=[parent_id], back_populates="dependencies")
    child = relationship("Package", foreign_keys=[child_id])
    
    # Indexes for fast lookups
    __table_args__ = (
        Index('idx_dep_parent_child_type', "parent_id", "child_id", "normalized_type"),
    )
    
    created_at = Column(DateTime(timezone=True), server_default=func.now())
