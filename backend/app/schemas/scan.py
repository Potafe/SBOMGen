from pydantic import BaseModel, HttpUrl
from typing import Optional, Dict, Any, List
from enum import Enum
from datetime import datetime

class ScanStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in-progress"
    COMPLETED = "completed"
    FAILED = "failed"

class ScannerType(str, Enum):
    TRIVY = "trivy"
    SYFT = "syft"
    CDXGEN = "cdxgen"
    BLACKDUCK = "blackduck"
    GHAS = "ghas"
    UPLOADED = "uploaded"

class RepositoryUpload(BaseModel):
    repo_url: HttpUrl
    github_token: Optional[str] = None  # for pvt repos
    bd_project_name: Optional[str] = None
    bd_project_version: Optional[str] = None
    bd_api_token: Optional[str] = None
    uploaded_sbom_format: Optional[str] = None  # 'spdx' or 'cyclonedx'

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class SBOMResult(BaseModel):
    scanner: ScannerType
    sbom: Optional[Dict[Any, Any]] = None
    component_count: int = 0
    error: Optional[str] = None
    rerun: bool = False

class ScanResults(BaseModel):
    scan_id: str
    status: ScanStatus
    repo_url: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    trivy_sbom: Optional[SBOMResult] = None
    syft_sbom: Optional[SBOMResult] = None
    cdxgen_sbom: Optional[SBOMResult] = None
    ghas_sbom: Optional[SBOMResult] = None
    bd_sbom: Optional[SBOMResult] = None
    tech_stack: Optional[List[str]] = None
    uploaded_sbom: Optional[SBOMResult] = None
    cached_analysis: Optional[Dict[str, Any]] = None

class RerunRequest(BaseModel):
    scan_id: str
    scanner: ScannerType
    commands: Optional[List[str]] = None

class SBOMFormat(str, Enum):
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"

class SBOMUploadResponse(BaseModel):
    scan_id: str
    status: str
    message: str
    format: str
    component_count: int

class UploadedScanResults(BaseModel):
    scan_id: str
    status: ScanStatus
    filename: str
    original_format: str
    created_at: datetime
    completed_at: Optional[datetime] = None
    uploaded_sbom: Optional[SBOMResult] = None