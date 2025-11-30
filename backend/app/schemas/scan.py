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

class RepositoryUpload(BaseModel):
    repo_url: HttpUrl
    github_token: Optional[str] = None  # for pvt repos

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
    tech_stack: Optional[List[str]] = None

class RerunRequest(BaseModel):
    scan_id: str
    scanner: ScannerType
    commands: Optional[List[str]] = None