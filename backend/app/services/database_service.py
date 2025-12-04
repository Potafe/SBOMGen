"""
Database service for SBOM operations
"""
import json
from datetime import datetime
from typing import Dict, Optional, List, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
import logging

from app.database import AsyncSessionLocal, ScanResultsDB, UploadedScanResultsDB
from app.schemas.scan import ScanResults, ScanStatus, SBOMResult, ScannerType, UploadedScanResults

logger = logging.getLogger(__name__)

class DatabaseService:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def save_scan_results(self, scan_results: ScanResults) -> bool:
        """Save scan results to database"""
        try:
            async with AsyncSessionLocal() as session:
                # Convert SBOMResult objects to JSON
                trivy_sbom_json = None
                if scan_results.trivy_sbom:
                    trivy_sbom_json = {
                        "scanner": scan_results.trivy_sbom.scanner.value,
                        "sbom": scan_results.trivy_sbom.sbom,
                        "component_count": scan_results.trivy_sbom.component_count,
                        "error": scan_results.trivy_sbom.error
                    }
                
                syft_sbom_json = None
                if scan_results.syft_sbom:
                    syft_sbom_json = {
                        "scanner": scan_results.syft_sbom.scanner.value,
                        "sbom": scan_results.syft_sbom.sbom,
                        "component_count": scan_results.syft_sbom.component_count,
                        "error": scan_results.syft_sbom.error
                    }
                
                cdxgen_sbom_json = None
                if scan_results.cdxgen_sbom:
                    cdxgen_sbom_json = {
                        "scanner": scan_results.cdxgen_sbom.scanner.value,
                        "sbom": scan_results.cdxgen_sbom.sbom,
                        "component_count": scan_results.cdxgen_sbom.component_count,
                        "error": scan_results.cdxgen_sbom.error
                    }
                
                uploaded_sbom_json = None
                if scan_results.uploaded_sbom:
                    uploaded_sbom_json = {
                        "scanner": scan_results.uploaded_sbom.scanner.value,
                        "sbom": scan_results.uploaded_sbom.sbom,
                        "component_count": scan_results.uploaded_sbom.component_count,
                        "error": scan_results.uploaded_sbom.error
                    }
                
                db_scan = ScanResultsDB(
                    scan_id=scan_results.scan_id,
                    status=scan_results.status.value,
                    repo_url=scan_results.repo_url,
                    tech_stack=scan_results.tech_stack,
                    trivy_sbom=trivy_sbom_json,
                    syft_sbom=syft_sbom_json,
                    cdxgen_sbom=cdxgen_sbom_json,
                    uploaded_sbom=uploaded_sbom_json,
                    created_at=scan_results.created_at,
                    completed_at=scan_results.completed_at
                )
                
                # Check if record exists first
                existing = await session.execute(
                    select(ScanResultsDB).where(ScanResultsDB.scan_id == scan_results.scan_id)
                )
                existing_scan = existing.scalar_one_or_none()
                
                if existing_scan:
                    # Update existing record
                    existing_scan.status = scan_results.status.value
                    existing_scan.repo_url = scan_results.repo_url
                    existing_scan.tech_stack = scan_results.tech_stack
                    existing_scan.trivy_sbom = trivy_sbom_json
                    existing_scan.syft_sbom = syft_sbom_json
                    existing_scan.cdxgen_sbom = cdxgen_sbom_json
                    existing_scan.uploaded_sbom = uploaded_sbom_json
                    existing_scan.completed_at = scan_results.completed_at
                else:
                    # Add new record
                    session.add(db_scan)
                
                await session.commit()
                logger.info(f"Successfully saved scan results for scan_id: {scan_results.scan_id}")
                return True
        except Exception as e:
            logger.error(f"Error saving scan results {scan_results.scan_id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    async def get_scan_results(self, scan_id: str) -> Optional[ScanResults]:
        """Get scan results from database"""
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(ScanResultsDB).where(ScanResultsDB.scan_id == scan_id)
                )
                db_scan = result.scalar_one_or_none()
                
                if not db_scan:
                    logger.info(f"No scan results found in database for scan_id: {scan_id}")
                    return None
                
                # Convert back to ScanResults object
                scan_results = ScanResults(
                    scan_id=db_scan.scan_id,
                    status=ScanStatus(db_scan.status),
                    repo_url=db_scan.repo_url,
                    tech_stack=db_scan.tech_stack,
                    created_at=db_scan.created_at,
                    completed_at=db_scan.completed_at
                )
                
                # Convert JSON back to SBOMResult objects
                if db_scan.trivy_sbom:
                    scan_results.trivy_sbom = SBOMResult(
                        scanner=ScannerType(db_scan.trivy_sbom["scanner"]),
                        sbom=db_scan.trivy_sbom["sbom"],
                        component_count=db_scan.trivy_sbom["component_count"],
                        error=db_scan.trivy_sbom["error"]
                    )
                
                if db_scan.syft_sbom:
                    scan_results.syft_sbom = SBOMResult(
                        scanner=ScannerType(db_scan.syft_sbom["scanner"]),
                        sbom=db_scan.syft_sbom["sbom"],
                        component_count=db_scan.syft_sbom["component_count"],
                        error=db_scan.syft_sbom["error"]
                    )
                
                if db_scan.cdxgen_sbom:
                    scan_results.cdxgen_sbom = SBOMResult(
                        scanner=ScannerType(db_scan.cdxgen_sbom["scanner"]),
                        sbom=db_scan.cdxgen_sbom["sbom"],
                        component_count=db_scan.cdxgen_sbom["component_count"],
                        error=db_scan.cdxgen_sbom["error"]
                    )
                
                if db_scan.uploaded_sbom:
                    scan_results.uploaded_sbom = SBOMResult(
                        scanner=ScannerType(db_scan.uploaded_sbom["scanner"]),
                        sbom=db_scan.uploaded_sbom["sbom"],
                        component_count=db_scan.uploaded_sbom["component_count"],
                        error=db_scan.uploaded_sbom["error"]
                    )
                
                return scan_results
        except Exception as e:
            logger.error(f"Error getting scan results {scan_id}: {e}")
            return None
    
    async def save_uploaded_scan_results(self, uploaded_scan: UploadedScanResults) -> bool:
        """Save uploaded scan results to database"""
        try:
            async with AsyncSessionLocal() as session:
                uploaded_sbom_json = None
                if uploaded_scan.uploaded_sbom:
                    uploaded_sbom_json = {
                        "scanner": uploaded_scan.uploaded_sbom.scanner.value,
                        "sbom": uploaded_scan.uploaded_sbom.sbom,
                        "component_count": uploaded_scan.uploaded_sbom.component_count,
                        "error": uploaded_scan.uploaded_sbom.error
                    }
                
                db_uploaded = UploadedScanResultsDB(
                    scan_id=uploaded_scan.scan_id,
                    status=uploaded_scan.status.value,
                    filename=uploaded_scan.filename,
                    original_format=uploaded_scan.original_format,
                    uploaded_sbom=uploaded_sbom_json,
                    created_at=uploaded_scan.created_at,
                    completed_at=uploaded_scan.completed_at
                )
                
                # Check if record exists first
                existing = await session.execute(
                    select(UploadedScanResultsDB).where(UploadedScanResultsDB.scan_id == uploaded_scan.scan_id)
                )
                existing_upload = existing.scalar_one_or_none()
                
                if existing_upload:
                    # Update existing record
                    existing_upload.status = uploaded_scan.status.value
                    existing_upload.filename = uploaded_scan.filename
                    existing_upload.original_format = uploaded_scan.original_format
                    existing_upload.uploaded_sbom = uploaded_sbom_json
                    existing_upload.completed_at = uploaded_scan.completed_at
                else:
                    # Add new record
                    session.add(db_uploaded)
                
                await session.commit()
                return True
        except Exception as e:
            logger.error(f"Error saving uploaded scan results {uploaded_scan.scan_id}: {e}")
            return False
    
    async def get_uploaded_scan_results(self, scan_id: str) -> Optional[UploadedScanResults]:
        """Get uploaded scan results from database"""
        try:
            async with AsyncSessionLocal() as session:
                result = await session.execute(
                    select(UploadedScanResultsDB).where(UploadedScanResultsDB.scan_id == scan_id)
                )
                db_uploaded = result.scalar_one_or_none()
                
                if not db_uploaded:
                    return None
                
                # Convert back to UploadedScanResults object
                uploaded_scan = UploadedScanResults(
                    scan_id=db_uploaded.scan_id,
                    status=ScanStatus(db_uploaded.status),
                    filename=db_uploaded.filename,
                    original_format=db_uploaded.original_format,
                    created_at=db_uploaded.created_at,
                    completed_at=db_uploaded.completed_at
                )
                
                # Convert JSON back to SBOMResult object
                if db_uploaded.uploaded_sbom:
                    uploaded_scan.uploaded_sbom = SBOMResult(
                        scanner=ScannerType(db_uploaded.uploaded_sbom["scanner"]),
                        sbom=db_uploaded.uploaded_sbom["sbom"],
                        component_count=db_uploaded.uploaded_sbom["component_count"],
                        error=db_uploaded.uploaded_sbom["error"]
                    )
                
                return uploaded_scan
        except Exception as e:
            logger.error(f"Error getting uploaded scan results {scan_id}: {e}")
            return None

# Global database service instance
db_service = DatabaseService()