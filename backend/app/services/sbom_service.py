import os
import json
import asyncio
import subprocess
import docker
import uuid
import logging
import tempfile

from typing import Dict, Optional, List, Any, Tuple
from datetime import datetime
from git import Repo

from app.schemas.scan import (
    ScanResults, ScanStatus, 
    SBOMResult, ScannerType,
    UploadedScanResults
)
from app.core.config import settings
from app.utils.tech_stack import detect_tech_stack
from app.services.package_analyze import PackageAnalyze
from app.services.github_service import GithubService
from app.services.database_service import db_service

logger = logging.getLogger(__name__)

class SBOMService:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.package_analyzer = PackageAnalyze()
        self.github_service = GithubService()

    async def start_scan(self, repo_url: str, github_token: Optional[str] = None) -> str:
        scan_id = str(uuid.uuid4())
        logger.info(f"Starting scan for repo: {repo_url}, scan_id: {scan_id}")
        scan = ScanResults(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            repo_url=str(repo_url),
            created_at=datetime.now(),
            tech_stack=detect_tech_stack(str(repo_url), github_token)
        )
        await db_service.save_scan_results(scan)
        return scan_id
    
    async def run_scan(self, scan_id: str, github_token: Optional[str] = None):
        scan = await db_service.get_scan_results(scan_id)
        if not scan:
            return

        logger.info(f"Running scan {scan_id} for repo {scan.repo_url}")
        scan.status = ScanStatus.IN_PROGRESS
        try:
            logger.info(f"Cloning repo {scan.repo_url} for scan {scan_id}")
            repo_path = os.path.join(settings.TEMP_DIR, scan_id)
            os.makedirs(repo_path, exist_ok=True)
            
            if github_token:
                auth_url = scan.repo_url.replace('https://', f'https://{github_token}@')
                logger.info(f"Using authenticated URL for cloning")
                Repo.clone_from(auth_url, repo_path)
            else:
                Repo.clone_from(scan.repo_url, repo_path)

            logger.info(f"Running scanners for scan {scan_id}")
            trivy_result = await self._run_scanner(scan_id, ScannerType.TRIVY, repo_path)
            syft_result = await self._run_scanner(scan_id, ScannerType.SYFT, repo_path)
            cdxgen_result = await self._run_scanner(scan_id, ScannerType.CDXGEN, repo_path)
            ghas_result = await self._run_scanner(scan_id, ScannerType.GHAS, repo_path, github_token, scan.repo_url)

            scan.trivy_sbom = trivy_result
            scan.syft_sbom = syft_result
            scan.cdxgen_sbom = cdxgen_result
            scan.ghas_sbom = ghas_result
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            logger.info(f"Scan {scan_id} completed successfully")
            
            # Save updated scan results
            await db_service.save_scan_results(scan)
            
            # Extract and save packages for each scanner immediately
            logger.info(f"Extracting and saving packages for scan {scan_id}")
            if trivy_result and trivy_result.sbom:
                trivy_packages = self.package_analyzer.extract_packages(trivy_result.sbom, ScannerType.TRIVY)
                await db_service.save_packages(scan_id, ScannerType.TRIVY.value, trivy_packages)
            
            if syft_result and syft_result.sbom:
                syft_packages = self.package_analyzer.extract_packages(syft_result.sbom, ScannerType.SYFT)
                await db_service.save_packages(scan_id, ScannerType.SYFT.value, syft_packages)
            
            if cdxgen_result and cdxgen_result.sbom:
                cdxgen_packages = self.package_analyzer.extract_packages(cdxgen_result.sbom, ScannerType.CDXGEN)
                await db_service.save_packages(scan_id, ScannerType.CDXGEN.value, cdxgen_packages)

            if ghas_result and ghas_result.sbom:
                ghas_packages = self.package_analyzer.extract_spdx_packages(ghas_result.sbom, ScannerType.GHAS)
                await db_service.save_packages(scan_id, ScannerType.GHAS.value, ghas_packages)

            # await self._handle_reruns(scan_id)
        except Exception as e:
            scan.status = ScanStatus.FAILED
            await db_service.save_scan_results(scan)
            logger.error(f"Scan {scan_id} failed: {e}")
            print(f"Scan failed: {e}")

    async def _run_scanner(
        self, 
        scan_id: str, 
        scanner: ScannerType, 
        repo_path: str = None,
        github_token: Optional[str] = None,
        repo_url: Optional[str] = None
    ) -> SBOMResult:
        logger.info(f"Running {scanner.value} for scan {scan_id}")
        try:
            if scanner == ScannerType.TRIVY:
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_file_path = temp_file.name
                
                result = subprocess.run(
                    ["trivy", "fs", "--format", "cyclonedx", "--output", temp_file_path, repo_path],
                    capture_output=True, text=True, timeout=settings.TRIVY_TIMEOUT
                )
                if result.returncode == 0:
                    with open(temp_file_path, 'r') as f:
                        sbom_data = json.load(f)
                    component_count = len(sbom_data.get("components", []))
                else:
                    raise Exception(f"Trivy failed: {result.stderr}")
                
                os.unlink(temp_file_path)
                    
            elif scanner == ScannerType.SYFT:
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_file_path = temp_file.name
                
                result = subprocess.run(
                    ["/usr/local/bin/syft", repo_path, "--output", f"cyclonedx-json={temp_file_path}"],
                    capture_output=True, text=True, timeout=settings.SYFT_TIMEOUT
                )
                if result.returncode == 0:
                    with open(temp_file_path, 'r') as f:
                        sbom_data = json.load(f)
                    component_count = len(sbom_data.get("components", []))
                else:
                    raise Exception(f"Syft failed: {result.stderr}")
                
                os.unlink(temp_file_path)
                    
            elif scanner == ScannerType.CDXGEN:
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_file_path = temp_file.name

                result = subprocess.run(
                    ["cdxgen", "-o", temp_file_path, "-r", repo_path],
                    capture_output=True, text=True, timeout=settings.CDXGEN_TIMEOUT
                )
                if result.returncode == 0:
                    with open(temp_file_path, 'r') as f:
                        sbom_data = json.load(f)
                    component_count = len(sbom_data.get("components", []))
                else:
                    raise Exception(f"CDXGen failed: {result.stderr}")
                
                os.unlink(temp_file_path)

            elif scanner == ScannerType.GHAS:
                if not repo_url:
                    raise Exception("repo_url is required for GHAS scanner")
                
                # Fetch SBOM from GitHub API
                sbom_data = await self.github_service.fetch_dependency_graph_sbom(
                    repo_url=repo_url,
                    github_token=github_token
                )
                
                # GitHub returns SPDX format with nested sbom structure
                if "sbom" in sbom_data:
                    actual_sbom = sbom_data["sbom"]
                else:
                    actual_sbom = sbom_data
                
                # Save to temp file for consistency with other scanners
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_file_path = temp_file.name
                    json.dump(actual_sbom, temp_file, indent=2)
                
                # Verify file was written correctly
                with open(temp_file_path, 'r') as f:
                    sbom_data = json.load(f)
                
                component_count = len(sbom_data.get("packages", []))
                
                # Clean up temp file
                os.unlink(temp_file_path)
            else:
                raise Exception(f"Unknown scanner type: {scanner.value}")

            logger.info(f"{scanner.value} for scan {scan_id} found {component_count} components")
            return SBOMResult(scanner=scanner, sbom=sbom_data, component_count=component_count)
            
        except Exception as e:
            logger.error(f"{scanner.value} for scan {scan_id} failed: {e}")
            return SBOMResult(scanner=scanner, error=str(e))

    async def get_scan_results(self, scan_id: str) -> Optional[ScanResults]:
        logger.info(f"Retrieving results for scan {scan_id}")
        return await db_service.get_scan_results(scan_id)

    async def get_scan_status(self, scan_id: str) -> Optional[str]:
        scan = await db_service.get_scan_results(scan_id)
        if not scan:
            scan = await db_service.get_uploaded_scan_results(scan_id)
        status = scan.status.value if scan else None
        logger.info(f"Status for scan {scan_id}: {status}")
        return status
    
    async def get_scanner_sbom(self, scan_id: str, scanner: ScannerType) -> Optional[Dict[str, Any]]:
        scan = await db_service.get_scan_results(scan_id)
        
        if scan:
            if scanner == ScannerType.TRIVY:
                return scan.trivy_sbom.sbom if scan.trivy_sbom else None
            elif scanner == ScannerType.SYFT:
                return scan.syft_sbom.sbom if scan.syft_sbom else None
            elif scanner == ScannerType.CDXGEN:
                return scan.cdxgen_sbom.sbom if scan.cdxgen_sbom else None
            elif scanner == ScannerType.GHAS:
                return scan.ghas_sbom.sbom if scan.ghas_sbom else None
            elif scanner == ScannerType.UPLOADED:
                return scan.uploaded_sbom.sbom if scan.uploaded_sbom else None
        
        if scanner == ScannerType.UPLOADED:
            uploaded_scan = await db_service.get_uploaded_scan_results(scan_id)
            if uploaded_scan and uploaded_scan.uploaded_sbom:
                return uploaded_scan.uploaded_sbom.sbom
        
        return None
    
    async def get_scan_analysis(self, scan_id: str) -> Dict:
        """
        Get analysis data for a scan.
        Now uses SQL-based analysis from DatabaseService for optimal performance.
        """
        try:
            # Check if this is an uploaded scan
            uploaded_results = await self.get_uploaded_scan_results(scan_id)
            if uploaded_results and uploaded_results.uploaded_sbom:
                logger.info(f"Getting analysis for uploaded scan {scan_id}")
                sbom_data = uploaded_results.uploaded_sbom.sbom
                if sbom_data:
                    # Extract and save packages if not already done
                    pkg_list = self.package_analyzer.extract_packages(sbom_data, ScannerType.UPLOADED)
                    await db_service.save_packages(scan_id, ScannerType.UPLOADED.value, pkg_list)
                    
                    return {
                        "packages": pkg_list,
                        "total_count": len(pkg_list),
                        "scanner": "uploaded",
                        "filename": uploaded_results.filename,
                        "original_format": uploaded_results.original_format,
                        "component_count": uploaded_results.uploaded_sbom.component_count
                    }
            
            # Use SQL-based analysis for repository scans
            results = await self.get_scan_results(scan_id)
            if not results:
                return {"error": "Scan not found"}
            
            # Get comprehensive analysis from database
            analysis = await db_service.analyze_scan_packages(scan_id)
            
            # Add tech stack info
            analysis["tech_stack"] = results.tech_stack
            
            return analysis
        except Exception as e:
            logger.error(f"Error in get_scan_analysis for scan {scan_id}: {e}")
            return {"error": "Analysis failed", "details": str(e)}
    
    async def get_scan_graph(self, scan_id: str, scanner: ScannerType) -> Dict[str, Any]:
        """Get graph data for a specific scanner's SBOM."""
        sbom_data = await self.get_scanner_sbom(scan_id, scanner)
        if not sbom_data:
            return {"error": "SBOM not found for this scanner"}
        
        return self.package_analyzer.parse_sbom_graph(sbom_data)
    
    async def process_uploaded_sbom(self, filename: str, file_content: bytes, sbom_format: str) -> str:
        """Process an uploaded SBOM file and return scan_id."""
        scan_id = str(uuid.uuid4())
        logger.info(f"Processing uploaded SBOM: {filename}, format: {sbom_format}, scan_id: {scan_id}")
        
        # Create uploaded scan entry
        uploaded_scan = UploadedScanResults(
            scan_id=scan_id,
            status=ScanStatus.IN_PROGRESS,
            filename=filename,
            original_format=sbom_format,
            created_at=datetime.now()
        )
        await db_service.save_uploaded_scan_results(uploaded_scan)
        
        try:
            # Save uploaded file temporarily
            temp_dir = os.path.join(settings.TEMP_DIR, scan_id)
            os.makedirs(temp_dir, exist_ok=True)
            
            original_file_path = os.path.join(temp_dir, f"original_{filename}")
            with open(original_file_path, 'wb') as f:
                f.write(file_content)
            
            # Process based on format
            if sbom_format.lower() == "spdx":
                logger.info(f"Converting SPDX to CycloneDX for scan {scan_id}")
                cyclonedx_file_path = os.path.join(temp_dir, f"converted_{filename}")
                
                # Convert SPDX to CycloneDX using cyclonedx-cli
                result = subprocess.run([
                    "cyclonedx", "convert",
                    "--input-file", original_file_path,
                    "--input-format", "spdxjson",
                    "--output-format", "json",
                    "--output-file", cyclonedx_file_path
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode != 0:
                    logger.error(f"CycloneDX conversion failed for scan {scan_id}: {result.stderr}")
                    raise Exception(f"Failed to convert SPDX to CycloneDX: {result.stderr}")
                
                logger.info(f"CycloneDX conversion logs for scan {scan_id}: {result.stdout}")
                
                # Load the converted file
                with open(cyclonedx_file_path, 'r', encoding='utf-8') as f:
                    sbom_data = json.load(f)
                    
            elif sbom_format.lower() == "cyclonedx":
                logger.info(f"Processing CycloneDX SBOM for scan {scan_id}")
                # Load the file directly as it's already in CycloneDX format
                with open(original_file_path, 'r', encoding='utf-8') as f:
                    sbom_data = json.load(f)
            else:
                raise Exception(f"Unsupported SBOM format: {sbom_format}")
            
            # Count components
            component_count = len(sbom_data.get("components", []))
            logger.info(f"Uploaded SBOM for scan {scan_id} contains {component_count} components")
            
            # Create SBOM result
            sbom_result = SBOMResult(
                scanner=ScannerType.UPLOADED,
                sbom=sbom_data,
                component_count=component_count
            )
            
            # Update the uploaded scan
            uploaded_scan.uploaded_sbom = sbom_result
            uploaded_scan.status = ScanStatus.COMPLETED
            uploaded_scan.completed_at = datetime.now()
            
            # Save updated uploaded scan results
            await db_service.save_uploaded_scan_results(uploaded_scan)
            
            # Extract and save packages
            logger.info(f"Extracting and saving packages from uploaded SBOM for scan {scan_id}")
            uploaded_packages = self.package_analyzer.extract_packages(sbom_data, ScannerType.UPLOADED)
            await db_service.save_packages(scan_id, ScannerType.UPLOADED.value, uploaded_packages)
            
            logger.info(f"Successfully processed uploaded SBOM for scan {scan_id}")
            return scan_id
            
        except Exception as e:
            logger.error(f"Failed to process uploaded SBOM for scan {scan_id}: {e}")
            uploaded_scan.status = ScanStatus.FAILED
            await db_service.save_uploaded_scan_results(uploaded_scan)
            raise e
        
    async def get_uploaded_scan_results(self, scan_id: str) -> Optional[UploadedScanResults]:
        logger.info(f"Retrieving uploaded scan results for scan {scan_id}")
        return await db_service.get_uploaded_scan_results(scan_id)