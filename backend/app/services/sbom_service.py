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
from app.services.bd_service import BDService
from app.services.database_service import db_service

from app.database import AsyncSessionLocal
from sqlalchemy import text

logger = logging.getLogger(__name__)

class SBOMService:
    def __init__(self):
        self.docker_client = docker.from_env()
        self.package_analyzer = PackageAnalyze()
        self.github_service = GithubService()
        self.bd_service = BDService()

    async def start_scan(
        self, 
        repo_url: str, 
        github_token: Optional[str] = None,
        bd_project_name: Optional[str] = None,
        bd_project_version: Optional[str] = None,
        bd_api_token: Optional[str] = None
    ) -> str:
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
    
    async def run_scan(
        self, 
        scan_id: str, 
        github_token: Optional[str] = None,
        bd_project_name: Optional[str] = None,
        bd_project_version: Optional[str] = None,
        bd_api_token: Optional[str] = None,
        uploaded_sbom_content: Optional[bytes] = None,
        uploaded_sbom_format: Optional[str] = None
    ):
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
            bd_result = await self._run_scanner(
                scan_id, 
                ScannerType.BLACKDUCK, 
                repo_path,
                bd_project_name=bd_project_name,
                bd_project_version=bd_project_version,
                bd_api_token=bd_api_token
            )

            scan.trivy_sbom = trivy_result
            scan.syft_sbom = syft_result
            scan.cdxgen_sbom = cdxgen_result
            scan.ghas_sbom = ghas_result
            scan.bd_sbom = bd_result
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            logger.info(f"Scan {scan_id} completed successfully")
            
            # Save updated scan results
            await db_service.save_scan_results(scan)
            
            # Extract and save packages and dependencies for each scanner
            logger.info(f"Extracting and saving packages and dependencies for scan {scan_id}")
            if trivy_result and trivy_result.sbom:
                trivy_packages, trivy_deps = self.package_analyzer.extract_packages(trivy_result.sbom, ScannerType.TRIVY)
                await db_service.save_packages(scan_id, ScannerType.TRIVY.value, trivy_packages)
                await db_service.save_dependencies(scan_id, ScannerType.TRIVY.value, trivy_deps)
            
            if syft_result and syft_result.sbom:
                syft_packages, syft_deps = self.package_analyzer.extract_packages(syft_result.sbom, ScannerType.SYFT)
                await db_service.save_packages(scan_id, ScannerType.SYFT.value, syft_packages)
                await db_service.save_dependencies(scan_id, ScannerType.SYFT.value, syft_deps)
            
            if cdxgen_result and cdxgen_result.sbom:
                cdxgen_packages, cdxgen_deps = self.package_analyzer.extract_packages(cdxgen_result.sbom, ScannerType.CDXGEN)
                await db_service.save_packages(scan_id, ScannerType.CDXGEN.value, cdxgen_packages)
                await db_service.save_dependencies(scan_id, ScannerType.CDXGEN.value, cdxgen_deps)

            if ghas_result and ghas_result.sbom:
                ghas_packages, ghas_deps = self.package_analyzer.extract_spdx_packages(ghas_result.sbom, ScannerType.GHAS)
                await db_service.save_packages(scan_id, ScannerType.GHAS.value, ghas_packages)
                await db_service.save_dependencies(scan_id, ScannerType.GHAS.value, ghas_deps)
            
            if bd_result and bd_result.sbom:
                bd_packages, bd_deps = self.package_analyzer.extract_packages(bd_result.sbom, ScannerType.BLACKDUCK)
                await db_service.save_packages(scan_id, ScannerType.BLACKDUCK.value, bd_packages)
                await db_service.save_dependencies(scan_id, ScannerType.BLACKDUCK.value, bd_deps)
            
            # Process uploaded SBOM if provided
            if uploaded_sbom_content and uploaded_sbom_format:
                logger.info(f"Processing uploaded SBOM for scan {scan_id}, format: {uploaded_sbom_format}")
                uploaded_result = await self._process_uploaded_sbom_for_scan(
                    uploaded_sbom_content,
                    uploaded_sbom_format
                )
                scan.uploaded_sbom = uploaded_result
                
                if uploaded_result and uploaded_result.sbom:
                    # Extract packages and dependencies based on format
                    if uploaded_sbom_format.lower() == 'spdx':
                        uploaded_packages, uploaded_deps = self.package_analyzer.extract_spdx_packages(
                            uploaded_result.sbom, 
                            ScannerType.UPLOADED
                        )
                    else:  # cyclonedx
                        uploaded_packages, uploaded_deps = self.package_analyzer.extract_packages(
                            uploaded_result.sbom, 
                            ScannerType.UPLOADED
                        )
                    await db_service.save_packages(scan_id, ScannerType.UPLOADED.value, uploaded_packages)
                    await db_service.save_dependencies(scan_id, ScannerType.UPLOADED.value, uploaded_deps)
                    logger.info(f"Saved {len(uploaded_packages)} packages and {len(uploaded_deps)} dependencies from uploaded SBOM")
            
            # Note: Merged SBOM will be created on-demand when user explicitly requests it via the UI
            logger.info(f"Scan {scan_id} completed. All packages and dependencies saved to database.")

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
        repo_url: Optional[str] = None,
        bd_project_name: Optional[str] = None,
        bd_project_version: Optional[str] = None,
        bd_api_token: Optional[str] = None
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
            
            elif scanner == ScannerType.BLACKDUCK:
                if not all([bd_project_name, bd_project_version, bd_api_token]):
                    logger.info(f"Black Duck parameters not provided, skipping BD scanner")
                    return SBOMResult(
                        scanner=scanner,
                        sbom=None,
                        component_count=0,
                        error="Black Duck parameters not provided"
                    )
                
                # Fetch SBOM from Black Duck API
                sbom_data = await self.bd_service.fetch_sbom(
                    project_name=bd_project_name,
                    project_version=bd_project_version,
                    api_token=bd_api_token
                )
                
                # Save to temp file for consistency
                with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
                    temp_file_path = temp_file.name
                    json.dump(sbom_data, temp_file, indent=2)
                
                # Verify file was written correctly
                with open(temp_file_path, 'r') as f:
                    sbom_data = json.load(f)
                
                component_count = len(sbom_data.get("components", []))
                
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
            elif scanner == ScannerType.BLACKDUCK:
                return scan.bd_sbom.sbom if scan.bd_sbom else None
            elif scanner == ScannerType.UPLOADED:
                return scan.uploaded_sbom.sbom if scan.uploaded_sbom else None
        
        if scanner == ScannerType.UPLOADED:
            uploaded_scan = await db_service.get_uploaded_scan_results(scan_id)
            if uploaded_scan and uploaded_scan.uploaded_sbom:
                return uploaded_scan.uploaded_sbom.sbom
        
        return None
    
    async def get_scan_analysis(self, scan_id: str, use_cache: bool = True) -> Dict:
        """
        Get analysis data for a scan.
        Now uses SQL-based analysis from DatabaseService with intelligent caching.
        
        Args:
            scan_id: The scan identifier
            use_cache: Whether to use cached analysis if available (default: True)
        """
        try:
            # Check if this is an uploaded scan
            uploaded_results = await self.get_uploaded_scan_results(scan_id)
            if uploaded_results and uploaded_results.uploaded_sbom:
                logger.info(f"Getting analysis for uploaded scan {scan_id}")
                sbom_data = uploaded_results.uploaded_sbom.sbom
                if sbom_data:
                    # Extract packages and dependencies (extract_packages returns a tuple)
                    pkg_list, deps_list = self.package_analyzer.extract_packages(sbom_data, ScannerType.UPLOADED)
                    await db_service.save_packages(scan_id, ScannerType.UPLOADED.value, pkg_list)
                    await db_service.save_dependencies(scan_id, ScannerType.UPLOADED.value, deps_list)
                    
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
            
            # Get comprehensive analysis from database (with caching)
            analysis = await db_service.analyze_scan_packages(scan_id, use_cache=use_cache)
            
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
    
    async def get_merged_sbom(self, scan_id: str, include_all_unique: bool = True, 
                             exclude_github_actions: bool = False, 
                             force_regenerate: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get the merged SBOM for a scan.
        
        Args:
            scan_id: The scan identifier
            include_all_unique: Whether to include all unique packages
            exclude_github_actions: Whether to exclude GitHub Actions packages
            force_regenerate: Force regeneration even if cached version exists
        """
        try:
            scan = await db_service.get_scan_results(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return None
            
            # Check if merged SBOM already exists in database (unless forcing regeneration)
            if not force_regenerate:                
                async with AsyncSessionLocal() as session:
                    result = await session.execute(
                        text("SELECT merged_sbom FROM scan_results WHERE scan_id = :scan_id"),
                        {"scan_id": scan_id}
                    )
                    row = result.fetchone()
                    
                    if row and row.merged_sbom:
                        logger.info(f"Retrieved existing merged SBOM for scan {scan_id}")
                        return row.merged_sbom
            
            # If not exists or force regenerate, create it
            logger.info(f"Creating merged SBOM for scan {scan_id} (include_all_unique={include_all_unique}, exclude_github_actions={exclude_github_actions})")
            merged_sbom = await db_service.merge_sboms(
                scan_id=scan_id,
                include_all_unique=include_all_unique,
                exclude_github_actions=exclude_github_actions
            )
            return merged_sbom
            
        except Exception as e:
            logger.error(f"Error getting merged SBOM for scan {scan_id}: {e}")
            return None
    
    async def get_merged_sbom_with_selections(self, scan_id: str, 
                                              selected_unique_packages: Dict[str, list]) -> Optional[Dict[str, Any]]:
        """
        Get the merged SBOM with specific unique packages selected by the user.
        
        Args:
            scan_id: The scan identifier
            selected_unique_packages: Dict mapping scanner names to lists of selected packages
                Example: {
                    "syft": [{"name": "pkg1", "version": "1.0.0"}],
                    "trivy": [{"name": "pkg2", "version": "2.0.0"}]
                }
        """
        try:
            scan = await db_service.get_scan_results(scan_id)
            if not scan:
                logger.error(f"Scan {scan_id} not found")
                return None
            
            logger.info(f"Creating merged SBOM for scan {scan_id} with specific package selections")
            merged_sbom = await db_service.merge_sboms_with_selections(
                scan_id=scan_id,
                selected_unique_packages=selected_unique_packages
            )
            return merged_sbom
            
        except Exception as e:
            logger.error(f"Error getting merged SBOM with selections for scan {scan_id}: {e}")
            return None
    
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
            
            # Extract and save packages and dependencies
            logger.info(f"Extracting and saving packages and dependencies from uploaded SBOM for scan {scan_id}")
            uploaded_packages, uploaded_deps = self.package_analyzer.extract_packages(sbom_data, ScannerType.UPLOADED)
            await db_service.save_packages(scan_id, ScannerType.UPLOADED.value, uploaded_packages)
            await db_service.save_dependencies(scan_id, ScannerType.UPLOADED.value, uploaded_deps)
            
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
    
    async def _process_uploaded_sbom_for_scan(
        self, 
        sbom_content: bytes, 
        sbom_format: str
    ) -> SBOMResult:
        """
        Process uploaded SBOM file for comparison with scanner results.
        Returns SBOMResult with parsed SBOM data.
        """
        try:
            # Parse JSON content
            sbom_data = json.loads(sbom_content.decode('utf-8'))
            
            # Count components based on format
            if sbom_format.lower() == 'spdx':
                component_count = len(sbom_data.get("packages", []))
            else:  # cyclonedx
                component_count = len(sbom_data.get("components", []))
            
            logger.info(f"Processed uploaded SBOM: format={sbom_format}, components={component_count}")
            
            return SBOMResult(
                scanner=ScannerType.UPLOADED,
                sbom=sbom_data,
                component_count=component_count,
                error=None
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse uploaded SBOM: {e}")
            return SBOMResult(
                scanner=ScannerType.UPLOADED,
                sbom=None,
                component_count=0,
                error=f"Invalid JSON format: {str(e)}"
            )
        except Exception as e:
            logger.error(f"Error processing uploaded SBOM: {e}")
            return SBOMResult(
                scanner=ScannerType.UPLOADED,
                sbom=None,
                component_count=0,
                error=str(e)
            )