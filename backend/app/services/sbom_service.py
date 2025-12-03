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

from app.schemas.scan import ScanResults, ScanStatus, SBOMResult, ScannerType
from app.core.config import settings
from app.utils.tech_stack import detect_tech_stack
from app.services.package_analyze import PackageAnalyze

logger = logging.getLogger(__name__)

class SBOMService:
    def __init__(self):
        self.scans: Dict[str, ScanResults] = {} # In-memory storage (will replace with DB later)
        self.docker_client = docker.from_env()
        self.package_analyzer = PackageAnalyze()

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
        self.scans[scan_id] = scan
        return scan_id
    
    async def run_scan(self, scan_id: str, github_token: Optional[str] = None):
        scan = self.scans.get(scan_id)
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

            scan.trivy_sbom = trivy_result
            scan.syft_sbom = syft_result
            scan.cdxgen_sbom = cdxgen_result
            scan.status = ScanStatus.COMPLETED
            scan.completed_at = datetime.now()
            logger.info(f"Scan {scan_id} completed successfully")

            # await self._handle_reruns(scan_id)
        except Exception as e:
            scan.status = ScanStatus.FAILED
            logger.error(f"Scan {scan_id} failed: {e}")
            print(f"Scan failed: {e}")

    async def _run_scanner(self, scan_id: str, scanner: ScannerType, repo_path: str) -> SBOMResult:
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

            logger.info(f"{scanner.value} for scan {scan_id} found {component_count} components")
            return SBOMResult(scanner=scanner, sbom=sbom_data, component_count=component_count)
            
        except Exception as e:
            logger.error(f"{scanner.value} for scan {scan_id} failed: {e}")
            return SBOMResult(scanner=scanner, error=str(e))

    async def get_scan_results(self, scan_id: str) -> Optional[ScanResults]:
        logger.info(f"Retrieving results for scan {scan_id}")
        return self.scans.get(scan_id)

    async def get_scan_status(self, scan_id: str) -> Optional[str]:
        scan = self.scans.get(scan_id)
        status = scan.status.value if scan else None
        logger.info(f"Status for scan {scan_id}: {status}")
        return status
    
    async def get_scanner_sbom(self, scan_id: str, scanner: ScannerType) -> Optional[Dict[str, Any]]:
        scan = self.scans.get(scan_id)
        if not scan:
            return None
        
        if scanner == ScannerType.TRIVY:
            return scan.trivy_sbom.sbom if scan.trivy_sbom else None
        elif scanner == ScannerType.SYFT:
            return scan.syft_sbom.sbom if scan.syft_sbom else None
        elif scanner == ScannerType.CDXGEN:
            return scan.cdxgen_sbom.sbom if scan.cdxgen_sbom else None
        
        return None
    
    async def get_scan_analysis(self, scan_id: str) -> Dict:
        """Get analysis data for a scan."""
        try:
            results = await self.get_scan_results(scan_id)
            if not results:
                return {}
            
            packages = []
            total_counts = {}
            for scanner in [ScannerType.TRIVY, ScannerType.SYFT, ScannerType.CDXGEN]:
                sbom_data = await self.get_scanner_sbom(scan_id, scanner)
                if sbom_data:
                    pkg_list = self.package_analyzer._extract_packages(sbom_data, scanner)
                    packages.append(pkg_list)
                    total_counts[scanner.value] = len(pkg_list)
                else:
                    packages.append([])
                    total_counts[scanner.value] = 0
            
            common = self.package_analyzer._find_common_packages(packages)
            unique = self.package_analyzer._find_unique_packages(packages)
            
            scores = self.package_analyzer._calculate_scores(common, unique, total_counts)
            
            return {
                "common_packages": common,
                "unique_packages": unique,
                "total_counts": total_counts,
                "scores": scores,
                "tech_stack": results.tech_stack
            }
        except Exception as e:
            logger.error(f"Error in get_scan_analysis for scan {scan_id}: {e}")
            return {"error": "Analysis failed", "details": str(e)}
    
    async def get_scan_graph(self, scan_id: str, scanner: ScannerType) -> Dict[str, Any]:
        """Get graph data for a specific scanner's SBOM."""
        sbom_data = await self.get_scanner_sbom(scan_id, scanner)
        if not sbom_data:
            return {"error": "SBOM not found for this scanner"}
        
        return self.package_analyzer._parse_sbom_graph(sbom_data)