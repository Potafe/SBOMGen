import os
import json
import asyncio
import subprocess
import docker
import uuid
import logging
import tempfile
import difflib

from typing import Dict, Optional, List, Any, Tuple
from collections import defaultdict
from datetime import datetime
from git import Repo

from app.schemas.scan import ScanResults, ScanStatus, SBOMResult, ScannerType
from app.core.config import settings
from app.utils.tech_stack import detect_tech_stack

logger = logging.getLogger(__name__)

class SBOMService:
    def __init__(self):
        self.scans: Dict[str, ScanResults] = {} # In-memory storage (will replace with DB later)
        self.docker_client = docker.from_env()

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
        
    async def _handle_reruns(self, scan_id: str, repo_path: str):
        scan = self.scans.get(scan_id)
        if not scan:
            return
        
        tech_stack = scan.tech_stack or []
        for sbom_result in [scan.trivy_sbom, scan.syft_sbom, scan.cdxgen_sbom]:
            if sbom_result and sbom_result.component_count == 0:
                commands = self._get_rerun_commands(sbom_result.scanner, tech_stack, repo_path)
                await self.rerun_scanner(scan_id, sbom_result.scanner, commands, repo_path)

    def _get_rerun_commands(self, scanner: ScannerType, tech_stack: List[str], repo_path: str) -> List[str]:
        # Cuurently some placeholder logic for rerun commands
        commands = []
        if "python" in tech_stack:
            commands.extend(["pip install -r requirements.txt"])
        if "nodejs" in tech_stack:
            commands.extend(["npm install"])
        return commands
    
    async def rerun_scanner(self, scan_id: str, scanner: ScannerType, repo_path: str, commands: Optional[List[str]] = None) -> bool:
        scan = self.scans.get(scan_id)
        if not scan:
            return False

        try:
            if commands:
                for cmd in commands:
                    self.docker_client.containers.run(
                        "alpine:latest",
                        ["sh", "-c", cmd],
                        working_dir=repo_path,
                        detach=False
                    )

            result = await self._run_scanner(scan_id, scanner, repo_path)
            result.rerun = True

            if scanner == ScannerType.TRIVY:
                scan.trivy_sbom = result
            elif scanner == ScannerType.SYFT:
                scan.syft_sbom = result
            elif scanner == ScannerType.CDXGEN:
                scan.cdxgen_sbom = result

            return True
        except Exception as e:
            print(f"Rerun failed: {e}")
            return False

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
    
    def _extract_packages(self, sbom_data: Dict, scanner: ScannerType) -> List[Dict[str, str]]:
        """Extract package data with name, version, purl, and cpe from SBOM data."""
        packages = []
        for component in sbom_data.get("components", []):
            name = component.get("name", "").lower().strip()
            version = component.get("version", "").lower().strip()
            purl = component.get("purl", "").lower().strip()
            
            cpe = ""
            if "cpe" in component:
                cpe = component["cpe"].lower().strip()
            elif "externalReferences" in component:
                for ref in component["externalReferences"]:
                    if ref.get("type") == "cpe22Type" or ref.get("type") == "cpe23Type":
                        cpe = ref.get("url", "").lower().strip()
                        break
            
            if name:
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe
                })
        return packages
    
    def _calculate_match_score(self, pkg1: Dict[str, str], pkg2: Dict[str, str]) -> Dict[str, float]:
        """Calculate comprehensive match score including name, version, purl, and cpe."""
        scores = {}
        
        scores["name"] = difflib.SequenceMatcher(None, pkg1["name"], pkg2["name"]).ratio()
        
        scores["version"] = difflib.SequenceMatcher(None, pkg1["version"], pkg2["version"]).ratio() if pkg1["version"] and pkg2["version"] else 0.0
        
        if pkg1["purl"] and pkg2["purl"]:
            scores["purl"] = difflib.SequenceMatcher(None, pkg1["purl"], pkg2["purl"]).ratio()
        else:
            scores["purl"] = 0.0
        
        if pkg1["cpe"] and pkg2["cpe"]:
            scores["cpe"] = difflib.SequenceMatcher(None, pkg1["cpe"], pkg2["cpe"]).ratio()
        else:
            scores["cpe"] = 0.0
        
        weights = {"name": 0.4, "version": 0.3, "purl": 0.2, "cpe": 0.1}
        overall = sum(scores[field] * weights[field] for field in weights)
        scores["overall"] = overall
        
        return scores
    
    def _find_common_packages(self, packages_list: List[List[Dict[str, str]]]) -> Dict[str, List[Dict]]:
        """Find common packages across scanners with comprehensive matching."""
        common = defaultdict(list)
        scanner_names = ["trivy", "syft", "cdxgen"]
        
        all_packages = []
        for i, packages in enumerate(packages_list):
            for pkg in packages:
                pkg_key = (pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"])
                all_packages.append((pkg_key, pkg, i))
        
        package_groups = defaultdict(list)
        for pkg_key, pkg, scanner_idx in all_packages:
            package_groups[pkg_key].append((pkg, scanner_idx))
        
        for pkg_key, occurrences in package_groups.items():
            if len(occurrences) > 1:
                found_in = [scanner_names[scanner_idx] for _, scanner_idx in occurrences]
                pkg = occurrences[0][0]  # Take first occurrence for details
                common["exact"].append({
                    "name": pkg["name"],
                    "version": pkg["version"],
                    "purl": pkg["purl"],
                    "cpe": pkg["cpe"],
                    "found_in": found_in,
                    "match_type": "exact",
                    "match_scores": {"name": 1.0, "version": 1.0, "purl": 1.0, "cpe": 1.0, "overall": 1.0}
                })
        
        exact_packages = set()
        for item in common["exact"]:
            exact_packages.add((item["name"], item["version"], item["purl"], item["cpe"]))
        
        for i in range(len(packages_list)):
            for j in range(i+1, len(packages_list)):
                for pkg1 in packages_list[i]:
                    for pkg2 in packages_list[j]:
                        pkg1_key = (pkg1["name"], pkg1["version"], pkg1["purl"], pkg1["cpe"])
                        pkg2_key = (pkg2["name"], pkg2["version"], pkg2["purl"], pkg2["cpe"])
                        
                        if pkg1_key in exact_packages or pkg2_key in exact_packages:
                            continue
                        
                        match_scores = self._calculate_match_score(pkg1, pkg2)
                        
                        # Consider it a fuzzy match if overall score > 0.7
                        if match_scores["overall"] > 0.7:
                            already_exists = any(
                                (f["name"] == pkg1["name"] and f["version"] == pkg1["version"]) or
                                (f["name"] == pkg2["name"] and f["version"] == pkg2["version"])
                                for f in common["fuzzy"]
                            )
                            
                            if not already_exists:
                                common["fuzzy"].append({
                                    "name": pkg1["name"],
                                    "version": pkg1["version"],
                                    "purl": pkg1["purl"],
                                    "cpe": pkg1["cpe"],
                                    "similar_to": {
                                        "name": pkg2["name"],
                                        "version": pkg2["version"],
                                        "purl": pkg2["purl"],
                                        "cpe": pkg2["cpe"]
                                    },
                                    "found_in": [scanner_names[i], scanner_names[j]],
                                    "match_type": f"fuzzy-{int(match_scores['overall'] * 100)}%",
                                    "match_scores": match_scores
                                })
        
        return dict(common)
    
    def _find_unique_packages(self, packages_list: List[List[Dict[str, str]]]) -> Dict[str, List[Dict]]:
        """Find packages unique to each scanner."""
        unique = {}
        scanner_names = ["trivy", "syft", "cdxgen"]
        
        for i, packages in enumerate(packages_list):
            scanner_name = scanner_names[i]
            unique[scanner_name] = []
            
            other_packages = set()
            for j, other in enumerate(packages_list):
                if j != i:
                    for pkg in other:
                        other_packages.add((pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"]))
            
            for pkg in packages:
                pkg_key = (pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"])
                if pkg_key not in other_packages:
                    unique[scanner_name].append({
                        "name": pkg["name"],
                        "version": pkg["version"],
                        "purl": pkg["purl"],
                        "cpe": pkg["cpe"]
                    })
        
        return unique
    
    def _calculate_scores(self, common: Dict, unique: Dict, total_counts: Dict[str, int]) -> Dict[str, float]:
        """Calculate basic scores based on common packages and uniqueness."""
        scores = {}
        for scanner in ["trivy", "syft", "cdxgen"]:
            # Score = (common packages found in this scanner / total packages) * 100
            # Plus bonus for uniqueness (but penalize too much uniqueness as potential false positives)
            common_count = sum(1 for c in common.get("exact", []) if scanner in c["found_in"]) + \
                          sum(1 for c in common.get("fuzzy", []) if scanner in c["found_in"])
            unique_count = len(unique.get(scanner, []))
            total = total_counts.get(scanner, 1)
            
            # Simple score: prioritize common packages, penalize excessive uniqueness
            score = (common_count / total) * 100 - (unique_count / total) * 10
            scores[scanner] = max(0, score)  # Ensure non-negative
        
        return scores
    
    async def get_scan_analysis(self, scan_id: str) -> Dict:
        """Get analysis data for a scan."""
        results = await self.get_scan_results(scan_id)
        if not results:
            return {}
        
        packages = []
        total_counts = {}
        for scanner in [ScannerType.TRIVY, ScannerType.SYFT, ScannerType.CDXGEN]:
            sbom_data = await self.get_scanner_sbom(scan_id, scanner)
            if sbom_data:
                pkg_list = self._extract_packages(sbom_data, scanner)
                packages.append(pkg_list)
                total_counts[scanner.value] = len(pkg_list)
            else:
                packages.append([])
                total_counts[scanner.value] = 0
        
        common = self._find_common_packages(packages)
        unique = self._find_unique_packages(packages)
        
        scores = self._calculate_scores(common, unique, total_counts)
        
        return {
            "common_packages": common,
            "unique_packages": unique,
            "total_counts": total_counts,
            "scores": scores,
            "tech_stack": results.tech_stack
        }
    
    def _parse_sbom_graph(self, sbom_data: Dict) -> Dict[str, Any]:
        """Parse CycloneDX SBOM to extract graph data for visualization."""
        nodes = []
        edges = []
        node_map = {}  # Map purl to node index
        
        for i, component in enumerate(sbom_data.get("components", [])):
            purl = component.get("purl", "")
            if not purl:
                continue
                
            node = {
                "id": purl,
                "label": component.get("name", "Unknown"),
                "properties": {
                    "name": component.get("name", ""),
                    "version": component.get("version", ""),
                    "purl": purl,
                    "type": component.get("type", ""),
                    "description": component.get("description", ""),
                    "licenses": [lic.get("license", {}).get("id", "") for lic in component.get("licenses", []) if lic.get("license")],
                    "hashes": component.get("hashes", []),
                    "externalReferences": component.get("externalReferences", [])
                }
            }
            nodes.append(node)
            node_map[purl] = i
        
        for dep in sbom_data.get("dependencies", []):
            source_ref = dep.get("ref", "")
            if source_ref not in node_map:
                continue
                
            for target_ref in dep.get("dependsOn", []):
                if target_ref in node_map:
                    edge = {
                        "source": source_ref,
                        "target": target_ref,
                        "type": "depends_on"
                    }
                    edges.append(edge)
        
        return {
            "nodes": nodes,
            "edges": edges,
            "metadata": {
                "total_nodes": len(nodes),
                "total_edges": len(edges),
                "sbom_version": sbom_data.get("specVersion", ""),
                "sbom_format": "CycloneDX"
            }
        }

    async def get_scan_graph(self, scan_id: str, scanner: ScannerType) -> Dict[str, Any]:
        """Get graph data for a specific scanner's SBOM."""
        sbom_data = await self.get_scanner_sbom(scan_id, scanner)
        if not sbom_data:
            return {"error": "SBOM not found for this scanner"}
        
        return self._parse_sbom_graph(sbom_data)