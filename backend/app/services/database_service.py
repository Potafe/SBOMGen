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
from app.database.models import Package
from app.schemas.scan import ScanResults, ScanStatus, SBOMResult, ScannerType, UploadedScanResults
from sqlalchemy import text, func

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
                
                ghas_sbom_json = None
                if scan_results.ghas_sbom:
                    ghas_sbom_json = {
                        "scanner": scan_results.ghas_sbom.scanner.value,
                        "sbom": scan_results.ghas_sbom.sbom,
                        "component_count": scan_results.ghas_sbom.component_count,
                        "error": scan_results.ghas_sbom.error
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
                    ghas_sbom=ghas_sbom_json,
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
                    existing_scan.ghas_sbom = ghas_sbom_json
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

                if db_scan.ghas_sbom:
                    scan_results.ghas_sbom = SBOMResult(
                        scanner=ScannerType(db_scan.ghas_sbom["scanner"]),
                        sbom=db_scan.ghas_sbom["sbom"],
                        component_count=db_scan.ghas_sbom["component_count"],
                        error=db_scan.ghas_sbom["error"]
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
    
    async def save_packages(self, scan_id: str, scanner_name: str, packages: List[Dict[str, str]]) -> bool:
        """
        Bulk insert packages for a specific scan and scanner.
        Does NOT deduplicate - saves all packages as-is.
        """
        try:
            async with AsyncSessionLocal() as session:
                # First, delete any existing packages for this scan_id and scanner
                await session.execute(
                    text("DELETE FROM packages WHERE scan_id = :scan_id AND scanner_name = :scanner_name"),
                    {"scan_id": scan_id, "scanner_name": scanner_name}
                )
                
                # Bulk insert new packages
                package_objects = [
                    Package(
                        scan_id=scan_id,
                        scanner_name=scanner_name,
                        name=pkg["name"],
                        version=pkg["version"],
                        purl=pkg.get("purl", ""),
                        cpe=pkg.get("cpe", "")
                    )
                    for pkg in packages
                ]
                
                session.add_all(package_objects)
                await session.commit()
                
                logger.info(f"Saved {len(packages)} packages for scan {scan_id}, scanner {scanner_name}")
                return True
        except Exception as e:
            logger.error(f"Error saving packages for scan {scan_id}, scanner {scanner_name}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return False
    
    async def find_exact_matches(self, scan_id: str) -> Dict[str, Any]:
        """
        Find exact matches (same name AND version) across all scanners for a scan.
        Returns packages that appear in multiple scanners with their counts.
        """
        try:
            async with AsyncSessionLocal() as session:
                # Query to find exact matches across scanners
                query = text("""
                    WITH package_scanner_counts AS (
                        SELECT 
                            name,
                            version,
                            scanner_name,
                            COUNT(*) as count_in_scanner
                        FROM packages
                        WHERE scan_id = :scan_id
                        GROUP BY name, version, scanner_name
                    ),
                    cross_scanner_packages AS (
                        SELECT 
                            name,
                            version,
                            COUNT(DISTINCT scanner_name) as scanner_count,
                            json_object_agg(scanner_name, count_in_scanner) as duplicate_counts,
                            array_agg(DISTINCT scanner_name) as found_in
                        FROM package_scanner_counts
                        GROUP BY name, version
                        HAVING COUNT(DISTINCT scanner_name) > 1
                    )
                    SELECT 
                        name,
                        version,
                        scanner_count,
                        duplicate_counts,
                        found_in
                    FROM cross_scanner_packages
                    ORDER BY scanner_count DESC, name
                """)
                
                result = await session.execute(query, {"scan_id": scan_id})
                rows = result.fetchall()
                
                exact_matches = []
                for row in rows:
                    exact_matches.append({
                        "name": row.name,
                        "version": row.version,
                        "found_in": row.found_in,
                        "scanner_count": row.scanner_count,
                        "duplicate_counts": row.duplicate_counts,
                        "match_type": "exact"
                    })
                
                logger.info(f"Found {len(exact_matches)} exact matches for scan {scan_id}")
                return {"exact": exact_matches}
        except Exception as e:
            logger.error(f"Error finding exact matches for scan {scan_id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {"exact": []}
    
    async def find_fuzzy_matches(self, scan_id: str, similarity_threshold: float = 0.8) -> Dict[str, Any]:
        """
        Find fuzzy matches using hybrid approach:
        1. Use pg_trgm to filter candidates (fast but inaccurate)
        2. Use normalized Levenshtein distance for final scoring (accurate)
        Excludes exact matches to avoid duplicates.
        """
        try:
            async with AsyncSessionLocal() as session:
                # Hybrid fuzzy matching: pg_trgm filter + normalized Levenshtein scoring
                query = text("""
                    WITH distinct_packages AS (
                        -- Get all unique package/scanner combinations
                        SELECT DISTINCT 
                            name,
                            version,
                            scanner_name
                        FROM packages
                        WHERE scan_id = :scan_id
                    ),
                    exact_match_pairs AS (
                        -- Find exact match pairs to exclude from fuzzy matching
                        SELECT DISTINCT
                            p1.name as name1,
                            p1.version as version1,
                            p1.scanner_name as scanner1,
                            p2.name as name2,
                            p2.version as version2,
                            p2.scanner_name as scanner2
                        FROM distinct_packages p1
                        JOIN distinct_packages p2 ON 
                            p1.name = p2.name 
                            AND p1.version = p2.version
                            AND p1.scanner_name < p2.scanner_name
                    ),
                    fuzzy_candidates AS (
                        -- Use pg_trgm for fast filtering (threshold 0.7)
                        SELECT DISTINCT
                            p1.name as name1,
                            p1.version as version1,
                            p1.scanner_name as scanner1,
                            p2.name as name2,
                            p2.version as version2,
                            p2.scanner_name as scanner2,
                            similarity(p1.name, p2.name) as trgm_name_sim,
                            similarity(p1.version, p2.version) as trgm_version_sim
                        FROM distinct_packages p1
                        JOIN distinct_packages p2 ON 
                            p1.scanner_name < p2.scanner_name
                        LEFT JOIN exact_match_pairs emp ON 
                            p1.name = emp.name1 
                            AND p1.version = emp.version1 
                            AND p1.scanner_name = emp.scanner1
                            AND p2.name = emp.name2 
                            AND p2.version = emp.version2 
                            AND p2.scanner_name = emp.scanner2
                        WHERE 
                            emp.name1 IS NULL  -- Exclude pairs that are already exact matches
                            AND similarity(p1.name, p2.name) > 0.7
                            AND similarity(p1.version, p2.version) > 0.5
                            AND (p1.name != p2.name OR p1.version != p2.version)  -- Exclude identical pairs
                    )
                    -- Final scoring with normalized Levenshtein distance
                    -- Similarity = 1 - (levenshtein_distance / max_length)
                    SELECT 
                        name1,
                        version1,
                        scanner1,
                        name2,
                        version2,
                        scanner2,
                        trgm_name_sim,
                        trgm_version_sim,
                        CASE 
                            WHEN GREATEST(LENGTH(name1), LENGTH(name2)) = 0 THEN 0
                            ELSE 1.0 - (CAST(levenshtein(name1, name2) AS FLOAT) / GREATEST(LENGTH(name1), LENGTH(name2)))
                        END as name_similarity,
                        CASE 
                            WHEN GREATEST(LENGTH(version1), LENGTH(version2)) = 0 THEN 0
                            ELSE 1.0 - (CAST(levenshtein(version1, version2) AS FLOAT) / GREATEST(LENGTH(version1), LENGTH(version2)))
                        END as version_similarity,
                        (
                            CASE 
                                WHEN GREATEST(LENGTH(name1), LENGTH(name2)) = 0 THEN 0
                                ELSE 1.0 - (CAST(levenshtein(name1, name2) AS FLOAT) / GREATEST(LENGTH(name1), LENGTH(name2)))
                            END +
                            CASE 
                                WHEN GREATEST(LENGTH(version1), LENGTH(version2)) = 0 THEN 0
                                ELSE 1.0 - (CAST(levenshtein(version1, version2) AS FLOAT) / GREATEST(LENGTH(version1), LENGTH(version2)))
                            END
                        ) / 2 as overall_similarity
                    FROM fuzzy_candidates
                    WHERE (
                        CASE 
                            WHEN GREATEST(LENGTH(name1), LENGTH(name2)) = 0 THEN 0
                            ELSE 1.0 - (CAST(levenshtein(name1, name2) AS FLOAT) / GREATEST(LENGTH(name1), LENGTH(name2)))
                        END +
                        CASE 
                            WHEN GREATEST(LENGTH(version1), LENGTH(version2)) = 0 THEN 0
                            ELSE 1.0 - (CAST(levenshtein(version1, version2) AS FLOAT) / GREATEST(LENGTH(version1), LENGTH(version2)))
                        END
                    ) / 2 > :threshold
                    ORDER BY overall_similarity DESC
                    LIMIT 1000
                """)
                
                result = await session.execute(query, {
                    "scan_id": scan_id,
                    "threshold": similarity_threshold
                })
                rows = result.fetchall()
                
                fuzzy_matches = []
                for row in rows:
                    fuzzy_matches.append({
                        "name": row.name1,
                        "version": row.version1,
                        "scanner": row.scanner1,
                        "similar_to": {
                            "name": row.name2,
                            "version": row.version2,
                            "scanner": row.scanner2
                        },
                        "similarity_scores": {
                            "name": round(float(row.name_similarity), 3),
                            "version": round(float(row.version_similarity), 3),
                            "overall": round(float(row.overall_similarity), 3)
                        },
                        "match_type": f"fuzzy-{int(row.overall_similarity * 100)}%"
                    })
                
                logger.info(f"Found {len(fuzzy_matches)} fuzzy matches for scan {scan_id}")
                return {"fuzzy": fuzzy_matches}
        except Exception as e:
            logger.error(f"Error finding fuzzy matches for scan {scan_id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {"fuzzy": []}
    
    async def find_unique_packages(self, scan_id: str) -> Dict[str, List[Dict]]:
        """
        Find packages unique to each scanner (not found in any other scanner).
        """
        try:
            async with AsyncSessionLocal() as session:
                # Find packages that only appear in one scanner
                query = text("""
                    WITH package_scanners AS (
                        SELECT DISTINCT 
                            name,
                            version,
                            scanner_name
                        FROM packages
                        WHERE scan_id = :scan_id
                    ),
                    scanner_counts AS (
                        SELECT 
                            name,
                            version,
                            COUNT(DISTINCT scanner_name) as num_scanners,
                            array_agg(DISTINCT scanner_name) as scanners
                        FROM package_scanners
                        GROUP BY name, version
                    )
                    SELECT 
                        ps.name,
                        ps.version,
                        ps.scanner_name
                    FROM package_scanners ps
                    JOIN scanner_counts sc ON ps.name = sc.name AND ps.version = sc.version
                    WHERE sc.num_scanners = 1
                    ORDER BY ps.scanner_name, ps.name
                """)
                
                result = await session.execute(query, {"scan_id": scan_id})
                rows = result.fetchall()
                
                unique = {}
                for row in rows:
                    scanner = row.scanner_name
                    if scanner not in unique:
                        unique[scanner] = []
                    unique[scanner].append({
                        "name": row.name,
                        "version": row.version
                    })
                
                logger.info(f"Found unique packages for scan {scan_id}: {sum(len(v) for v in unique.values())} total")
                return unique
        except Exception as e:
            logger.error(f"Error finding unique packages for scan {scan_id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {}
    
    async def get_package_counts(self, scan_id: str) -> Dict[str, int]:
        """Get total package counts for each scanner."""
        try:
            async with AsyncSessionLocal() as session:
                query = text("""
                    SELECT 
                        scanner_name,
                        COUNT(*) as count
                    FROM packages
                    WHERE scan_id = :scan_id
                    GROUP BY scanner_name
                """)
                
                result = await session.execute(query, {"scan_id": scan_id})
                rows = result.fetchall()
                
                counts = {row.scanner_name: row.count for row in rows}
                logger.info(f"Package counts for scan {scan_id}: {counts}")
                return counts
        except Exception as e:
            logger.error(f"Error getting package counts for scan {scan_id}: {e}")
            return {}
    
    async def analyze_scan_packages(self, scan_id: str) -> Dict[str, Any]:
        """
        Complete analysis of packages for a scan.
        Finds exact matches, fuzzy matches, unique packages, and calculates scores.
        """
        try:
            # Get all analysis data in parallel
            exact_matches = await self.find_exact_matches(scan_id)
            fuzzy_matches = await self.find_fuzzy_matches(scan_id)
            unique_packages = await self.find_unique_packages(scan_id)
            total_counts = await self.get_package_counts(scan_id)
            
            # Calculate simple scores based on commonality
            scores = {}
            for scanner in total_counts.keys():
                if total_counts[scanner] == 0:
                    scores[scanner] = 0.0
                    continue
                
                # Count how many of this scanner's packages are common
                exact_count = sum(1 for m in exact_matches.get("exact", []) if scanner in m.get("found_in", []))
                fuzzy_count = sum(1 for m in fuzzy_matches.get("fuzzy", []) if m.get("scanner") == scanner or m.get("similar_to", {}).get("scanner") == scanner)
                unique_count = len(unique_packages.get(scanner, []))
                
                # Score: higher is better (more common packages)
                # Penalize excessive uniqueness slightly
                common_ratio = (exact_count + fuzzy_count * 0.5) / total_counts[scanner]
                unique_ratio = unique_count / total_counts[scanner]
                scores[scanner] = max(0, common_ratio * 100 - unique_ratio * 10)
            
            return {
                "common_packages": exact_matches,
                "fuzzy_matches": fuzzy_matches,
                "unique_packages": unique_packages,
                "total_counts": total_counts,
                "scores": scores
            }
        except Exception as e:
            logger.error(f"Error analyzing scan packages {scan_id}: {e}")
            import traceback
            logger.error(f"Full traceback: {traceback.format_exc()}")
            return {
                "common_packages": {"exact": []},
                "fuzzy_matches": {"fuzzy": []},
                "unique_packages": {},
                "total_counts": {},
                "scores": {},
                "error": str(e)
            }

# Global database service instance
db_service = DatabaseService()