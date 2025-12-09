"""
Docstring for backend.app.services.sbom_merge

This will basically take in all the common packages and the unique packages from all the scanners and merge it into a single sbom json (cyclonedx) file.

We will use cyclondx-cli for now for performing the merge part:

https://github.com/CycloneDX/cyclonedx-cli
    
    Merge Command
        merge
        Merge two or more BOMs

        Usage:
        cyclonedx merge [options]

        Options:
        --input-files <input-files>                           Input BOM filenames (separate filenames with a space).
        --output-file <output-file>                           Output BOM filename, will write to stdout if no value provided.
        --input-format <autodetect|json|protobuf|xml>         Specify input file format.
        --output-format <autodetect|json|protobuf|xml>        Specify output file format.
        --output-version <v1_0|v1_1|v1_2|v1_3|v1_4|v1_5|v1_6> Specify output BOM specification version.
        --hierarchical                                        Perform a hierarchical merge.
        --group <group>                                       Provide the group of software the merged BOM describes.
        --name <name>                                         Provide the name of software the merged BOM describes (required for hierarchical merging).
        --version <version>                                   Provide the version of software the merged BOM describes (required for hierarchical merging).

Later if we see the logic failing using cyclonedx-cli, we will write a seperate logic.
"""

import os
import json
import subprocess
import logging
import tempfile

from app.database import AsyncSessionLocal
from app.services.database_service import db_service

from sqlalchemy import text
from datetime import datetime
from typing import Dict, Optional, List, Any, Tuple

logger = logging.getLogger(__name__)

class SBOMMerge:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        # Common SPDX license identifiers (subset for validation)
        # Full list: https://spdx.org/licenses/
        self.valid_spdx_licenses = {
            "MIT", "Apache-2.0", "GPL-2.0", "GPL-3.0", "BSD-2-Clause", "BSD-3-Clause",
            "ISC", "LGPL-2.1", "LGPL-3.0", "MPL-2.0", "CDDL-1.0", "EPL-1.0", "EPL-2.0",
            "AGPL-3.0", "Unlicense", "CC0-1.0", "WTFPL", "Zlib", "BSL-1.0", "AFL-3.0",
            "Apache-1.1", "Artistic-2.0", "CC-BY-4.0", "CC-BY-SA-4.0", "PSF-2.0",
            "Python-2.0", "Ruby", "Vim", "0BSD", "BlueOak-1.0.0", "bzip2-1.0.6"
        }
    
    async def merge_sboms(self, scan_id: str, include_all_unique: bool = True, 
                         exclude_github_actions: bool = False) -> Dict[str, Any]:
        """
        Merge multiple SBOMs using intelligent custom merge logic.
        
        Args:
            scan_id: The scan identifier
            include_all_unique: Whether to include all unique packages (default: True)
            exclude_github_actions: Whether to exclude GitHub Actions packages (default: False)
            
        Returns:
            Dict containing the merged SBOM or error information
        """
        try:
            # Use custom merge as primary logic
            self.logger.info(f"Starting custom merge for scan {scan_id}")
            merged_sbom = await self._custom_merge(
                scan_id, 
                include_all_unique=include_all_unique,
                exclude_github_actions=exclude_github_actions
            )
            
            if merged_sbom and merged_sbom.get("components"):
                return merged_sbom
            
            return {
                "error": "Custom merge failed to produce valid SBOM",
                "details": "No components found"
            }
            
        except Exception as e:
            self.logger.error(f"Error merging SBOMs for scan {scan_id}: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return {"error": f"Merge failed: {str(e)}"}
    
    async def merge_sboms_with_selections(self, scan_id: str, 
                                         selected_unique_packages: Dict[str, list]) -> Dict[str, Any]:
        """
        Merge SBOMs with specific unique packages selected by the user.
        
        Args:
            scan_id: The scan identifier
            selected_unique_packages: Dict mapping scanner names to lists of selected packages
                Example: {
                    "syft": [{"name": "pkg1", "version": "1.0.0"}],
                    "trivy": [{"name": "pkg2", "version": "2.0.0"}]
                }
            
        Returns:
            Dict containing the merged SBOM or error information
        """
        try:
            self.logger.info(f"Starting custom merge with selections for scan {scan_id}")
            merged_sbom = await self._custom_merge_with_selections(
                scan_id, 
                selected_unique_packages
            )
            
            if merged_sbom and merged_sbom.get("components"):
                return merged_sbom
            
            return {
                "error": "Custom merge failed to produce valid SBOM",
                "details": "No components found"
            }
            
        except Exception as e:
            self.logger.error(f"Error merging SBOMs with selections for scan {scan_id}: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return {"error": f"Merge failed: {str(e)}"}
    
    async def _merge_with_cyclonedx_cli(self, scan_id: str, 
                                       valid_sboms: List[tuple]) -> Optional[Dict[str, Any]]:
        """
        Attempt to merge SBOMs using cyclonedx-cli.
        """
        temp_files = []
        try:
            for i, (sbom_data, scanner_name) in enumerate(valid_sboms):
                temp_file = tempfile.NamedTemporaryFile(
                    mode='w', suffix=f'-{scanner_name}.json', delete=False
                )
                json.dump(sbom_data, temp_file, indent=2)
                temp_file.close()
                temp_files.append(temp_file.name)
            
            output_file = tempfile.NamedTemporaryFile(
                mode='w', suffix='-merged.json', delete=False
            )
            output_file.close()
            
            cmd = [
                'cyclonedx', 'merge',
                '--input-files'
            ] + temp_files + [
                '--output-file', output_file.name,
                '--output-format', 'json',
                '--output-version', 'v1_6'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                with open(output_file.name, 'r') as f:
                    merged_data = json.load(f)
                
                merged_data['metadata'] = merged_data.get('metadata', {})
                tools = merged_data['metadata'].get('tools', [])
                if not isinstance(tools, list):
                    tools = []
                tools.append({
                    'vendor': 'SBOMGen',
                    'name': 'sbom-merger',
                    'version': '0.0.1'
                })
                merged_data['metadata']['tools'] = tools
                merged_data['metadata']['timestamp'] = datetime.now().isoformat()
                
                os.unlink(output_file.name)
                return merged_data
            else:
                self.logger.error(f"cyclonedx-cli error: {result.stderr}")
                return None
                
        except FileNotFoundError:
            self.logger.warning("cyclonedx-cli not found, will use custom merge")
            return None
        except Exception as e:
            self.logger.error(f"cyclonedx-cli merge error: {e}")
            return None
        finally:
            for temp_file in temp_files:
                try:
                    os.unlink(temp_file)
                except:
                    pass
    

    async def _custom_merge(self, scan_id: str, include_all_unique: bool = True, 
                          exclude_github_actions: bool = False) -> Dict[str, Any]:
        """
        Custom SBOM merge logic:
            This is now the default logic for merging the sbom.

            The logic of the sbom merge is like this:
                1. We select all the exact matched packages and add them to the new merged sbom.
                2. We try to rank the fuzzy matched packages and add them to the merge sbom:
                    a. The ranking can be done by either selecting the most common fuzzy matched packages.
                    b. We can also use some other better way of ranking the fuzzy matched packages and including them to the sbom.
                    c. Fallback logic can be to include all the fuzzy matched packages.
                3. For the unique packages, we provide options:
                    a. If we want to include all the unique packages, we do so.
                    b. Second option would be to exclude actions/ and other github workflow packages
                       and then add all the unique packages.
                4. We try to preserve all the relationships present in the SBOMs from the scanners.
                5. We provide the merged SBOM in CycloneDX format.
        """
        try:
            # Update match status first
            await db_service.update_match_status(scan_id)
            
            async with AsyncSessionLocal() as session:
                # Get all packages with their match status
                result = await session.execute(
                    text("""
                        SELECT 
                            name, version, purl, cpe, licenses, component_type, 
                            description, match_status, original_ref, scanner_name, "primary",
                            COUNT(*) OVER (PARTITION BY name, version) as occurrence_count
                        FROM packages 
                        WHERE scan_id = :scan_id
                        ORDER BY match_status DESC, occurrence_count DESC, name, version
                    """),
                    {"scan_id": scan_id}
                )
                packages_data = result.fetchall()
                
                # Log primary packages found in database
                primary_packages = [pkg for pkg in packages_data if pkg.primary == "true"]
                if primary_packages:
                    self.logger.info(f"Found {len(primary_packages)} primary packages in database:")
                    for pkg in primary_packages:
                        self.logger.info(f"  - {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name}, match_status: {pkg.match_status})")
                else:
                    self.logger.warning("No primary packages found in database for this scan")
                
                # Build merged components with intelligent selection
                merged_components = []
                seen_packages = set()
                package_id_map = {}  # Map (scanner, original_ref) to merged bom-ref
                primary_component = None  # Track primary package for metadata
                
                # FIRST PASS: Always include primary package regardless of match status
                for pkg in packages_data:
                    if pkg.primary == "true" and not primary_component:
                        pkg_key = (pkg.name, pkg.version)
                        if pkg_key not in seen_packages:
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            primary_component = component.copy()
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            self.logger.info(f"✓ Added PRIMARY package to merge: {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name}, match_status: {pkg.match_status})")
                            break  # Only one primary package
                
                # SECOND PASS: Process all other packages based on match status
                for pkg in packages_data:
                    pkg_key = (pkg.name, pkg.version)
                    
                    # Skip if already added (but still check for primary)
                    if pkg_key in seen_packages:
                        bom_ref = f"pkg:{pkg.purl}" if pkg.purl else f"{pkg.name}@{pkg.version}"
                        package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                        # Check if this duplicate is the primary package
                        if pkg.primary == "true" and not primary_component:
                            # Find the already-added component in merged_components
                            for comp in merged_components:
                                if comp.get("name") == pkg.name and comp.get("version") == pkg.version:
                                    primary_component = comp.copy()
                                    self.logger.info(f"✓ Captured PRIMARY component (duplicate entry): {pkg.name}@{pkg.version} from scanner={pkg.scanner_name}")
                                    break
                        continue
                    
                    # Step 1: Always include exact matches
                    if pkg.match_status == "exact":
                        # Skip GitHub Actions packages (unsupported by analyzers)
                        if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                            continue
                        seen_packages.add(pkg_key)
                        component = self._build_component(pkg)
                        merged_components.append(component)
                        bom_ref = component["bom-ref"]
                        package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                        # Track primary package
                        if pkg.primary == "true" and not primary_component:
                            primary_component = component.copy()
                            self.logger.info(f"Captured PRIMARY component (exact match): {pkg.name}@{pkg.version} from scanner={pkg.scanner_name}")
                        continue
                    
                    # Step 2: Include fuzzy matches (higher occurrence = more likely to be correct)
                    if pkg.match_status == "fuzzy":
                        if pkg.occurrence_count >= 2:  # Found by at least 2 scanners
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            # Track primary package
                            if pkg.primary == "true" and not primary_component:
                                primary_component = component.copy()
                                self.logger.info(f"✓ Captured PRIMARY component (fuzzy match): {pkg.name}@{pkg.version} from scanner={pkg.scanner_name}")
                        continue
                    
                    # Step 3: Handle unique packages based on options
                    if pkg.match_status == "unique":
                        # Option to exclude GitHub Actions packages
                        if exclude_github_actions and self._is_github_action_package(pkg.name):
                            continue
                        
                        # Include all unique packages if option is set
                        if include_all_unique:
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            # Track primary package
                            if pkg.primary == "true" and not primary_component:
                                primary_component = component.copy()
                                self.logger.info(f"✓ Captured PRIMARY component (unique): {pkg.name}@{pkg.version} from scanner={pkg.scanner_name}")
                
                # Step 4: Preserve all relationships (dependencies)
                dep_result = await session.execute(
                    text("""
                        SELECT DISTINCT
                            d.parent_id, d.child_id, d.normalized_type,
                            p1.original_ref as parent_ref, p1.scanner_name as parent_scanner,
                            p2.original_ref as child_ref, p2.scanner_name as child_scanner
                        FROM dependencies d
                        JOIN packages p1 ON d.parent_id = p1.id
                        JOIN packages p2 ON d.child_id = p2.id
                        WHERE d.scan_id = :scan_id
                    """),
                    {"scan_id": scan_id}
                )
                dependencies_data = dep_result.fetchall()
                
                # Build merged dependencies
                merged_dependencies = []
                seen_deps = set()
                
                for dep in dependencies_data:
                    parent_bom_ref = package_id_map.get((dep.parent_scanner, dep.parent_ref))
                    child_bom_ref = package_id_map.get((dep.child_scanner, dep.child_ref))
                    
                    # Only include dependency if both parent and child are in merged components
                    if not parent_bom_ref or not child_bom_ref:
                        continue
                    
                    dep_key = (parent_bom_ref, child_bom_ref)
                    if dep_key in seen_deps:
                        continue
                    
                    seen_deps.add(dep_key)
                    merged_dependencies.append({
                        "ref": parent_bom_ref,
                        "dependsOn": [child_bom_ref]
                    })
                
                # Consolidate dependencies (group by ref)
                consolidated_deps = {}
                for dep in merged_dependencies:
                    ref = dep["ref"]
                    if ref not in consolidated_deps:
                        consolidated_deps[ref] = {"ref": ref, "dependsOn": []}
                    consolidated_deps[ref]["dependsOn"].extend(dep["dependsOn"])
                
                # Deduplicate dependsOn lists
                for ref in consolidated_deps:
                    consolidated_deps[ref]["dependsOn"] = list(set(consolidated_deps[ref]["dependsOn"]))
                
                # Step 5: Build final merged SBOM in CycloneDX format
                metadata = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "tools": [
                        {
                            "vendor": "SBOMGen",
                            "name": "SBOM Custom Merge Tool",
                            "version": "1.0.0"
                        }
                    ],
                    "properties": [
                        {
                            "name": "sbomgen:scan_id",
                            "value": scan_id
                        },
                        {
                            "name": "sbomgen:total_components",
                            "value": str(len(merged_components))
                        },
                        {
                            "name": "sbomgen:total_dependencies",
                            "value": str(len(consolidated_deps))
                        },
                        {
                            "name": "sbomgen:include_all_unique",
                            "value": str(include_all_unique)
                        },
                        {
                            "name": "sbomgen:exclude_github_actions",
                            "value": str(exclude_github_actions)
                        }
                    ]
                }
                
                # Add primary component to metadata if found
                if primary_component:
                    metadata["component"] = primary_component
                    self.logger.info(f"Added PRIMARY component to merged SBOM metadata: {primary_component.get('name')}@{primary_component.get('version')}")
                else:
                    self.logger.warning(f"No PRIMARY component found for scan {scan_id} - merged SBOM will not have metadata.component")
                
                merged_sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "metadata": metadata,
                    "components": merged_components,
                    "dependencies": list(consolidated_deps.values())
                }
                
                # Save merged SBOM to database
                await session.execute(
                    text("""
                        UPDATE scan_results 
                        SET merged_sbom = :merged_sbom 
                        WHERE scan_id = :scan_id
                    """),
                    {"scan_id": scan_id, "merged_sbom": json.dumps(merged_sbom)}
                )
                await session.commit()
                
                self.logger.info(
                    f"Custom merged SBOM for scan {scan_id}: "
                    f"{len(merged_components)} components, "
                    f"{len(consolidated_deps)} dependencies"
                )
                return merged_sbom
                
        except Exception as e:
            self.logger.error(f"Error in custom merge for scan {scan_id}: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return {}
    
    async def _custom_merge_with_selections(self, scan_id: str, 
                                           selected_unique_packages: Dict[str, list]) -> Dict[str, Any]:
        """
        Custom SBOM merge with user-selected unique packages.
        
        Args:
            scan_id: The scan identifier
            selected_unique_packages: Dict mapping scanner names to lists of selected packages
        """
        try:
            # Update match status first
            await db_service.update_match_status(scan_id)
            
            # Convert selected packages to a set for quick lookup
            selected_pkg_keys = set()
            for scanner, packages in selected_unique_packages.items():
                for pkg in packages:
                    selected_pkg_keys.add((scanner, pkg["name"], pkg["version"]))
            
            async with AsyncSessionLocal() as session:
                # Get all packages with their match status
                result = await session.execute(
                    text("""
                        SELECT 
                            name, version, purl, cpe, licenses, component_type, 
                            description, match_status, original_ref, scanner_name, "primary",
                            COUNT(*) OVER (PARTITION BY name, version) as occurrence_count
                        FROM packages 
                        WHERE scan_id = :scan_id
                        ORDER BY match_status DESC, occurrence_count DESC, name, version
                    """),
                    {"scan_id": scan_id}
                )
                packages_data = result.fetchall()
                
                # Log primary packages found in database
                primary_packages = [pkg for pkg in packages_data if pkg.primary == "true"]
                if primary_packages:
                    logger.info(f"Found {len(primary_packages)} primary packages in database:")
                    for pkg in primary_packages:
                        logger.info(f"  - {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name}, match_status: {pkg.match_status})")
                else:
                    logger.warning("No primary packages found in database for this scan")
                
                # Build merged components with user selections
                merged_components = []
                seen_packages = set()
                package_id_map = {}  # Map (scanner, original_ref) to merged bom-ref
                primary_component = None  # Track primary package for metadata
                
                # FIRST PASS: Always include primary package regardless of match status or selections
                for pkg in packages_data:
                    if pkg.primary == "true" and not primary_component:
                        pkg_key = (pkg.name, pkg.version)
                        if pkg_key not in seen_packages:
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            primary_component = component.copy()
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            logger.info(f"✓ Added PRIMARY package to merge: {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name}, match_status: {pkg.match_status})")
                            break  # Only one primary package
                
                # SECOND PASS: Process all other packages based on match status and selections
                for pkg in packages_data:
                    pkg_key = (pkg.name, pkg.version)
                    
                    # Skip if already added (but still check for primary)
                    if pkg_key in seen_packages:
                        bom_ref = f"pkg:{pkg.purl}" if pkg.purl else f"{pkg.name}@{pkg.version}"
                        package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                        # Check if this duplicate is the primary package
                        if pkg.primary == "true" and not primary_component:
                            # Find the already-added component in merged_components
                            for comp in merged_components:
                                if comp.get("name") == pkg.name and comp.get("version") == pkg.version:
                                    primary_component = comp.copy()
                                    logger.info(f"✓ Captured PRIMARY component (duplicate entry): {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name})")
                                    break
                        continue
                    
                    # Always include exact matches
                    if pkg.match_status == "exact":
                        # Skip GitHub Actions packages (unsupported by analyzers)
                        if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                            continue
                        seen_packages.add(pkg_key)
                        component = self._build_component(pkg)
                        merged_components.append(component)
                        bom_ref = component["bom-ref"]
                        package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                        # Track primary package
                        if pkg.primary == "true" and not primary_component:
                            primary_component = component.copy()
                            logger.info(f"✓ Captured PRIMARY component from exact match: {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name})")
                        continue
                    
                    # Include fuzzy matches (higher occurrence = more likely correct)
                    if pkg.match_status == "fuzzy":
                        if pkg.occurrence_count >= 2:
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            # Track primary package
                            if pkg.primary == "true" and not primary_component:
                                primary_component = component.copy()
                                logger.info(f"✓ Captured PRIMARY component from fuzzy match: {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name})")
                        continue
                    
                    # Only include unique packages if user selected them
                    if pkg.match_status == "unique":
                        selection_key = (pkg.scanner_name, pkg.name, pkg.version)
                        if selection_key in selected_pkg_keys:
                            # Skip GitHub Actions packages (unsupported by analyzers)
                            if pkg.purl and 'pkg:githubactions' in pkg.purl.lower():
                                continue
                            seen_packages.add(pkg_key)
                            component = self._build_component(pkg)
                            merged_components.append(component)
                            bom_ref = component["bom-ref"]
                            package_id_map[(pkg.scanner_name, pkg.original_ref)] = bom_ref
                            # Track primary package
                            if pkg.primary == "true" and not primary_component:
                                primary_component = component.copy()
                                logger.info(f"✓ Captured PRIMARY component from unique match: {pkg.name}@{pkg.version} (scanner: {pkg.scanner_name})")
                
                # Preserve all relationships (dependencies)
                dep_result = await session.execute(
                    text("""
                        SELECT DISTINCT
                            d.parent_id, d.child_id, d.normalized_type,
                            p1.original_ref as parent_ref, p1.scanner_name as parent_scanner,
                            p2.original_ref as child_ref, p2.scanner_name as child_scanner
                        FROM dependencies d
                        JOIN packages p1 ON d.parent_id = p1.id
                        JOIN packages p2 ON d.child_id = p2.id
                        WHERE d.scan_id = :scan_id
                    """),
                    {"scan_id": scan_id}
                )
                dependencies_data = dep_result.fetchall()
                
                # Build merged dependencies
                merged_dependencies = []
                seen_deps = set()
                
                for dep in dependencies_data:
                    parent_bom_ref = package_id_map.get((dep.parent_scanner, dep.parent_ref))
                    child_bom_ref = package_id_map.get((dep.child_scanner, dep.child_ref))
                    
                    if not parent_bom_ref or not child_bom_ref:
                        continue
                    
                    dep_key = (parent_bom_ref, child_bom_ref)
                    if dep_key in seen_deps:
                        continue
                    
                    seen_deps.add(dep_key)
                    merged_dependencies.append({
                        "ref": parent_bom_ref,
                        "dependsOn": [child_bom_ref]
                    })
                
                # Consolidate dependencies
                consolidated_deps = {}
                for dep in merged_dependencies:
                    ref = dep["ref"]
                    if ref not in consolidated_deps:
                        consolidated_deps[ref] = {"ref": ref, "dependsOn": []}
                    consolidated_deps[ref]["dependsOn"].extend(dep["dependsOn"])
                
                for ref in consolidated_deps:
                    consolidated_deps[ref]["dependsOn"] = list(set(consolidated_deps[ref]["dependsOn"]))
                
                # Build final merged SBOM
                metadata = {
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "tools": [
                        {
                            "vendor": "SBOMGen",
                            "name": "SBOM Custom Merge Tool",
                            "version": "1.0.0"
                        }
                    ],
                    "properties": [
                        {
                            "name": "sbomgen:scan_id",
                            "value": scan_id
                        },
                        {
                            "name": "sbomgen:total_components",
                            "value": str(len(merged_components))
                        },
                        {
                            "name": "sbomgen:total_dependencies",
                            "value": str(len(consolidated_deps))
                        },
                        {
                            "name": "sbomgen:merge_type",
                            "value": "user_selected"
                        }
                    ]
                }
                
                # Add primary component to metadata if found
                if primary_component:
                    metadata["component"] = primary_component
                    logger.info(f"✓ Added PRIMARY component to merged SBOM metadata: {primary_component.get('name')}@{primary_component.get('version')}")
                else:
                    logger.warning("⚠ No primary component was captured during merge - metadata.component will be missing")
                
                merged_sbom = {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "metadata": metadata,
                    "components": merged_components,
                    "dependencies": list(consolidated_deps.values())
                }
                
                # Save to database
                await session.execute(
                    text("""
                        UPDATE scan_results 
                        SET merged_sbom = :merged_sbom 
                        WHERE scan_id = :scan_id
                    """),
                    {"scan_id": scan_id, "merged_sbom": json.dumps(merged_sbom)}
                )
                await session.commit()
                
                self.logger.info(
                    f"Custom merged SBOM with selections for scan {scan_id}: "
                    f"{len(merged_components)} components, "
                    f"{len(consolidated_deps)} dependencies"
                )
                return merged_sbom
                
        except Exception as e:
            self.logger.error(f"Error in custom merge with selections for scan {scan_id}: {e}")
            import traceback
            self.logger.error(f"Full traceback: {traceback.format_exc()}")
            return {}
    
    def _build_component(self, pkg) -> Dict[str, Any]:
        """Build a CycloneDX component from package data."""
        bom_ref = f"pkg:{pkg.purl}" if pkg.purl else f"{pkg.name}@{pkg.version}"
        
        component = {
            "bom-ref": bom_ref,
            "type": pkg.component_type or "library",
            "name": pkg.name,
            "version": pkg.version
        }
        
        if pkg.purl:
            component["purl"] = pkg.purl
        
        if pkg.cpe:
            component["cpe"] = pkg.cpe
        
        if pkg.description:
            component["description"] = pkg.description
        
        # Parse and add licenses (filter out invalid SPDX identifiers)
        if pkg.licenses:
            try:
                licenses_list = json.loads(pkg.licenses)
                if licenses_list:
                    # Validate and filter licenses
                    valid_licenses = []
                    for lic in licenses_list:
                        if self._is_valid_spdx_license(lic):
                            valid_licenses.append({"license": {"id": lic}})
                        else:
                            # Use license name instead of id for non-SPDX licenses
                            valid_licenses.append({"license": {"name": lic}})
                    
                    if valid_licenses:
                        component["licenses"] = valid_licenses
            except:
                pass
        
        # Add metadata about merge
        component["properties"] = [
            {
                "name": "sbomgen:match_status",
                "value": pkg.match_status
            },
            {
                "name": "sbomgen:occurrence_count",
                "value": str(pkg.occurrence_count)
            },
            {
                "name": "sbomgen:scanner_name",
                "value": pkg.scanner_name
            }
        ]
        
        return component
    
    def _is_valid_spdx_license(self, license_id: str) -> bool:
        """
        Check if a license identifier is a valid SPDX license.
        Returns True if valid, False otherwise.
        """
        if not license_id:
            return False
        
        # Check against known SPDX licenses
        # Also accept licenses with -only or -or-later suffixes (e.g., GPL-2.0-only)
        base_license = license_id.replace("-only", "").replace("-or-later", "")
        
        return (
            license_id in self.valid_spdx_licenses or 
            base_license in self.valid_spdx_licenses or
            license_id.startswith("LicenseRef-")  # Custom license references are valid
        )
    
    def _is_github_action_package(self, package_name: str = None, package_dict: dict = None) -> bool:
        """Check if a package is a GitHub Actions workflow package."""
        # Check by purl if package dict is provided
        if package_dict:
            purl = package_dict.get('purl', '')
            if 'pkg:githubactions' in purl.lower():
                return True
            package_name = package_dict.get('name', '')
        
        if not package_name:
            return False
            
        github_action_patterns = [
            "actions/",
            "github/",
            ".github/",
            "workflow/",
            "action-",
            "/app/temp",
            "app/temp",
            "temp",
            ".yaml",
            "setup",
            "com.github",

        ]
        package_lower = package_name.lower()
        return any(pattern in package_lower for pattern in github_action_patterns)
