from typing import Dict, List, Any, Tuple
from app.schemas.scan import ScannerType
import json


class PackageAnalyze:
    """
    Package analyzer - handles extraction of packages, dependencies, and graph generation.
    All comparison logic moved to DatabaseService for SQL-based analysis.
    """
    
    def extract_packages(self, sbom_data: Dict, scanner: ScannerType) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
        """
        Extract package data and dependencies from CycloneDX SBOM.
        Returns: (packages_list, dependencies_list)
        """
        packages = []
        dependencies = []
        
        # Identify primary package from metadata.component
        primary_bom_ref = None
        metadata = sbom_data.get("metadata", {})
        if "component" in metadata:
            primary_component = metadata["component"]
            primary_bom_ref = primary_component.get("bom-ref") or primary_component.get("purl") or f"{primary_component.get('name', '')}@{primary_component.get('version', '')}"
            import logging
            logger = logging.getLogger(__name__)
            logger.info(f"Found primary package in CycloneDX metadata: {primary_bom_ref}")
        
        # Extract components
        for component in sbom_data.get("components", []):
            name = component.get("name", "").strip()
            version = component.get("version", "").strip()
            purl = component.get("purl", "").strip()
            bom_ref = component.get("bom-ref", purl or f"{name}@{version}").strip()
            
            # Extract CPE
            cpe = ""
            if "cpe" in component:
                cpe = component["cpe"].strip()
            elif "externalReferences" in component:
                for ref in component["externalReferences"]:
                    if ref.get("type") == "cpe22Type" or ref.get("type") == "cpe23Type":
                        cpe = ref.get("url", "").strip()
                        break
            
            # Extract licenses
            licenses = []
            for lic in component.get("licenses", []):
                if "license" in lic:
                    if "id" in lic["license"]:
                        licenses.append(lic["license"]["id"])
                    elif "name" in lic["license"]:
                        licenses.append(lic["license"]["name"])
            
            if name:
                # Check if this is the primary package
                is_primary = "true" if (primary_bom_ref and bom_ref == primary_bom_ref) else "false"
                
                if is_primary == "true":
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.info(f"Marking package as primary: {name}@{version} (bom-ref: {bom_ref})")
                
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe,
                    "original_ref": bom_ref,
                    "licenses": json.dumps(licenses) if licenses else "",
                    "component_type": component.get("type", "library"),
                    "description": component.get("description", "").strip(),
                    "primary": is_primary
                })
        
        # Extract dependencies
        for dep in sbom_data.get("dependencies", []):
            parent_ref = dep.get("ref", "").strip()
            if not parent_ref:
                continue
            
            for child_ref in dep.get("dependsOn", []):
                if child_ref:
                    dependencies.append({
                        "parent_ref": parent_ref,
                        "child_ref": child_ref,
                        "original_type": "DEPENDS_ON",
                        "normalized_type": "functional"
                    })
        
        return packages, dependencies
    
    def extract_spdx_packages(self, spdx_data: Dict, scanner: ScannerType) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
        """
        Extract package data and relationships from SPDX format SBOM.
        Supports SPDX 2.x format (including 2.3 from GitHub).
        Returns: (packages_list, dependencies_list)
        """
        packages = []
        dependencies = []
        
        # Identify primary package from DESCRIBES relationship
        primary_spdx_id = None
        for rel in spdx_data.get("relationships", []):
            if rel.get("relationshipType") == "DESCRIBES" and rel.get("spdxElementId") == "SPDXRef-DOCUMENT":
                primary_spdx_id = rel.get("relatedSpdxElement")
                import logging
                logger = logging.getLogger(__name__)
                logger.info(f"Found primary package in SPDX DESCRIBES relationship: {primary_spdx_id}")
                break
        
        # Map SPDXID to package for relationship resolution
        spdxid_map = {}
        
        # SPDX stores packages in the "packages" array
        for package in spdx_data.get("packages", []):
            name = package.get("name", "").strip()
            version = package.get("versionInfo", "").strip()
            spdx_id = package.get("SPDXID", "").strip()
            
            # Extract PURL and CPE from externalRefs
            purl = ""
            cpe = ""
            for ref in package.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                if ref_type == "purl":
                    purl = ref.get("referenceLocator", "").strip()
                elif ref_type in ["cpe22Type", "cpe23Type"]:
                    cpe = ref.get("referenceLocator", "").strip()
            
            # Extract licenses
            licenses = []
            concluded_license = package.get("licenseConcluded", "")
            if concluded_license and concluded_license != "NOASSERTION":
                licenses.append(concluded_license)
            declared_license = package.get("licenseDeclared", "")
            if declared_license and declared_license != "NOASSERTION" and declared_license not in licenses:
                licenses.append(declared_license)
            
            # Extract component type from primaryPackagePurpose
            component_type = "library"  # Default
            primary_purpose = package.get("primaryPackagePurpose", "").upper()
            if primary_purpose:
                # Map SPDX primaryPackagePurpose to CycloneDX component type
                purpose_map = {
                    "APPLICATION": "application",
                    "FRAMEWORK": "framework",
                    "LIBRARY": "library",
                    "CONTAINER": "container",
                    "OPERATING-SYSTEM": "operating-system",
                    "DEVICE": "device",
                    "FIRMWARE": "firmware",
                    "FILE": "file",
                    "SOURCE": "library",  # Map to library
                    "ARCHIVE": "library",  # Map to library
                    "INSTALL": "library",  # Map to library
                    "OTHER": "library"  # Map to library
                }
                component_type = purpose_map.get(primary_purpose, "library")
            
            if name:
                # Check if this is the primary package
                is_primary = "true" if (primary_spdx_id and spdx_id == primary_spdx_id) else "false"
                
                if is_primary == "true":
                    import logging
                    logger = logging.getLogger(__name__)
                    logger.info(f"Marking package as primary: {name}@{version} (SPDXID: {spdx_id})")
                
                pkg_data = {
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe,
                    "original_ref": spdx_id,
                    "licenses": json.dumps(licenses) if licenses else "",
                    "component_type": component_type,
                    "description": package.get("description", "").strip(),
                    "primary": is_primary
                }
                packages.append(pkg_data)
                spdxid_map[spdx_id] = pkg_data
        
        # Extract relationships
        for rel in spdx_data.get("relationships", []):
            rel_type = rel.get("relationshipType", "").strip()
            spdx_element = rel.get("spdxElementId", "").strip()
            related_element = rel.get("relatedSpdxElement", "").strip()
            
            # Map SPDX relationship types to normalized types
            normalized_type = self._normalize_spdx_relationship(rel_type)
            
            if normalized_type and spdx_element and related_element:
                # For DEPENDS_ON, parent depends on child
                if rel_type in ["DEPENDS_ON", "DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF", "BUILD_DEPENDENCY_OF", "DEV_DEPENDENCY_OF"]:
                    dependencies.append({
                        "parent_ref": spdx_element,
                        "child_ref": related_element,
                        "original_type": rel_type,
                        "normalized_type": normalized_type
                    })
        
        return packages, dependencies
    
    def _normalize_spdx_relationship(self, rel_type: str) -> str:
        """Normalize SPDX relationship types to simplified categories."""
        rel_type = rel_type.upper()
        
        if rel_type in ["DEPENDS_ON", "DEPENDENCY_OF", "RUNTIME_DEPENDENCY_OF"]:
            return "functional"
        elif rel_type in ["BUILD_DEPENDENCY_OF", "BUILD_TOOL_OF"]:
            return "build"
        elif rel_type in ["DEV_DEPENDENCY_OF", "TEST_DEPENDENCY_OF", "TEST_TOOL_OF"]:
            return "dev"
        elif rel_type in ["OPTIONAL_DEPENDENCY_OF"]:
            return "optional"
        else:
            return ""
    
    def parse_sbom_graph(self, sbom_data: Dict) -> Dict[str, Any]:
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
