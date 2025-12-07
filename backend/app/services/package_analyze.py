from typing import Dict, List, Any
from app.schemas.scan import ScannerType


class PackageAnalyze:
    """
    Simplified package analyzer - handles only extraction and graph generation.
    All comparison logic moved to DatabaseService for SQL-based analysis.
    """
    
    def extract_packages(self, sbom_data: Dict, scanner: ScannerType) -> List[Dict[str, str]]:
        """
        Extract package data with name, version, purl, and cpe from SBOM data.
        Does NOT deduplicate - returns all packages as-is from the scanner.
        """
        packages = []
        for component in sbom_data.get("components", []):
            name = component.get("name", "").strip()
            version = component.get("version", "").strip()
            purl = component.get("purl", "").strip()
            
            cpe = ""
            if "cpe" in component:
                cpe = component["cpe"].strip()
            elif "externalReferences" in component:
                for ref in component["externalReferences"]:
                    if ref.get("type") == "cpe22Type" or ref.get("type") == "cpe23Type":
                        cpe = ref.get("url", "").strip()
                        break
            
            if name:
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe
                })
        
        return packages
    
    def extract_spdx_packages(self, spdx_data: Dict, scanner: ScannerType) -> List[Dict[str, str]]:
        """
        Extract package data from SPDX format SBOM.
        Supports SPDX 2.x format (including 2.3 from GitHub).
        Does NOT deduplicate - returns all packages as-is.
        """
        packages = []
        
        # SPDX stores packages in the "packages" array
        for package in spdx_data.get("packages", []):
            name = package.get("name", "").strip()
            version = package.get("versionInfo", "").strip()
            
            # Extract PURL if available in externalRefs
            purl = ""
            cpe = ""
            for ref in package.get("externalRefs", []):
                ref_type = ref.get("referenceType", "")
                if ref_type == "purl":
                    purl = ref.get("referenceLocator", "").strip()
                elif ref_type in ["cpe22Type", "cpe23Type"]:
                    cpe = ref.get("referenceLocator", "").strip()
            
            if name:
                packages.append({
                    "name": name,
                    "version": version,
                    "purl": purl,
                    "cpe": cpe
                })
        
        return packages
    
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
