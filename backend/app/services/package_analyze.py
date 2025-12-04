from typing import Dict, List, Any
import difflib
from collections import defaultdict
from app.schemas.scan import ScannerType


class PackageAnalyze:
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
        
        # Group packages by unique key and track duplicates per scanner
        package_groups = defaultdict(lambda: defaultdict(int))  # pkg_key -> {scanner_idx: count}
        package_details = {}  # pkg_key -> package details
        
        for i, packages in enumerate(packages_list):
            for pkg in packages:
                pkg_key = (pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"])
                package_groups[pkg_key][i] += 1
                if pkg_key not in package_details:
                    package_details[pkg_key] = pkg
        
        # Find packages that appear in multiple scanners
        for pkg_key, scanner_counts in package_groups.items():
            if len(scanner_counts) > 1:  # Found in multiple scanners
                pkg = package_details[pkg_key]
                found_in_scanners = list(scanner_counts.keys())
                duplicate_counts = {scanner_names[i]: count for i, count in scanner_counts.items()}
                
                common["exact"].append({
                    "name": pkg["name"],
                    "version": pkg["version"],
                    "purl": pkg["purl"],
                    "cpe": pkg["cpe"],
                    "found_in": [scanner_names[i] for i in found_in_scanners],
                    "duplicate_counts": duplicate_counts,
                    "has_duplicates": any(count > 1 for count in scanner_counts.values()),
                    "match_type": "exact",
                    "match_scores": {"name": 1.0, "version": 1.0, "purl": 1.0, "cpe": 1.0, "overall": 1.0}
                })
        
        # Get exact packages to avoid duplicating them in fuzzy matches
        exact_packages = set()
        for item in common["exact"]:
            exact_packages.add((item["name"], item["version"], item["purl"], item["cpe"]))
        
        # Find fuzzy matches between different scanners
        for i in range(len(packages_list)):
            for j in range(i+1, len(packages_list)):
                # Get unique packages from each scanner for fuzzy matching
                unique_i = {}
                unique_j = {}
                
                for pkg in packages_list[i]:
                    pkg_key = (pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"])
                    if pkg_key not in exact_packages:
                        unique_i[pkg_key] = pkg
                
                for pkg in packages_list[j]:
                    pkg_key = (pkg["name"], pkg["version"], pkg["purl"], pkg["cpe"])
                    if pkg_key not in exact_packages:
                        unique_j[pkg_key] = pkg
                
                for pkg1_key, pkg1 in unique_i.items():
                    for pkg2_key, pkg2 in unique_j.items():
                        match_scores = self._calculate_match_score(pkg1, pkg2)
                        
                        # Consider it a fuzzy match if overall score > 0.7
                        if match_scores["overall"] > 0.7:
                            already_exists = any(
                                (f["name"] == pkg1["name"] and f["version"] == pkg1["version"]) or
                                (f["name"] == pkg2["name"] and f["version"] == pkg2["version"])
                                for f in common["fuzzy"]
                            )
                            
                            if not already_exists:
                                # Check for duplicates in the original scanners
                                pkg1_duplicates = sum(1 for p in packages_list[i] if 
                                    (p["name"], p["version"], p["purl"], p["cpe"]) == pkg1_key)
                                pkg2_duplicates = sum(1 for p in packages_list[j] if 
                                    (p["name"], p["version"], p["purl"], p["cpe"]) == pkg2_key)
                                
                                duplicate_counts = {}
                                if pkg1_duplicates > 0:
                                    duplicate_counts[scanner_names[i]] = pkg1_duplicates
                                if pkg2_duplicates > 0:
                                    duplicate_counts[scanner_names[j]] = pkg2_duplicates
                                
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
                                    "duplicate_counts": duplicate_counts,
                                    "has_duplicates": any(count > 1 for count in duplicate_counts.values()),
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