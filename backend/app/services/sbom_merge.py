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

from datetime import datetime
from typing import Dict, Optional, List, Any, Tuple

logger = logging.getLogger(__name__)

class SBOMMerge:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    async def merge_sboms(self, scan_id: str, sbom_data_list: List[Dict[str, Any]], 
                         scanner_names: List[str]) -> Dict[str, Any]:
        """
        Merge multiple SBOMs using cyclonedx-cli.
        
        Args:
            scan_id: The scan identifier
            sbom_data_list: List of SBOM data dictionaries
            scanner_names: List of scanner names corresponding to SBOMs
            
        Returns:
            Dict containing the merged SBOM or error information
        """
        try:
            valid_sboms = [(sbom, name) for sbom, name in zip(sbom_data_list, scanner_names) 
                          if sbom and sbom.get('components')]
            
            if len(valid_sboms) < 2:
                return {
                    "error": "Need at least 2 valid SBOMs to merge",
                    "available_sboms": len(valid_sboms)
                }
            
            merged_sbom = await self._merge_with_cyclonedx_cli(scan_id, valid_sboms)
            
            if merged_sbom:
                return merged_sbom
            
            # self.logger.warning("cyclonedx-cli merge failed, falling back to custom merge")
            # return await self._custom_merge(scan_id, valid_sboms)
            
        except Exception as e:
            self.logger.error(f"Error merging SBOMs for scan {scan_id}: {e}")
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
                '--input-files', ' '.join(temp_files),
                '--output-file', output_file.name,
                '--output-format', 'json',
                '--output-version', 'v1_5'
            ]
            
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60
            )
            
            if result.returncode == 0:
                with open(output_file.name, 'r') as f:
                    merged_data = json.load(f)
                
                merged_data['metadata'] = merged_data.get('metadata', {})
                merged_data['metadata']['tools'] = merged_data['metadata'].get('tools', [])
                merged_data['metadata']['tools'].append({
                    'vendor': 'SBOMGen',
                    'name': 'sbom-merger',
                    'version': '1.0.0'
                })
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
    
    async def _custom_merge(self, scan_id: str, 
                           valid_sboms: List[tuple]) -> Dict[str, Any]:
        """
        Custom SBOM merge logic as fallback.
        """
        merged_components = {}
        merged_dependencies = []
        scanner_sources = []
        
        base_sbom = valid_sboms[0][0]
        
        merged_sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{scan_id}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now().isoformat(),
                "tools": [
                    {
                        "vendor": "SBOMGen",
                        "name": "custom-sbom-merger",
                        "version": "1.0.0"
                    }
                ],
                "component": base_sbom.get('metadata', {}).get('component', {})
            },
            "components": [],
            "dependencies": []
        }
        
        for sbom_data, scanner_name in valid_sboms:
            scanner_sources.append(scanner_name)
            
            for component in sbom_data.get('components', []):
                purl = component.get('purl', '')
                name = component.get('name', '')
                version = component.get('version', '')
                
                if purl:
                    key = purl
                else:
                    key = f"{name}@{version}"
                
                if key in merged_components:
                    existing = merged_components[key]
                    
                    existing_licenses = set(
                        lic.get('license', {}).get('id', '') 
                        for lic in existing.get('licenses', [])
                    )
                    new_licenses = set(
                        lic.get('license', {}).get('id', '') 
                        for lic in component.get('licenses', [])
                    )
                    all_licenses = existing_licenses.union(new_licenses)
                    if all_licenses:
                        existing['licenses'] = [
                            {'license': {'id': lic_id}} 
                            for lic_id in all_licenses if lic_id
                        ]
                    
                    if 'properties' not in existing:
                        existing['properties'] = []
                    
                    existing['properties'].append({
                        'name': 'sbom:source_scanner',
                        'value': scanner_name
                    })
                    
                else:
                    new_component = component.copy()
                    if 'properties' not in new_component:
                        new_component['properties'] = []
                    
                    new_component['properties'].append({
                        'name': 'sbom:source_scanner',
                        'value': scanner_name
                    })
                    
                    merged_components[key] = new_component
            
            for dep in sbom_data.get('dependencies', []):
                if dep not in merged_dependencies:
                    merged_dependencies.append(dep)
        
        merged_sbom['components'] = list(merged_components.values())
        merged_sbom['dependencies'] = merged_dependencies
        
        merged_sbom['metadata']['properties'] = [
            {
                'name': 'sbom:merge_source_scanners',
                'value': ','.join(scanner_sources)
            },
            {
                'name': 'sbom:total_components',
                'value': str(len(merged_sbom['components']))
            },
            {
                'name': 'sbom:scan_id',
                'value': scan_id
            }
        ]
        
        return merged_sbom