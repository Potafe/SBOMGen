#TODO: implement below functions

# async def _handle_reruns(self, scan_id: str, repo_path: str):
#     scan = self.scans.get(scan_id)
#     if not scan:
#         return
    
#     tech_stack = scan.tech_stack or []
#     for sbom_result in [scan.trivy_sbom, scan.syft_sbom, scan.cdxgen_sbom]:
#         if sbom_result and sbom_result.component_count == 0:
#             commands = self._get_rerun_commands(sbom_result.scanner, tech_stack, repo_path)
#             await self.rerun_scanner(scan_id, sbom_result.scanner, commands, repo_path)

# def _get_rerun_commands(self, scanner: ScannerType, tech_stack: List[str], repo_path: str) -> List[str]:
#     # Cuurently some placeholder logic for rerun commands
#     commands = []
#     if "python" in tech_stack:
#         commands.extend(["pip install -r requirements.txt"])
#     if "nodejs" in tech_stack:
#         commands.extend(["npm install"])
#     return commands

# async def rerun_scanner(self, scan_id: str, scanner: ScannerType, repo_path: str, commands: Optional[List[str]] = None) -> bool:
#     scan = self.scans.get(scan_id)
#     if not scan:
#         return False

#     try:
#         if commands:
#             for cmd in commands:
#                 self.docker_client.containers.run(
#                     "alpine:latest",
#                     ["sh", "-c", cmd],
#                     working_dir=repo_path,
#                     detach=False
#                 )

#         result = await self._run_scanner(scan_id, scanner, repo_path)
#         result.rerun = True

#         if scanner == ScannerType.TRIVY:
#             scan.trivy_sbom = result
#         elif scanner == ScannerType.SYFT:
#             scan.syft_sbom = result
#         elif scanner == ScannerType.CDXGEN:
#             scan.cdxgen_sbom = result

#         return True
#     except Exception as e:
#         print(f"Rerun failed: {e}")
#         return False