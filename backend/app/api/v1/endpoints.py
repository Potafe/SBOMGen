import os

from fastapi import (
    APIRouter, HTTPException, 
    BackgroundTasks, File, 
    UploadFile, Form 
)
from fastapi.responses import JSONResponse
from typing import Dict, Any, Optional
from app.schemas.scan import (
    RepositoryUpload, ScanResponse, 
    ScannerType, ScanResults, 
    RerunRequest, ScanStatus, 
    SBOMFormat, SBOMUploadResponse
)
from app.services.sbom_service import SBOMService
from app.services.sbom_merge import SBOMMerge
from app.services.cpe_service import cpe_service
from app.core.config import settings

router = APIRouter()

sbom_service = SBOMService()
sbom_merge = SBOMMerge()

@router.post("/upload-repository", response_model=ScanResponse)
async def upload_repository(
    background_tasks: BackgroundTasks,
    repo_url: str = Form(...),
    github_token: Optional[str] = Form(None),
    bd_project_name: Optional[str] = Form(None),
    bd_project_version: Optional[str] = Form(None),
    bd_api_token: Optional[str] = Form(None),
    uploaded_sbom_format: Optional[str] = Form(None),
    uploaded_sbom_file: Optional[UploadFile] = File(None)
) -> ScanResponse:
    """
    Upload a GitHub repository URL and initiate scanning.
    Optionally provide:
    - Black Duck project details to fetch SBOM from Black Duck
    - An SBOM file to compare with scanner results
    """
    try:
        # Read uploaded SBOM file if provided
        uploaded_sbom_content = None
        if uploaded_sbom_file:
            uploaded_sbom_content = await uploaded_sbom_file.read()
        
        scan_id = await sbom_service.start_scan(
            repo_url, 
            github_token,
            bd_project_name,
            bd_project_version,
            bd_api_token
        )
        background_tasks.add_task(
            sbom_service.run_scan, 
            scan_id, 
            github_token,
            bd_project_name,
            bd_project_version,
            bd_api_token,
            uploaded_sbom_content,
            uploaded_sbom_format
        )
        return ScanResponse(scan_id=scan_id, status="started", message="Cloning and scanning the repository.")
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to start scan: {str(e)}")

@router.get("/sbom-results/{scan_id}", response_model=ScanResults)
async def get_sbom_results(scan_id: str) -> ScanResults:
    """
    Fetch SBOM results for a specific scan session.
    """
    try:
        results = await sbom_service.get_scan_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve results: {str(e)}")

#TODO: implement this (will do this later, not priority now):

# @router.post("/rerun-scanner", response_model=Dict[str, Any])
# async def rerun_scanner(request: RerunRequest) -> Dict[str, Any]:
#     """
#     Rerun a specific scanner with additional commands.
#     """
#     try:
#         success = await sbom_service.rerun_scanner(request.scan_id, request.scanner, request.commands)
#         if success:
#             return {"status": "success", "message": f"{request.scanner} rerun completed"}
#         else:
#             raise HTTPException(status_code=400, detail="Rerun failed")
#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Rerun failed: {str(e)}")

@router.get("/scan-status/{scan_id}")
async def get_scan_status(scan_id: str) -> Dict[str, str]:  
    """
    Check the status of a scan.
    """
    try:
        status = await sbom_service.get_scan_status(scan_id)
        if not status:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": status}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get status: {str(e)}")
    
@router.get("/logs/{scan_id}")
async def get_scan_logs(scan_id: str) -> Dict[str, Any]:
    """
    Retrieve logs for a specific scan.
    """
    try:
        log_file = settings.LOG_FILE
        if not os.path.exists(log_file):
            raise HTTPException(status_code=404, detail="Log file not found")
        
        with open(log_file, "r") as f:
            all_logs = f.read()
        
        # Filter logs for the specific scan_id
        scan_logs = [line for line in all_logs.split('\n') if scan_id in line]
        
        return {"scan_id": scan_id, "logs": '\n'.join(scan_logs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve logs: {str(e)}")
    
@router.get("/download-sbom/{scan_id}/{scanner_name}")
async def download_sbom(scan_id: str, scanner_name: str):
    """
    Download SBOM JSON file for scanners (including uploaded SBOMs).
    """
    try:
        try:
            scanner = ScannerType(scanner_name.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scanner name")
        
        # Check if it's an uploaded SBOM
        if scanner == ScannerType.UPLOADED:
            uploaded_results = await sbom_service.get_uploaded_scan_results(scan_id)
            if not uploaded_results:
                raise HTTPException(status_code=404, detail="Uploaded SBOM scan not found")
            
            sbom_data = await sbom_service.get_scanner_sbom(scan_id, scanner)
            if not sbom_data:
                raise HTTPException(status_code=404, detail="SBOM not found")
            
            filename = f"uploaded-{uploaded_results.filename}"
        else:
            results = await sbom_service.get_scan_results(scan_id)
            if not results:
                raise HTTPException(status_code=404, detail="Scan not found")
            
            sbom_data = await sbom_service.get_scanner_sbom(scan_id, scanner)
            if not sbom_data:
                raise HTTPException(status_code=404, detail="SBOM not found for this scanner")
            
            repo_url = results.repo_url
            repo_name = repo_url.rstrip('/').split('/')[-1]
            filename = f"{scanner_name}-{repo_name}-sbom.json"
        
        return JSONResponse(
            content=sbom_data,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/json"
            }
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download SBOM: {str(e)}")
    
@router.get("/scan-analysis/{scan_id}")
async def get_scan_analysis(scan_id: str):
    """
    Get analysis data for a scan including common/unique packages and scores.
    """
    try:
        analysis = await sbom_service.get_scan_analysis(scan_id)
        if not analysis:
            raise HTTPException(status_code=404, detail="Scan not found")
        return analysis
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get analysis: {str(e)}")

@router.get("/scan-graph/{scan_id}/{scanner_name}")
async def get_scan_graph(scan_id: str, scanner_name: str):
    """
    Get graph data for a specific scanner's SBOM for visualization.
    """
    try:
        try:
            scanner = ScannerType(scanner_name.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scanner name")
        
        graph_data = await sbom_service.get_scan_graph(scan_id, scanner)
        if "error" in graph_data:
            raise HTTPException(status_code=404, detail=graph_data["error"])
        
        return graph_data
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to get graph data: {str(e)}")

@router.get("/merge-sbom/{scan_id}")
async def get_merge_sbom(
    scan_id: str,
    include_all_unique: bool = True,
    exclude_github_actions: bool = False,
    force_regenerate: bool = False
):
    """
    Get merged SBOM from all the scanners using intelligent database-driven merging.
    
    Args:
        scan_id: The scan identifier
        include_all_unique: Include all unique packages (default: True)
        exclude_github_actions: Exclude GitHub Actions packages (default: False)
        force_regenerate: Force regeneration of merged SBOM (default: False)
    """
    try:
        results = await sbom_service.get_scan_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Use the new custom merge functionality with options
        merged_sbom = await sbom_service.get_merged_sbom(
            scan_id=scan_id,
            include_all_unique=include_all_unique,
            exclude_github_actions=exclude_github_actions,
            force_regenerate=force_regenerate
        )
        
        if not merged_sbom:
            raise HTTPException(status_code=400, detail="Failed to create merged SBOM")
        
        return merged_sbom
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to merge SBOMs: {str(e)}")

@router.post("/merge-sbom/{scan_id}")
async def post_merge_sbom(
    scan_id: str,
    request_body: Dict[str, Any]
):
    """
    Generate merged SBOM with specific unique packages selected by the user.
    
    Args:
        scan_id: The scan identifier
        request_body: JSON body with selected_unique_packages
            {
                "selected_unique_packages": {
                    "scanner_name": [
                        {"name": "pkg1", "version": "1.0.0"},
                        {"name": "pkg2", "version": "2.0.0"}
                    ]
                }
            }
    """
    try:
        results = await sbom_service.get_scan_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        selected_unique = request_body.get("selected_unique_packages", {})
        
        # Call merge service with specific package selections
        merged_sbom = await sbom_service.get_merged_sbom_with_selections(
            scan_id=scan_id,
            selected_unique_packages=selected_unique
        )
        
        if not merged_sbom:
            raise HTTPException(status_code=400, detail="Failed to create merged SBOM")
        
        return merged_sbom
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to merge SBOMs: {str(e)}")

@router.get("/download-merged-sbom/{scan_id}")
async def download_merged_sbom(scan_id: str):
    """
    Download merged SBOM JSON file.
    """
    try:
        merged_sbom = await get_merge_sbom(scan_id)
        
        results = await sbom_service.get_scan_results(scan_id)
        repo_url = results.repo_url if results else "unknown"
        repo_name = repo_url.rstrip('/').split('/')[-1]
        
        filename = f"merged-{repo_name}-sbom.json"
        
        return JSONResponse(
            content=merged_sbom,
            headers={
                "Content-Disposition": f"attachment; filename={filename}",
                "Content-Type": "application/json"
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to download merged SBOM: {str(e)}")
    
@router.post("/upload-sbom", response_model=SBOMUploadResponse)
async def upload_sbom_file(file: UploadFile = File(...), format: str = Form(...)) -> SBOMUploadResponse:
    """
    Upload an SBOM file (SPDX or CycloneDX format) for analysis.
    """
    try:
        if format.lower() not in ["spdx", "cyclonedx"]:
            raise HTTPException(status_code=400, detail="Format must be 'spdx' or 'cyclonedx'")
        
        if not file.filename.endswith(('.json', '.spdx.json', '.cdx.json')):
            raise HTTPException(status_code=400, detail="File must be a JSON file")
        
        file_content = await file.read()
        if len(file_content) == 0:
            raise HTTPException(status_code=400, detail="File is empty")
        
        scan_id = await sbom_service.process_uploaded_sbom(
            filename=file.filename,
            file_content=file_content,
            sbom_format=format
        )
        
        uploaded_results = await sbom_service.get_uploaded_scan_results(scan_id)
        component_count = 0
        if uploaded_results and uploaded_results.uploaded_sbom:
            component_count = uploaded_results.uploaded_sbom.component_count
        
        return SBOMUploadResponse(
            scan_id=scan_id,
            status="completed",
            message=f"SBOM file '{file.filename}' processed successfully",
            format=format,
            component_count=component_count
        )
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to process SBOM file: {str(e)}")
    
@router.get("/uploaded-sbom-results/{scan_id}")
async def get_uploaded_sbom_results(scan_id: str):
    """
    Fetch results for an uploaded SBOM file.
    """
    try:
        results = await sbom_service.get_uploaded_scan_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail="Uploaded SBOM scan not found")
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve uploaded SBOM results: {str(e)}")

@router.post("/validate-cpes")
async def validate_cpes(request_body: Dict[str, Any]):
    """
    Validate CPEs for components in a merged SBOM.
    
    Args:
        request_body: JSON body with cpes list
            {
                "cpes": ["cpe:2.3:a:vendor:product:version:...", ...]
            }
    
    Returns:
        Dict mapping CPE to validation status
    """
    try:
        cpes = request_body.get("cpes", [])
        if not cpes:
            return {"results": {}}
        
        results = await cpe_service.verify_cpes_batch(cpes)
        return {"results": results}
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate CPEs: {str(e)}")

@router.get("/cpe-stats")
async def get_cpe_stats():
    """
    Check NVD CPE API availability and configuration.
    """
    try:
        # Test API with a known CPE
        test_cpe = "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"
        is_valid = await cpe_service.verify_cpe(test_cpe)
        
        return {
            "api_available": True,
            "test_validation": is_valid,
            "base_url": cpe_service.base_url,
            "rate_limit": f"{cpe_service.max_requests_per_30_seconds} requests per 30 seconds"
        }
    except Exception as e:
        return {
            "api_available": False,
            "error": str(e)
        }
