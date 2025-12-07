import os

from fastapi import (
    APIRouter, HTTPException, 
    BackgroundTasks, File, 
    UploadFile, Form 
)
from fastapi.responses import JSONResponse
from typing import Dict, Any
from app.schemas.scan import (
    RepositoryUpload, ScanResponse, 
    ScannerType, ScanResults, 
    RerunRequest, ScanStatus, 
    SBOMFormat, SBOMUploadResponse
)
from app.services.sbom_service import SBOMService
from app.services.sbom_merge import SBOMMerge
from app.core.config import settings

router = APIRouter()

sbom_service = SBOMService()
sbom_merge = SBOMMerge()

@router.post("/upload-repository", response_model=ScanResponse)
async def upload_repository(repo: RepositoryUpload, background_tasks: BackgroundTasks) -> ScanResponse:
    """
    Upload a GitHub repository URL and initiate scanning.
    Optionally provide Black Duck project details to fetch SBOM from Black Duck.
    """
    try:
        scan_id = await sbom_service.start_scan(
            repo.repo_url, 
            repo.github_token,
            repo.bd_project_name,
            repo.bd_project_version,
            repo.bd_api_token
        )
        background_tasks.add_task(
            sbom_service.run_scan, 
            scan_id, 
            repo.github_token,
            repo.bd_project_name,
            repo.bd_project_version,
            repo.bd_api_token
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
async def get_merge_sbom(scan_id: str):
    """
    Get merged SBOM from all the scanners.
    """
    try:
        results = await sbom_service.get_scan_results(scan_id)
        if not results:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        sbom_data_list = []
        scanner_names = []
        
        for scanner in [ScannerType.TRIVY, ScannerType.SYFT, ScannerType.CDXGEN]:
            sbom_data = await sbom_service.get_scanner_sbom(scan_id, scanner)
            sbom_data_list.append(sbom_data)
            scanner_names.append(scanner.value)
        
        merged_result = await sbom_merge.merge_sboms(scan_id, sbom_data_list, scanner_names)
        
        if "error" in merged_result:
            raise HTTPException(status_code=400, detail=merged_result["error"])
        
        return merged_result
        
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
