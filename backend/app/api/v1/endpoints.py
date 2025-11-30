import os

from fastapi import APIRouter, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse
from typing import Dict, Any
from app.schemas.scan import (
    RepositoryUpload, ScanResponse, 
    ScannerType, ScanResults, 
    RerunRequest, ScanStatus
)
from app.services.sbom_service import SBOMService
from app.core.config import settings

router = APIRouter()

sbom_service = SBOMService()

@router.post("/upload-repository", response_model=ScanResponse)
async def upload_repository(repo: RepositoryUpload, background_tasks: BackgroundTasks) -> ScanResponse:
    """
    Upload a GitHub repository URL and initiate scanning.
    """
    try:
        scan_id = await sbom_service.start_scan(repo.repo_url, repo.github_token)
        background_tasks.add_task(sbom_service.run_scan, scan_id, repo.github_token)
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

@router.post("/rerun-scanner", response_model=Dict[str, Any])
async def rerun_scanner(request: RerunRequest) -> Dict[str, Any]:
    """
    Rerun a specific scanner with additional commands.
    """
    try:
        success = await sbom_service.rerun_scanner(request.scan_id, request.scanner, request.commands)
        if success:
            return {"status": "success", "message": f"{request.scanner} rerun completed"}
        else:
            raise HTTPException(status_code=400, detail="Rerun failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Rerun failed: {str(e)}")

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
    Download SBOM JSON file for scanners.
    """
    try:
        try:
            scanner = ScannerType(scanner_name.lower())
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid scanner name")
        
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
