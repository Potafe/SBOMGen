import logging
import httpx
import asyncio
import zipfile
import io
import json
from typing import Optional, Dict, Any
from app.core.config import settings

logger = logging.getLogger(__name__)


class BDService:
    """Service for interacting with Black Duck APIs"""
    
    def __init__(self, base_url: str = "https://blackduck.philips.com"):
        self.base_url = base_url.rstrip('/')
        self.logger = logging.getLogger(__name__)
        self.timeout = getattr(settings, 'BD_TIMEOUT', 60)
    
    async def _authenticate(self, api_token: str) -> str:
        """
        Authenticate with Black Duck and get bearer token.
        
        Args:
            api_token: Black Duck API token
            
        Returns:
            Bearer token string
            
        Raises:
            httpx.HTTPError: If authentication fails
        """
        url = f"{self.base_url}/api/tokens/authenticate"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.user-4+json',
            'Authorization': f'token {api_token}'
        }
        
        logger.info("Authenticating to Black Duck...")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.post(url, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                bearer_token = data['bearerToken']
                logger.info("Successfully obtained bearer token")
                return bearer_token
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Black Duck authentication error: {e.response.status_code} - {e.response.text}")
                raise
            except httpx.RequestError as e:
                logger.error(f"Request error during authentication: {e}")
                raise
    
    async def _get_project_id(self, bearer_token: str, project_name: str) -> Optional[str]:
        """
        Get project ID by name.
        
        Args:
            bearer_token: Black Duck bearer token
            project_name: Name of the project
            
        Returns:
            Project ID or None if not found
        """
        url = f"{self.base_url}/api/projects"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
            'Authorization': f'Bearer {bearer_token}'
        }
        
        logger.info(f"Searching for project: {project_name}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                items = data.get('items', [])
                
                for item in items:
                    if item.get('name') == project_name:
                        href = item['_meta']['href']
                        project_id = href.split('/')[-1]
                        logger.info(f"Found project: {project_name} (ID: {project_id})")
                        return project_id
                
                logger.error(f"Project '{project_name}' not found")
                return None
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Error fetching projects: {e.response.status_code} - {e.response.text}")
                return None
            except httpx.RequestError as e:
                logger.error(f"Request error fetching projects: {e}")
                return None
    
    async def _get_project_version_id(
        self, 
        bearer_token: str, 
        project_id: str, 
        version_name: str
    ) -> Optional[str]:
        """
        Get project version ID by version name.
        
        Args:
            bearer_token: Black Duck bearer token
            project_id: Black Duck project ID
            version_name: Name of the project version
            
        Returns:
            Version ID or None if not found
        """
        url = f"{self.base_url}/api/projects/{project_id}/versions?limit=100"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.project-detail-4+json',
            'Authorization': f'Bearer {bearer_token}'
        }
        
        logger.info(f"Searching for version '{version_name}' in project {project_id}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                
                data = response.json()
                items = data.get('items', [])
                
                for item in items:
                    if item.get('versionName') == version_name:
                        href = item.get('_meta', {}).get('href', '')
                        if href:
                            version_id = href.split('/')[-1]
                            logger.info(f"Found version '{version_name}' (ID: {version_id})")
                            return version_id
                
                logger.error(f"Version '{version_name}' not found")
                return None
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Error fetching versions: {e.response.status_code} - {e.response.text}")
                return None
            except httpx.RequestError as e:
                logger.error(f"Request error fetching versions: {e}")
                return None
    
    async def _create_sbom_report(
        self, 
        bearer_token: str, 
        project_id: str, 
        version_id: str
    ) -> Optional[str]:
        """
        Create SBOM report and return report ID.
        
        Args:
            bearer_token: Black Duck bearer token
            project_id: Black Duck project ID
            version_id: Black Duck version ID
            
        Returns:
            Report ID or None if failed
        """
        url = f"{self.base_url}/api/projects/{project_id}/versions/{version_id}/sbom-reports"
        headers = {
            'Content-Type': 'application/vnd.blackducksoftware.report-4+json',
            'Authorization': f'Bearer {bearer_token}'
        }
        
        payload = {
            "reportFormat": "JSON",
            "sbomType": "CYCLONEDX_16"
        }
        
        logger.info(f"Creating SBOM report for project {project_id}, version {version_id}")
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.post(url, headers=headers, json=payload)
                response.raise_for_status()
                
                # Extract report ID from Location header
                location = response.headers.get('Location', '')
                if location:
                    report_id = location.split('/')[-1]
                    logger.info(f"Created SBOM report with ID: {report_id}")
                    return report_id
                
                logger.error("No Location header in report creation response")
                return None
                
            except httpx.HTTPStatusError as e:
                logger.error(f"Error creating SBOM report: {e.response.status_code} - {e.response.text}")
                return None
            except httpx.RequestError as e:
                logger.error(f"Request error creating SBOM report: {e}")
                return None
    
    async def _wait_for_report(
        self, 
        bearer_token: str, 
        project_id: str, 
        version_id: str, 
        report_id: str,
        max_wait: int = 300
    ) -> bool:
        """
        Wait for report to be ready.
        
        Args:
            bearer_token: Black Duck bearer token
            project_id: Black Duck project ID
            version_id: Black Duck version ID
            report_id: Report ID
            max_wait: Maximum time to wait in seconds
            
        Returns:
            True if report is ready, False otherwise
        """
        url = f"{self.base_url}/api/projects/{project_id}/versions/{version_id}/reports/{report_id}"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.report-4+json',
            'Authorization': f'Bearer {bearer_token}'
        }
        
        logger.info(f"Waiting for report {report_id} to be ready...")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            waited = 0
            while waited < max_wait:
                try:
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code == 200:
                        data = response.json()
                        status = data.get('status', '')
                        
                        # Check if report status is COMPLETED
                        if status == 'COMPLETED':
                            logger.info(f"Report {report_id} is ready (status: {status})")
                            return True
                        else:
                            logger.debug(f"Report {report_id} status: {status}, waiting...")
                    
                    await asyncio.sleep(5)
                    waited += 5
                    
                except Exception as e:
                    logger.warning(f"Error checking report status: {e}")
                    await asyncio.sleep(5)
                    waited += 5
            
            logger.error(f"Report {report_id} not ready after {max_wait} seconds")
            return False
    
    async def _download_sbom_report(
        self, 
        bearer_token: str, 
        project_id: str, 
        version_id: str, 
        report_id: str
    ) -> Dict[str, Any]:
        """
        Download SBOM report (returns as ZIP file containing JSON).
        
        Args:
            bearer_token: Black Duck bearer token
            project_id: Black Duck project ID
            version_id: Black Duck version ID
            report_id: Report ID
            
        Returns:
            CycloneDX SBOM data extracted from ZIP
            
        Raises:
            httpx.HTTPError: If download fails
            ValueError: If ZIP extraction fails
        """
        url = f"{self.base_url}/api/projects/{project_id}/versions/{version_id}/reports/{report_id}/download"
        headers = {
            'Accept': 'application/vnd.blackducksoftware.report-4+json',
            'Authorization': f'Bearer {bearer_token}'
        }
        
        logger.info(f"Downloading SBOM report {report_id}")
        
        async with httpx.AsyncClient(timeout=60.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                
                # Black Duck returns a ZIP file containing the JSON
                zip_content = response.content
                
                # Extract JSON from ZIP
                with zipfile.ZipFile(io.BytesIO(zip_content)) as zip_file:
                    # Get list of files in ZIP
                    file_list = zip_file.namelist()
                    logger.debug(f"Files in ZIP: {file_list}")
                    
                    # Find the JSON file (usually has .json extension)
                    json_file = None
                    for filename in file_list:
                        if filename.endswith('.json'):
                            json_file = filename
                            break
                    
                    if not json_file:
                        raise ValueError(f"No JSON file found in ZIP archive. Files: {file_list}")
                    
                    # Read and parse JSON
                    with zip_file.open(json_file) as f:
                        sbom_data = json.load(f)
                
                logger.info(f"Successfully downloaded and extracted SBOM report {report_id}")
                return sbom_data
                
            except zipfile.BadZipFile as e:
                logger.error(f"Invalid ZIP file received: {e}")
                raise ValueError(f"Black Duck returned invalid ZIP file: {e}")
            except httpx.HTTPStatusError as e:
                logger.error(f"Error downloading SBOM report: {e.response.status_code} - {e.response.text}")
                raise
            except httpx.RequestError as e:
                logger.error(f"Request error downloading SBOM report: {e}")
                raise
    
    async def fetch_sbom(
        self, 
        project_name: str, 
        project_version: str, 
        api_token: str
    ) -> Dict[str, Any]:
        """
        Fetch SBOM from Black Duck for a specific project and version.
        Returns CycloneDX 1.6 format SBOM.
        
        Args:
            project_name: Black Duck project name
            project_version: Black Duck project version name
            api_token: Black Duck API token
            
        Returns:
            Dict containing CycloneDX SBOM data
            
        Raises:
            httpx.HTTPError: If API request fails
            ValueError: If project or version not found
        """
        try:
            # Authenticate
            bearer_token = await self._authenticate(api_token)
            
            # Get project ID
            project_id = await self._get_project_id(bearer_token, project_name)
            if not project_id:
                raise ValueError(f"Project '{project_name}' not found in Black Duck")
            
            # Get version ID
            version_id = await self._get_project_version_id(bearer_token, project_id, project_version)
            if not version_id:
                raise ValueError(f"Version '{project_version}' not found for project '{project_name}'")
            
            # Create SBOM report
            report_id = await self._create_sbom_report(bearer_token, project_id, version_id)
            if not report_id:
                raise ValueError("Failed to create SBOM report")
            
            # Wait for report to be ready
            is_ready = await self._wait_for_report(bearer_token, project_id, version_id, report_id)
            if not is_ready:
                raise ValueError("SBOM report generation timed out")
            
            # Download report
            sbom_data = await self._download_sbom_report(bearer_token, project_id, version_id, report_id)
            
            logger.info(f"Successfully fetched SBOM from Black Duck for {project_name}/{project_version}")
            return sbom_data
            
        except Exception as e:
            logger.error(f"Error fetching SBOM from Black Duck: {e}")
            raise
