import logging
import httpx
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)


class GithubService:
    """Service for interacting with GitHub APIs"""
    
    BASE_URL = "https://api.github.com"
    API_VERSION = "2022-11-28"
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def _parse_repo_url(self, repo_url: str) -> tuple[str, str]:
        """
        Extract owner and repo name from GitHub URL.
        Examples:
          https://github.com/owner/repo -> (owner, repo)
          https://github.com/owner/repo.git -> (owner, repo)
        """
        # Remove trailing .git if present
        url = repo_url.rstrip('/').replace('.git', '')
        
        # Split and get last two parts
        parts = url.split('/')
        if len(parts) >= 2:
            return parts[-2], parts[-1]
        
        raise ValueError(f"Invalid GitHub URL format: {repo_url}")
    
    async def fetch_dependency_graph_sbom(
        self, 
        repo_url: str, 
        github_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Fetch SBOM from GitHub Dependency Graph API.
        Returns SPDX 2.3 format SBOM.
        
        Args:
            repo_url: GitHub repository URL
            github_token: GitHub personal access token (required for private repos)
            
        Returns:
            Dict containing SPDX SBOM data
            
        Raises:
            httpx.HTTPError: If API request fails
            ValueError: If repo_url format is invalid
        """
        owner, repo = self._parse_repo_url(repo_url)
        
        url = f"{self.BASE_URL}/repos/{owner}/{repo}/dependency-graph/sbom"
        
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": self.API_VERSION
        }
        
        if github_token:
            headers["Authorization"] = f"Bearer {github_token}"
        
        logger.info(f"Fetching SBOM from GitHub for {owner}/{repo}")
        
        async with httpx.AsyncClient(timeout=30.0) as client:
            try:
                response = await client.get(url, headers=headers)
                response.raise_for_status()
                
                sbom_data = response.json()
                logger.info(f"Successfully fetched SBOM from GitHub for {owner}/{repo}")
                return sbom_data
                
            except httpx.HTTPStatusError as e:
                logger.error(f"GitHub API error for {owner}/{repo}: {e.response.status_code} - {e.response.text}")
                raise
            except httpx.RequestError as e:
                logger.error(f"Request error when fetching SBOM for {owner}/{repo}: {e}")
                raise
            except Exception as e:
                logger.error(f"Unexpected error fetching SBOM for {owner}/{repo}: {e}")
                raise