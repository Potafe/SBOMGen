import logging
import aiohttp
import asyncio
import json
from typing import Optional, Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)

class CPEService:
    """
    CPE Service - verifies CPEs of packages in SBOM against the official NVD CPE Dictionary API.
    Uses the NVD REST API v2.0 to validate CPE strings without maintaining a local database.
    """
    
    def __init__(self):
        self.base_url = "https://services.nvd.nist.gov/rest/json/cpes/2.0"
        self.headers = {
            'apiKey': '417d28ac-7e9c-43a6-ad61-7a7e0a7b97a7'
        }
        self.request_times = []
        self.max_requests_per_30_seconds = 5  # Without API key: 5 requests per 30 seconds

    async def _rate_limit(self):
        """
        Enforce NVD API rate limits.
        Without API key: 5 requests per 30 seconds
        With API key: 50 requests per 30 seconds
        """
        current_time = datetime.now().timestamp()
        
        # Remove requests older than 30 seconds
        self.request_times = [t for t in self.request_times if current_time - t < 30]
        
        # If we've hit the limit, wait
        if len(self.request_times) >= self.max_requests_per_30_seconds:
            oldest_request = self.request_times[0]
            wait_time = 30 - (current_time - oldest_request)
            if wait_time > 0:
                logger.info(f"Rate limit reached, waiting {wait_time:.2f} seconds")
                await asyncio.sleep(wait_time)
                # Clear old requests after waiting
                current_time = datetime.now().timestamp()
                self.request_times = [t for t in self.request_times if current_time - t < 30]
        
        # Record this request
        self.request_times.append(datetime.now().timestamp())
        
    async def _query_nvd_api(self, cpe_match_string: str) -> Optional[Dict[str, Any]]:
        """
        Query the NVD CPE API with a CPE match string.
        Returns the API response or None if error.
        """
        try:
            await self._rate_limit()
            
            params = {'cpeMatchString': cpe_match_string}
            
            async with aiohttp.ClientSession() as session:
                async with session.get(self.base_url, headers=self.headers, params=params) as response:
                    if response.status == 200:
                        data = await response.json()
                        return data
                    else:
                        logger.warning(f"NVD API returned status {response.status} for CPE: {cpe_match_string}")
                        return None
        except Exception as e:
            logger.error(f"Error querying NVD API for CPE {cpe_match_string}: {e}")
            return None

    async def verify_cpe(self, cpe: str) -> bool:
        """
        Verify if a CPE exists in the NVD database using the API.
        Returns True if the CPE is valid (exact match found), False otherwise.
        """
        try:
            if not cpe or not cpe.startswith('cpe:'):
                return False
            
            data = await self._query_nvd_api(cpe)
            
            if not data:
                return False
            
            # Check if we got any products back
            products = data.get('products', [])
            
            # Verify exact match - the API should return exact match when using cpeMatchString
            for product in products:
                cpe_info = product.get('cpe', {})
                cpe_name = cpe_info.get('cpeName', '')
                
                # Check for exact match
                if cpe_name == cpe:
                    return True
            
            return False
        except Exception as e:
            logger.error(f"Error verifying CPE {cpe}: {e}")
            return False
    
    async def verify_cpes_batch(self, cpes: List[str]) -> Dict[str, bool]:
        """
        Verify multiple CPEs using the NVD API with rate limiting.
        Returns dict mapping CPE string to existence boolean.
        """
        try:
            if not cpes:
                return {}
            
            # Filter valid CPE strings
            valid_cpes = [cpe for cpe in cpes if cpe and cpe.startswith('cpe:')]
            if not valid_cpes:
                return {cpe: False for cpe in cpes}
            
            results = {}
            
            # Query each CPE individually with rate limiting
            for cpe in valid_cpes:
                is_valid = await self.verify_cpe(cpe)
                results[cpe] = is_valid
            
            # Add invalid CPEs as False
            for cpe in cpes:
                if cpe not in results:
                    results[cpe] = False
            
            return results
        except Exception as e:
            logger.error(f"Error verifying CPEs batch: {e}")
            return {cpe: False for cpe in cpes}


cpe_service = CPEService()