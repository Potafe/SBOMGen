import logging
import asyncio
from typing import Optional, Dict, Any, List
from packageurl import PackageURL

logger = logging.getLogger(__name__)

class PURLService:
    """
    PURL Service - verifies PURL syntax of packages in SBOM.
    This is a basic check, focusing on syntax validation only.
    """

    def __init__(self):
        pass

    async def verify_purl(self, purl: str) -> bool:
        """
        Verify if a PURL has valid syntax using packageurl library.
        Returns True if the PURL syntax is valid, False otherwise.
        """
        try:
            if not purl or not purl.startswith('pkg:'):
                return False
            PackageURL.from_string(purl)  # Raises exception if invalid
            return True  # Syntax valid; skip existence check
        except Exception as e:
            logger.error(f"Error verifying PURL {purl}: {e}")
            return False

    async def verify_purls_batch(self, purls: List[str]) -> Dict[str, bool]:
        """
        Verify multiple PURLs for syntax using packageurl library.
        Returns dict mapping PURL string to syntax validity boolean.
        """
        try:
            if not purls:
                return {}
            
            results = {}
            for purl in purls:
                results[purl] = await self.verify_purl(purl)
            
            return results
        except Exception as e:
            logger.error(f"Error verifying PURLs batch: {e}")
            return {purl: False for purl in purls}


purl_service = PURLService()