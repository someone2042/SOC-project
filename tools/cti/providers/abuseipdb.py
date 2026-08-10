from typing import Dict, Any, Optional
import httpx
import logging
from config import settings
from tools.cti.base import CTIProvider

logger = logging.getLogger(__name__)

class AbuseIPDBProvider(CTIProvider):
    def __init__(self):
        super().__init__()
        self.api_key = settings.abuseipdb_api_key

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        if not self.api_key or self.api_key == "your_abuseipdb_api_key_here":
            logger.warning(f"[{self.name}] API key not configured. Skipping.")
            return {"error": f"API key missing"}

        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {
            "Accept": "application/json",
            "Key": self.api_key
        }
        params = {"ipAddress": ip, "maxAgeInDays": 90}

        try:
            logger.info(f"[{self.name}] Fetching IP: {ip}")
            response = await client.get(url, headers=headers, params=params)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            return {"error": f"HTTP {e.response.status_code}", "detail": e.response.text}
        except Exception as e:
            return {"error": str(e)}
