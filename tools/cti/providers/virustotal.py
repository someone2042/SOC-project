from typing import Dict, Any, Optional
import httpx
import logging
from config import settings
from tools.cti.base import CTIProvider

logger = logging.getLogger(__name__)

class VirusTotalProvider(CTIProvider):
    def __init__(self):
        super().__init__()
        self.api_key = settings.virustotal_api_key

    async def lookup_hash(self, file_hash: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        if not self.api_key or self.api_key == "your_vt_api_key_here":
            logger.warning(f"[{self.name}] API key not configured. Skipping.")
            return {"error": f"API key missing"}

        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": self.api_key}

        try:
            logger.info(f"[{self.name}] Fetching Hash: {file_hash}")
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return {"result": "Hash not found in VirusTotal (Unknown File)."}
            return {"error": f"HTTP {e.response.status_code}"}
        except Exception as e:
            return {"error": str(e)}
