from abc import ABC
from typing import Dict, Any, Optional
import httpx

class CTIProvider(ABC):
    """
    Abstract Base Class for all Cyber Threat Intelligence plugins.
    Any new tool (like Shodan, AlienVault) must inherit from this class.
    """
    def __init__(self):
        self.name = self.__class__.__name__

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Override this if the provider supports IP lookups. Returns None if unsupported."""
        return None

    async def lookup_hash(self, file_hash: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        """Override this if the provider supports File Hash lookups. Returns None if unsupported."""
        return None
