import httpx
import asyncio
import logging
from typing import Dict, Any

from tools.cache import ThreatIntelCache
from tools.cti.providers.virustotal import VirusTotalProvider
from tools.cti.providers.abuseipdb import AbuseIPDBProvider

logger = logging.getLogger(__name__)

class CTIManager:
    """
    Central Manager that coordinates multiple CTI plugins and handles local caching.
    """
    def __init__(self):
        self.cache = ThreatIntelCache()
        self.client = httpx.AsyncClient(timeout=10.0)
        
        # Register enabled providers
        self.providers = [
            VirusTotalProvider(),
            AbuseIPDBProvider()
        ]

    async def lookup_ip(self, ip: str) -> Dict[str, Any]:
        """Query all registered CTI providers for an IP address concurrently."""
        cached = self.cache.get(f"ip_{ip}")
        if cached:
            logger.info(f"[CTIManager] Cache hit for IP: {ip}")
            return cached

        logger.info(f"[CTIManager] Fetching fresh CTI for IP: {ip}")
        tasks = []
        names = []
        for provider in self.providers:
            tasks.append(provider.lookup_ip(ip, self.client))
            names.append(provider.name)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        merged_result = {}
        for name, res in zip(names, results):
            if res is not None:
                if isinstance(res, Exception):
                    merged_result[name] = {"error": "Plugin crashed", "detail": str(res)}
                else:
                    merged_result[name] = res

        if merged_result:
            self.cache.set(f"ip_{ip}", "ip", merged_result)

        return merged_result

    async def lookup_hash(self, file_hash: str) -> Dict[str, Any]:
        """Query all registered CTI providers for a File Hash concurrently."""
        cached = self.cache.get(f"hash_{file_hash}")
        if cached:
            logger.info(f"[CTIManager] Cache hit for Hash: {file_hash}")
            return cached

        logger.info(f"[CTIManager] Fetching fresh CTI for Hash: {file_hash}")
        tasks = []
        names = []
        for provider in self.providers:
            tasks.append(provider.lookup_hash(file_hash, self.client))
            names.append(provider.name)

        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        merged_result = {}
        for name, res in zip(names, results):
            if res is not None:
                if isinstance(res, Exception):
                    merged_result[name] = {"error": "Plugin crashed", "detail": str(res)}
                else:
                    merged_result[name] = res

        if merged_result:
            self.cache.set(f"hash_{file_hash}", "hash", merged_result)

        return merged_result

    async def close(self):
        await self.client.aclose()
