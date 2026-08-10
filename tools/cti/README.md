# Adding New CTI Plugins

This SOC platform uses a scalable plugin architecture for Cyber Threat Intelligence (CTI) tools. When the AI agent requests an IP or Hash lookup, the `CTIManager` concurrently queries all enabled plugins.

To add a new CTI tool (e.g., AlienVault OTX, Shodan, Greynoise), follow these 3 simple steps:

## Step 1: Create the Plugin File
Create a new Python file in the `tools/cti/providers/` directory (e.g., `alienvault.py`).

## Step 2: Inherit from CTIProvider
Your class must inherit from `CTIProvider` and override the `lookup_ip` or `lookup_hash` async methods. If your tool doesn't support a specific lookup type, simply do not override that method (it will default to returning `None`).

```python
# tools/cti/providers/alienvault.py
import httpx
from typing import Dict, Any, Optional
from tools.cti.base import CTIProvider
from config import settings

class AlienVaultProvider(CTIProvider):
    def __init__(self):
        super().__init__()
        # Ensure you add alienvault_api_key to config.py and .env first!
        self.api_key = getattr(settings, "alienvault_api_key", None) 

    async def lookup_ip(self, ip: str, client: httpx.AsyncClient) -> Optional[Dict[str, Any]]:
        # 1. Check if API key exists
        if not self.api_key:
            return {"error": "API key missing"}
            
        # 2. Make the async HTTP request
        url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
        headers = {"X-OTX-API-KEY": self.api_key}
        
        try:
            response = await client.get(url, headers=headers)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            return {"error": str(e)}
```

## Step 3: Register the Plugin
Open `tools/threat_intel.py` (the CTIManager) and add your new provider to the `self.providers` list.

```python
# tools/threat_intel.py
from tools.cti.providers.alienvault import AlienVaultProvider

class CTIManager:
    def __init__(self):
        # ...
        self.providers = [
            VirusTotalProvider(),
            AbuseIPDBProvider(),
            AlienVaultProvider()  # <--- Add it here!
        ]
```

That's it! The `CTIManager` will now automatically include AlienVault OTX in all future concurrent API lookups and cache the results locally.
