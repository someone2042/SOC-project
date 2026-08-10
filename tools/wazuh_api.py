import httpx
import sys
import os

# Ensure we can import config if this file is run directly
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import settings

class WazuhAPIClient:
    def __init__(self):
        self.base_url = settings.wazuh_api_url
        self.user = settings.wazuh_api_user
        self.password = settings.wazuh_api_password
        # Wazuh uses self-signed certs often, verify=False is needed for dev lab
        self.client = httpx.AsyncClient(verify=False)
        self.token = None

    async def authenticate(self) -> str:
        """
        Authenticate with the Wazuh API and retrieve a JWT token.
        """
        url = f"{self.base_url}/security/user/authenticate?raw=true"
        auth = (self.user, self.password)
        
        response = await self.client.post(url, auth=auth)
        response.raise_for_status()
        
        self.token = response.text.strip()
        return self.token

    async def get_headers(self) -> dict:
        """
        Get the authorization headers with the JWT token.
        """
        if not self.token:
            await self.authenticate()
        return {"Authorization": f"Bearer {self.token}"}

    async def close(self):
        """
        Close the underlying httpx client.
        """
        await self.client.aclose()

# For testing locally if this script is executed directly
if __name__ == "__main__":
    import asyncio
    import urllib3
    
    async def main():
        # Disable insecure request warnings for our self-signed lab certificate
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        client = WazuhAPIClient()
        try:
            print(f"Authenticating with Wazuh at {client.base_url}...")
            token = await client.authenticate()
            print(f"Authentication successful! Token prefix: {token[:20]}...")
        except Exception as e:
            print(f"Failed to authenticate: {e}")
        finally:
            await client.close()
            
    asyncio.run(main())
