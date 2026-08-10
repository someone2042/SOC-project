import asyncio
import json
from tools.threat_intel import CTIManager
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)

async def main():
    manager = CTIManager()
    
    print("\n--- Testing CTIManager for IP (8.8.8.8) ---")
    ip_result = await manager.lookup_ip("8.8.8.8")
    print(f"Result: {json.dumps(ip_result, ensure_ascii=True)[:500]}... [TRUNCATED]")
    
    print("\n--- Testing CTIManager for VirusTotal (EICAR Hash) ---")
    hash_result = await manager.lookup_hash("275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
    print(f"Result: {json.dumps(hash_result, ensure_ascii=True)[:500]}... [TRUNCATED]")
    
    print("\n--- Testing Cache Hit (Should be instant) ---")
    cached_ip_result = await manager.lookup_ip("8.8.8.8")
    print(f"Cached Result: {json.dumps(cached_ip_result, ensure_ascii=True)[:500]}... [TRUNCATED]")
         
    await manager.close()

if __name__ == "__main__":
    asyncio.run(main())
