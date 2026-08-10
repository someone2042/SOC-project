import asyncio
import logging
from tools.siem import SIEMClient
import json

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

async def main():
    siem = SIEMClient()
    
    print("\n--- Testing SIEM Query (IP Frequency Aggregation) ---")
    
    # Example DSL query: Get top 5 source IPs from recent alerts
    query = {
        "query": {
            "match_all": {}
        },
        "aggs": {
            "top_ips": {
                "terms": {
                    "field": "data.srcip",
                    "size": 5
                }
            }
        },
        "size": 0  # We only care about aggregations for this test, not raw hits
    }
    
    result = await siem.execute_query(index="wazuh-alerts-*", dsl_query=query)
    
    if "error" in result:
        print(f"SIEM Query Failed: {result['error']}")
        print("\nMake sure you have added your OPENSEARCH_URL and credentials to the .env file!")
    else:
        print(f"Success! Retrieved result.")
        # Print aggregations safely
        print(json.dumps(result.get("aggregations", {}), indent=2))
        
    print("\n--- Testing SIEM Query 2 (Deep Investigation - Raw Logs) ---")
    print("Notice that we can query 'wazuh-archives-*' or 'wazuh-*' for deep hunting!")
    
    # Example DSL query: Get the 2 most recent raw logs
    query2 = {
        "query": {
            "match_all": {}
        },
        "sort": [
            {"timestamp": {"order": "desc"}}
        ],
        "size": 2  # The AI can control how many logs it wants to see
    }
    
    # We use 'wazuh-*' to search across both alerts and archives (if enabled)
    result2 = await siem.execute_query(index="wazuh-*", dsl_query=query2)
    
    if "error" in result2:
        print(f"SIEM Query 2 Failed: {result2['error']}")
    else:
        hits = result2.get("hits", {}).get("hits", [])
        print(f"Success! Retrieved {len(hits)} raw logs.")
        if hits:
            print("\nExample Raw Log (First result):")
            # Truncating the output slightly so it doesn't flood the terminal
            print(json.dumps(hits[0]['_source'], indent=2)[:800] + "\n... [TRUNCATED]")
        
    await siem.close()

if __name__ == "__main__":
    asyncio.run(main())
