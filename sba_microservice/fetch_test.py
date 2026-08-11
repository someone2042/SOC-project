from opensearch_client import connect_opensearch, fetch_historical_logs
from datetime import datetime, timedelta, timezone

def run_fetch_test():
    print("--- SBA Fetch & Parser Diagnostic ---")
    client = connect_opensearch()
    
    end_time = datetime.now(timezone.utc)
    start_time = end_time - timedelta(days=2)  # Look back a bit to ensure we hit the alerts
    
    start_str = start_time.isoformat()
    end_str = end_time.isoformat()
    
    print(f"Fetching sample logs for 'window_server' from {start_str} to {end_str}...")
    
    # We use a custom raw query here just to grab a few samples for window_server
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "agent.name": "window_server"
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_str,
                                "lte": end_str
                            }
                        }
                    }
                ]
            }
        },
        "_source": ["timestamp", "agent.name", "rule.description", "full_log"],
        "size": 5,
        "sort": [{"timestamp": {"order": "desc"}}]
    }
    
    try:
        response = client.search(index="wazuh-archives-*", body=query)
        hits = response['hits']['hits']
        print(f"Found {len(hits)} raw hits.")
        
        for i, hit in enumerate(hits):
            log = hit['_source']
            print(f"\n--- Log Sample {i+1} Raw Source ---")
            print(log)
            
            # --- The exact parser logic from train.py & inference.py ---
            log_message = log.get('full_log')
            if log_message and (log_message.strip().startswith('{') or log_message.strip().startswith('[')):
                log_message = log.get('rule', {}).get('description', '')
                
            if not log_message:
                log_message = log.get('rule', {}).get('description', 'Unknown Alert')
            # -------------------------------------------------------------
            
            print("\n-> Extracted Log Message for Drain3:")
            print(f"   {repr(log_message)}")
            
    except Exception as e:
        print(f"Error executing fetch test: {e}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    run_fetch_test()
