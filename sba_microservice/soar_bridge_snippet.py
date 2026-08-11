import os
from datetime import datetime, timedelta, timezone
from opensearchpy import OpenSearch
from typing import Dict, Any, Optional

def query_sba_score(host_name: str, alert_time_iso: str, client: Optional[OpenSearch] = None) -> Dict[str, Any]:
    """
    Demonstration snippet for the webhook receiver or SOAR agent to fetch the SBA score 
    for a specific host around the time of an alert.
    
    Args:
        host_name (str): The host where the alert originated (e.g., 'ubuntu-server')
        alert_time_iso (str): The time the alert occurred in ISO 8601 format
        client (OpenSearch, optional): An existing OpenSearch client instance
        
    Returns:
        dict: The SBA score and contributing factors, or None if no score exists.
    """
    
    if client is None:
        import sys
        sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
        from config import settings
        
        host = settings.opensearch_url
        if host.startswith("https://"): host = host.replace("https://", "")
        elif host.startswith("http://"): host = host.replace("http://", "")
        
        host_parts = host.split(":")
        hostname = host_parts[0]
        port = int(host_parts[1]) if len(host_parts) > 1 else 9200
        
        client = OpenSearch(
            hosts=[{'host': hostname, 'port': port}],
            http_compress=True,
            http_auth=(settings.opensearch_user, settings.opensearch_password),
            use_ssl=True,
            verify_certs=False,
            ssl_assert_hostname=False,
            ssl_show_warn=False
        )

    # Parse the alert time
    alert_time = datetime.fromisoformat(alert_time_iso.replace('Z', '+00:00'))
    
    # Calculate a +/- 5 minute window around the alert
    start_time = alert_time - timedelta(minutes=5)
    end_time = alert_time + timedelta(minutes=5)
    
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "term": {
                            "host": host_name
                        }
                    },
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time.isoformat(),
                                "lte": end_time.isoformat()
                            }
                        }
                    }
                ]
            }
        },
        # Sort by timestamp descending to get the closest/latest score
        "sort": [{"timestamp": {"order": "desc"}}],
        "size": 1
    }
    
    try:
        response = client.search(index="sba-host-scores", body=query)
        hits = response['hits']['hits']
        
        if hits:
            # Return the highest relevant or most recent score context
            best_hit = hits[0]['_source']
            return {
                "ml_sba_score": best_hit.get("ml_sba_score"),
                "anomaly_severity": best_hit.get("anomaly_severity", "UNKNOWN"),
                "anomaly_nature": best_hit.get("anomaly_nature", "UNKNOWN"),
                "sba_contributing_factors": best_hit.get("sba_contributing_factors", [])
            }
            
        return {"ml_sba_score": None, "anomaly_severity": None, "anomaly_nature": None, "sba_contributing_factors": []}
        
    except Exception as e:
        print(f"Failed to query SBA scores: {e}")
        return {"ml_sba_score": None, "sba_contributing_factors": [], "error": str(e)}

if __name__ == "__main__":
    # Test the snippet
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Let's use the current time, mimicking an alert that just fired
    mock_alert_time = datetime.now(timezone.utc).isoformat()
    mock_host = "window_server" # Testing the host we just scored
    
    print(f"Querying SBA Context for host: {mock_host} at time: {mock_alert_time}")
    result = query_sba_score(mock_host, mock_alert_time)
    print("SBA Context Returned to SOAR:")
    print(result)
