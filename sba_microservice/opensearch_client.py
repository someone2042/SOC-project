import os
import json
from datetime import datetime, timezone
from dotenv import load_dotenv
from opensearchpy import OpenSearch

# Load environment variables from parent directory if running locally
load_dotenv(os.path.join(os.path.dirname(__file__), '..', '.env'))

import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from config import settings

def connect_opensearch() -> OpenSearch:
    """Establish connection to the OpenSearch cluster."""
    host = settings.opensearch_url
    
    # Extract host and port
    if host.startswith("https://"):
        host = host.replace("https://", "")
    elif host.startswith("http://"):
        host = host.replace("http://", "")
        
    host_parts = host.split(":")
    hostname = host_parts[0]
    port = int(host_parts[1]) if len(host_parts) > 1 else 9200

    user = settings.opensearch_user
    password = settings.opensearch_password

    client = OpenSearch(
        hosts=[{'host': hostname, 'port': port}],
        http_compress=True,
        http_auth=(user, password),
        use_ssl=True,
        verify_certs=False,  # Set to True in production with proper certs
        ssl_assert_hostname=False,
        ssl_show_warn=False
    )
    return client

def fetch_historical_logs(client: OpenSearch, start_time: str, end_time: str, index: str = "wazuh-archives-*", max_docs: int = 100000) -> list:
    """
    Fetch logs from OpenSearch within a time window.
    start_time and end_time should be ISO 8601 strings (e.g., '2026-08-01T00:00:00Z')
    """
    query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ],
                "must_not": [
                    {
                        "term": {
                            "agent.id": "000"
                        }
                    }
                ]
            }
        },
        "_source": ["timestamp", "agent.name", "rule.description", "full_log"],
        "size": 10000, # Using a reasonable batch size
        "sort": [{"timestamp": {"order": "asc"}}]
    }

    all_hits = []
    response = client.search(index=index, body=query, scroll='2m')
    scroll_id = response['_scroll_id']
    hits = response['hits']['hits']
    
    print(f"Fetching logs from {index}...")
    while len(hits) > 0:
        all_hits.extend(hits)
        print(f"Fetched {len(all_hits)} logs so far...", flush=True)
        if len(all_hits) >= max_docs:
            print(f"Reached max_docs limit ({max_docs}). Stopping fetch.", flush=True)
            all_hits = all_hits[:max_docs]
            break
            
        response = client.scroll(scroll_id=scroll_id, scroll='2m')
        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']
        
    client.clear_scroll(scroll_id=scroll_id)
    
    # Group by host
    logs_by_host = {}
    for hit in all_hits:
        source = hit['_source']
        agent_name = source.get('agent', {}).get('name', 'unknown')
        if agent_name not in logs_by_host:
            logs_by_host[agent_name] = []
        logs_by_host[agent_name].append(source)
        
    return logs_by_host

def push_sba_scores(client: OpenSearch, scores: list, index: str = "sba-host-scores"):
    """
    Push anomaly scores to the specified OpenSearch index.
    scores should be a list of dictionaries:
    [
        {
            "timestamp": "...",
            "host": "...",
            "ml_sba_score": 85,
            "sba_contributing_factors": ["template1", "template2", "template3"]
        }
    ]
    """
    # Create index if it doesn't exist
    if not client.indices.exists(index=index):
        index_body = {
            "settings": {
                "number_of_shards": 1,
                "number_of_replicas": 0
            },
            "mappings": {
                "properties": {
                    "timestamp": {"type": "date"},
                    "host": {"type": "keyword"},
                    "ml_sba_score": {"type": "float"},
                    "anomaly_severity": {"type": "keyword"},
                    "anomaly_nature": {"type": "keyword"},
                    "sba_contributing_factors": {"type": "keyword"}
                }
            }
        }
        client.indices.create(index=index, body=index_body)

    # Bulk index
    # We will use the simple index API if the list is small, or bulk API if large.
    # Since it's per host per 5 mins, the list is small (number of hosts).
    for score_doc in scores:
        client.index(index=index, body=score_doc, refresh=True)
    print(f"Successfully pushed {len(scores)} SBA score documents to {index}")

if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    print("Testing OpenSearch connectivity...")
    client = connect_opensearch()
    info = client.info()
    print(f"Connected to OpenSearch: {info['version']['number']}")
    
    # Test pushing a dummy score
    dummy_score = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "host": "test-agent",
        "ml_sba_score": 12.5,
        "sba_contributing_factors": ["syslog: user root logged in"]
    }
    push_sba_scores(client, [dummy_score])
    
    # Test fetching the dummy score back
    res = client.search(index="sba-host-scores", body={"query": {"match_all": {}}})
    print(f"Found {res['hits']['total']['value']} documents in sba-host-scores index.")
