import logging
from typing import Dict, Any, Optional
from opensearchpy import AsyncOpenSearch
from config import settings

logger = logging.getLogger(__name__)

class SIEMClient:
    """
    Scalable client for executing dynamic OpenSearch DSL queries against Wazuh Indexer.
    Provides the AI Agent with the ability to perform historical lookups and aggregations.
    """
    def __init__(self):
        # We disable SSL warnings because lab environments use self-signed certificates
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        
        self.url = settings.opensearch_url
        self.user = settings.opensearch_user
        self.password = settings.opensearch_password
        
        # Initialize the OpenSearch Async Client
        self.client = AsyncOpenSearch(
            hosts=[self.url],
            http_auth=(self.user, self.password),
            use_ssl=True,
            verify_certs=False,
            ssl_show_warn=False
        )

    async def execute_query(self, index: str, dsl_query: dict, limit: int = 10) -> Dict[str, Any]:
        """
        Executes an arbitrary OpenSearch DSL query.
        
        Args:
            index (str): The index pattern to search (e.g., "wazuh-alerts-*")
            dsl_query (dict): The raw JSON OpenSearch DSL query
            limit (int): Maximum number of results to return (applied if query doesn't specify size)
            
        Returns:
            Dict[str, Any]: The raw OpenSearch response containing 'hits' and 'aggregations'
        """
        try:
            logger.info(f"[SIEMClient] Executing DSL Query against index: {index}")
            
            # Aggressively enforce a hard limit to prevent token exhaustion
            # even if the AI tries to sneak a huge 'size' parameter into the DSL query
            requested_size = dsl_query.get('size', limit)
            dsl_query['size'] = min(requested_size, 10)
                
            response = await self.client.search(
                body=dsl_query,
                index=index
            )
            
            result = {}
            if 'hits' in response:
                total = response['hits']['total']
                result["total_hits"] = total['value'] if isinstance(total, dict) else total
                events = [hit.get('_source', {}) for hit in response['hits']['hits']]
                result["returned_events"] = len(events)
                result["events"] = events
                
            if 'aggregations' in response:
                result["aggregations"] = response['aggregations']
                
            return result if result else response
        except Exception as e:
            logger.error(f"[SIEMClient] Query execution failed: {e}")
            return {"error": str(e)}

    async def close(self):
        """Closes the underlying async client connections."""
        await self.client.close()
