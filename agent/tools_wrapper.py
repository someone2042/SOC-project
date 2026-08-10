from langchain_core.tools import tool
from tools.threat_intel import CTIManager
from tools.siem import SIEMClient
import json

cti_manager = CTIManager()
siem_client = SIEMClient()

@tool
async def check_ip_reputation(ip: str) -> str:
    """Queries Threat Intelligence to check if an IP address is malicious."""
    result = await cti_manager.lookup_ip(ip)
    return json.dumps(result)

@tool
async def check_file_hash(file_hash: str) -> str:
    """Queries Threat Intelligence to check if a file hash is malicious."""
    result = await cti_manager.lookup_hash(file_hash)
    return json.dumps(result)

@tool
async def query_siem(dsl_query_json: str) -> str:
    """
    Executes a raw OpenSearch DSL query against the SIEM to hunt for historical logs.
    Provide the query as a valid JSON string.
    """
    try:
        query = json.loads(dsl_query_json)
        result = await siem_client.execute_query("wazuh-archives-*", query, 10)
        return json.dumps(result)
    except Exception as e:
        return f"Error executing SIEM query: {str(e)}"

# Provide tools as a list for LangChain
agent_tools = [check_ip_reputation, check_file_hash, query_siem]
