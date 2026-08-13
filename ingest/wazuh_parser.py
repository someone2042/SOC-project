from typing import Dict, Any, List
from pydantic import BaseModel
import ipaddress

class Observable(BaseModel):
    type: str  # e.g., "ip", "hash", "domain", "process"
    value: str

class ParsedAlert(BaseModel):
    alert_id: str
    rule_id: str
    rule_level: int
    rule_description: str
    agent_id: str
    agent_name: str
    agent_ip: str
    observables: List[Observable]
    raw_payload: Dict[str, Any]
    sba_context: Dict[str, Any] = {}

def extract_observables(payload: Dict[str, Any]) -> List[Observable]:
    """
    Extracts core Observables (IPs, hashes, etc.) from a Wazuh alert JSON.
    """
    observables = []
    
    # Usually Wazuh places contextual data in 'data' or 'syscheck' depending on the rule.
    data = payload.get("data", {})
    
    # 1. IP Addresses (e.g. from Suricata, or network events)
    for ip_field in ["srcip", "dstip", "src_ip", "dest_ip"]:
        if ip_field in data:
            observables.append(Observable(type="ip", value=str(data[ip_field])))
            
    # 2. File Hashes (e.g. from FIM / Syscheck)
    syscheck = payload.get("syscheck", {})
    for hash_alg in ["md5_after", "sha1_after", "sha256_after"]:
        if hash_alg in syscheck:
            observables.append(Observable(type="hash", value=str(syscheck[hash_alg])))
            
    # 3. Process Execution (Windows Event Logs / Sysmon)
    if "win" in data and "eventdata" in data.get("win", {}):
        eventdata = data["win"]["eventdata"]
        
        # Process name/image
        if "image" in eventdata:
            observables.append(Observable(type="process", value=str(eventdata["image"])))
            
        # Extract hashes from sysmon EventID 1 (Hashes are formatted like "MD5=...,SHA256=...")
        if "hashes" in eventdata:
            hash_str = eventdata["hashes"]
            for pair in hash_str.split(","):
                if "=" in pair:
                    alg, val = pair.split("=", 1)
                    observables.append(Observable(type="hash", value=val))

    return observables

def is_benign(parsed_alert: ParsedAlert) -> bool:
    """
    Deterministically filters out benign noise (e.g., local subnets, low severity) 
    before triggering the expensive LLM API.
    """
    # 1. Drop low severity alerts (Severity < 5 usually means info/debug)
    if parsed_alert.rule_level < 3:
        return True
        
    # 2. Drop traffic originating from loopback or specific trusted subnets
    for obs in parsed_alert.observables:
        if obs.type == "ip":
            try:
                ip = ipaddress.ip_address(obs.value)
                # Ignore loopback and link-local. 
                # (You can also add specific lab subnets like 192.168.1.0/24 here)
                if ip.is_loopback or ip.is_link_local:
                    return True
            except ValueError:
                pass
                
    return False

def parse_wazuh_alert(payload: Dict[str, Any]) -> ParsedAlert:
    """
    Parses a raw Wazuh webhook JSON payload into a structured ParsedAlert model.
    """
    # Wazuh webhook integration wraps the actual alert in 'all_fields'
    actual_alert = payload.get("all_fields", payload)
    
    rule = actual_alert.get("rule", {})
    agent = actual_alert.get("agent", {})
    
    alert = ParsedAlert(
        alert_id=actual_alert.get("id", str(payload.get("id", "unknown"))),
        rule_id=str(rule.get("id", payload.get("rule_id", "unknown"))),
        rule_level=rule.get("level", 0),
        rule_description=rule.get("description", payload.get("title", "No description provided")),
        agent_id=str(agent.get("id", "unknown")),
        agent_name=agent.get("name", "unknown"),
        agent_ip=agent.get("ip", "unknown"),
        observables=extract_observables(actual_alert),
        raw_payload=payload
    )
    return alert
