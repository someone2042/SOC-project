import asyncio
import json
from agent.core_agent import SOCAgent
from ingest.wazuh_parser import ParsedAlert, Observable
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

async def main():
    agent = SOCAgent()
    
    # Mock Alert that is HIGH severity and should trigger an investigation
    mock_alert = ParsedAlert(
        alert_id="TEST-123",
        rule_id="100100",
        rule_level=12,
        rule_description="Suspicious PowerShell Execution (EICAR Test)",
        agent_id="001",
        agent_name="WIN-SERVER",
        agent_ip="192.168.1.50",
        observables=[
            Observable(type="hash", value="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f")
        ],
        raw_payload={"mock": "data"}
    )
    
    print("\n--- Starting Autonomous AI Investigation ---")
    decision = await agent.investigate_alert(mock_alert)
    
    print("\n--- Final Structured Decision ---")
    print(json.dumps(decision, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
