from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from agent.prompts import SYSTEM_PROMPT
from agent.tools_wrapper import agent_tools
from config import settings
from ingest.wazuh_parser import ParsedAlert
import json
import logging

logger = logging.getLogger(__name__)

class SOCAgent:
    def __init__(self):
        self.llm = ChatGoogleGenerativeAI(
            model="gemini-3.1-flash-lite", 
            api_key=settings.gemini_api_key,
            temperature=0
        )
        
        self.agent = create_react_agent(
            self.llm, 
            tools=agent_tools,
            prompt=SYSTEM_PROMPT
        )

    async def investigate_alert(self, alert: ParsedAlert) -> dict:
        """
        Executes the autonomous reasoning loop for a parsed alert.
        Returns the structured JSON triage decision.
        """
        logger.info(f"Starting agentic investigation for alert {alert.alert_id}")
        alert_json = json.dumps(alert.model_dump(), indent=2)
        
        try:
            inputs = {"messages": [("user", f"Investigate the following Wazuh alert:\n\n{alert_json}")]}
            
            reasoning_chain = []
            final_content = ""
            
            async for event in self.agent.astream(inputs, stream_mode="values"):
                last_message = event["messages"][-1]
                
                if last_message.type == "ai" and last_message.content:
                    content_val = last_message.content
                    if isinstance(content_val, list):
                        blocks = []
                        for block in content_val:
                            if isinstance(block, dict) and "text" in block:
                                blocks.append(block["text"])
                            elif isinstance(block, str):
                                blocks.append(block)
                        content_val = "".join(blocks)
                        
                    reasoning_chain.append({
                        "type": "thought",
                        "content": content_val
                    })
                    final_content = content_val
                elif last_message.type == "ai" and getattr(last_message, "tool_calls", None):
                    for tc in last_message.tool_calls:
                        logger.info(f"[Agent] Action: {tc['name']} with args: {tc['args']}")
                        reasoning_chain.append({
                            "type": "action",
                            "tool": tc['name'],
                            "args": tc['args']
                        })
                elif last_message.type == "tool":
                    content_str = str(last_message.content)
                    logger.info(f"[Agent] Observation: {last_message.name} returned {content_str[:150]}...")
                    try:
                        parsed_content = json.loads(content_str)
                    except Exception:
                        parsed_content = content_str
                    
                    reasoning_chain.append({
                        "type": "observation",
                        "tool": last_message.name,
                        "content": parsed_content
                    })
            
            output = final_content
            
            if isinstance(output, list):
                text_blocks = []
                for block in output:
                    if isinstance(block, dict) and "text" in block:
                        text_blocks.append(block["text"])
                    elif isinstance(block, str):
                        text_blocks.append(block)
                output = "".join(text_blocks)
            
            if isinstance(output, str):
                if "```json" in output:
                    output = output.split("```json")[1].split("```")[0].strip()
                if output.startswith("```") and output.endswith("```"):
                    output = output.strip("```").strip()
            
            decision = json.loads(output)
            decision["alert_id"] = alert.alert_id
            
            # The final AI message is just the JSON output, which we intercepted as a 'thought'. 
            # We remove it so it doesn't render as a massive JSON block in the UI.
            if reasoning_chain and reasoning_chain[-1].get("type") == "thought" and "{" in str(reasoning_chain[-1].get("content")):
                reasoning_chain.pop()
            
            # The AI generates a nice string-based reasoning_chain in its JSON output.
            # We want to show that story to the user, BUT we also want to append our rich 
            # Action and Observation JSON blocks for maximum glass-box transparency.
            ai_chain = decision.get("reasoning_chain", [])
            decision["reasoning_chain"] = ai_chain + reasoning_chain
                
            return decision
        except Exception as e:
            logger.error(f"Agent failed during investigation: {e}")
            return {
                "alert_id": alert.alert_id,
                "verdict": "SUSPICIOUS_NEEDS_HUMAN",
                "confidence_score": 0.0,
                "summary": f"Investigation aborted. API Error or Invalid Output: {str(e)}",
                "recommended_action": "ESCALATE",
                "reasoning_chain": reasoning_chain + [{"type": "error", "content": f"CRASH: {str(e)}"}]
            }
