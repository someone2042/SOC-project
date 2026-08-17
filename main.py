import logging
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ingest.wazuh_parser import parse_wazuh_alert, is_benign
from agent.core_agent import SOCAgent
import asyncio
import database
import sys
from datetime import datetime

# Add the microservice directory to the path so we can import the bridge
sys.path.append(os.path.join(os.path.dirname(__file__), 'sba_microservice'))
from soar_bridge_snippet import query_sba_score
from inference import run_inference

logging.basicConfig(
    level=logging.INFO, 
    format="%(asctime)s [%(levelname)s] %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="AI Autonomous SOC Platform")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the queue
alert_queue = asyncio.Queue()

# Initialize the agent
soc_agent = SOCAgent()

async def queue_worker():
    """Background worker that pulls alerts from the queue and processes them sequentially."""
    while True:
        try:
            item = await alert_queue.get()
            db_id = item["db_id"]
            raw_payload = item["raw_payload"]
            
            parsed = parse_wazuh_alert(raw_payload)
            
            logger.info(f"Processing Alert ID: {parsed.alert_id} from Queue (DB ID: {db_id})")
            database.update_alert_status(db_id, "PROCESSING")
            
            if is_benign(parsed):
                logger.info(f"Triage Decision: [DROP] Alert {parsed.rule_id} marked as benign noise.")
                database.update_alert_status(db_id, "COMPLETED", decision={
                    "verdict": "FALSE_POSITIVE",
                    "confidence_score": 1.0,
                    "summary": "Alert was dropped as benign noise during initial triage.",
                    "recommended_action": "CLOSE_TICKET",
                    "reasoning_chain": [{"type": "thought", "content": "Dropped by parser."}]
                })
            else:
                logger.info(f"Triage Decision: [ESCALATE] Alert {parsed.rule_id} requires AI investigation.")
                
                # Fetch System Behavior Analytics (SBA) Context
                alert_timestamp = parsed.raw_payload.get("timestamp") or parsed.raw_payload.get("all_fields", {}).get("timestamp") or datetime.now().isoformat()
                try:
                    logger.info(f"Fetching SBA Context for {parsed.agent_name} around {alert_timestamp}")
                    sba_context = query_sba_score(parsed.agent_name, alert_timestamp)
                    parsed.sba_context = sba_context
                    logger.info(f"SBA Context Attached to Alert:\n{json.dumps(sba_context, indent=2)}")
                except Exception as e:
                    logger.error(f"Failed to fetch SBA Context: {e}")
                
                # Log the final prompt payload for visibility
                logger.info(f"Escalating to AI Agent. Full Parsed Alert Payload:\n{parsed.model_dump_json(indent=2)}")
                
                decision = await soc_agent.investigate_alert(parsed)
                database.update_alert_status(db_id, "COMPLETED", decision, sba_score=sba_context.get("ml_sba_score") if 'sba_context' in locals() else None)
                
            alert_queue.task_done()
        except Exception as e:
            logger.error(f"Error in queue worker: {e}")
            if 'db_id' in locals():
                database.update_alert_status(db_id, "FAILED")
            await asyncio.sleep(5) # Prevent tight crash loop

async def sba_inference_worker():
    """Background worker that runs the SBA ML inference every 5 minutes (Dev Environment)."""
    logger.info("SBA Inference background worker started. Running every 5 minutes.")
    
    # Run once at startup, then loop
    while True:
        try:
            logger.info("Triggering scheduled SBA Inference Job...")
            # Run inference synchronously in a thread pool to avoid blocking the async FastAPI loop
            results = await asyncio.to_thread(run_inference, index="wazuh-archives-*")
            if results:
                database.insert_sba_history(results)
                logger.info(f"Saved {len(results)} host scores to SQLite history.")
        except Exception as e:
            logger.error(f"Error during SBA inference run: {e}")
        
        await asyncio.sleep(300) # Sleep for 5 minutes (300 seconds)

@app.on_event("startup")
async def startup_event():
    logger.info("Initializing Database...")
    database.init_db()
    
    logger.info("Loading pending alerts from database into queue...")
    pending_alerts = database.get_pending_alerts()
    for alert in pending_alerts:
        await alert_queue.put(alert)
    logger.info(f"Loaded {len(pending_alerts)} pending alerts into the queue.")
    
    # Start the background worker
    asyncio.create_task(queue_worker())
    
    # Start the dev-environment SBA inference scheduler
    asyncio.create_task(sba_inference_worker())

@app.post("/webhook/wazuh")
async def wazuh_webhook(request: Request):
    """
    Receives real-time JSON webhooks from the Wazuh Manager.
    Returns 200 OK immediately and processes the payload asynchronously.
    """
    try:
        payload = await request.json()
        parsed = parse_wazuh_alert(payload)
        
        # Insert into DB as PENDING
        db_id = database.insert_alert(parsed, status="PENDING")
        
        # Put into Queue
        await alert_queue.put({"db_id": db_id, "raw_payload": payload})
        
        return {"status": "accepted", "db_id": db_id}
    except Exception as e:
        logger.error(f"Error parsing webhook request: {e}")
        raise HTTPException(status_code=400, detail="Invalid JSON payload")

@app.get("/api/alerts")
async def get_alerts():
    """Returns the most recent completed alerts for the dashboard."""
    return database.get_completed_alerts(limit=50)

@app.get("/api/sba-history")
async def get_sba_history(agent_name: str = None):
    """Returns the background SBA ML score history for the dashboard chart."""
    return database.get_sba_history(limit=50, agent_name=agent_name)

@app.get("/api/agents")
async def get_agents():
    """Returns a list of unique agent names."""
    return database.get_unique_agents()

class SBAFeedback(BaseModel):
    agent_name: str
    timestamp: str

@app.post("/api/sba-feedback")
async def mark_sba_normal(feedback: SBAFeedback):
    """Saves user feedback to the SQLite database to mark a specific host's behavior as normal."""
    try:
        database.insert_sba_feedback(feedback.agent_name, feedback.timestamp)
        return {"status": "success"}
    except Exception as e:
        logger.error(f"Error saving SBA feedback: {e}")
        raise HTTPException(status_code=500, detail="Failed to save feedback")

# Ensure frontend directory exists
os.makedirs("frontend", exist_ok=True)
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")
