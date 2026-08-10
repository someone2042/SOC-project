import logging
import os
from fastapi import FastAPI, Request, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from ingest.wazuh_parser import parse_wazuh_alert, is_benign
from agent.core_agent import SOCAgent
import asyncio
import database

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
                decision = await soc_agent.investigate_alert(parsed)
                database.update_alert_status(db_id, "COMPLETED", decision)
                
            alert_queue.task_done()
        except Exception as e:
            logger.error(f"Error in queue worker: {e}")
            if 'db_id' in locals():
                database.update_alert_status(db_id, "FAILED")
            await asyncio.sleep(5) # Prevent tight crash loop

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
    # Only return completed alerts so the UI doesn't crash on missing 'decision'
    return database.get_completed_alerts(limit=100)

# Ensure frontend directory exists
os.makedirs("frontend", exist_ok=True)
app.mount("/static", StaticFiles(directory="frontend"), name="static")

@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")
