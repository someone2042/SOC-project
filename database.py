import sqlite3
import json
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

DB_PATH = "soc_data.db"

def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                wazuh_alert_id TEXT,
                timestamp TEXT,
                rule_description TEXT,
                agent_name TEXT,
                agent_ip TEXT,
                status TEXT,
                raw_payload TEXT,
                decision TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        logger.info("Database initialized successfully.")

def insert_alert(parsed_alert, status="PENDING"):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO alerts (
                wazuh_alert_id, timestamp, rule_description, agent_name, agent_ip, status, raw_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            parsed_alert.alert_id,
            parsed_alert.raw_payload.get("timestamp", "Just now"),
            parsed_alert.rule_description,
            parsed_alert.agent_name,
            parsed_alert.agent_ip,
            status,
            json.dumps(parsed_alert.raw_payload)
        ))
        conn.commit()
        return cursor.lastrowid

def update_alert_status(db_id: int, status: str, decision: dict = None):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        if decision:
            cursor.execute("""
                UPDATE alerts SET status = ?, decision = ? WHERE id = ?
            """, (status, json.dumps(decision), db_id))
        else:
            cursor.execute("""
                UPDATE alerts SET status = ? WHERE id = ?
            """, (status, db_id))
        conn.commit()

def get_completed_alerts(limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT wazuh_alert_id, timestamp, rule_description, agent_name, agent_ip, decision 
            FROM alerts 
            WHERE status = 'COMPLETED' 
            ORDER BY id DESC 
            LIMIT ?
        """, (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "id": row["wazuh_alert_id"],
                "timestamp": row["timestamp"],
                "rule_description": row["rule_description"],
                "agent_name": row["agent_name"],
                "agent_ip": row["agent_ip"],
                "decision": json.loads(row["decision"]) if row["decision"] else None
            })
        return results

def get_pending_alerts():
    """Fetches alerts that are PENDING or PROCESSING in case of server crash/restart."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, raw_payload
            FROM alerts 
            WHERE status IN ('PENDING', 'PROCESSING')
            ORDER BY id ASC
        """)
        return [{"db_id": row["id"], "raw_payload": json.loads(row["raw_payload"])} for row in cursor.fetchall()]
