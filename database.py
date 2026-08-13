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
                ml_sba_score REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            cursor.execute("ALTER TABLE alerts ADD COLUMN ml_sba_score REAL")
        except sqlite3.OperationalError:
            pass # Column already exists
            
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS sba_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT,
                agent_name TEXT,
                score REAL,
                severity TEXT,
                nature TEXT,
                factors TEXT
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

def update_alert_status(db_id: int, status: str, decision: dict = None, sba_score: float = None):
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        if decision:
            if sba_score is not None:
                cursor.execute("""
                    UPDATE alerts SET status = ?, decision = ?, ml_sba_score = ? WHERE id = ?
                """, (status, json.dumps(decision), sba_score, db_id))
            else:
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
            SELECT wazuh_alert_id, timestamp, rule_description, agent_name, agent_ip, decision, ml_sba_score 
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
                "ml_sba_score": row["ml_sba_score"],
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

def insert_sba_history(results: list):
    """Inserts background SBA inference results into the database for time-series tracking."""
    if not results:
        return
        
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        for r in results:
            cursor.execute("""
                INSERT INTO sba_history (timestamp, agent_name, score, severity, nature, factors)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                r.get("timestamp"),
                r.get("host"),
                r.get("ml_sba_score"),
                r.get("anomaly_severity"),
                r.get("anomaly_nature"),
                json.dumps(r.get("sba_contributing_factors", []))
            ))
        conn.commit()

def get_unique_agents():
    """Fetches a list of all unique agent names that have SBA history."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT DISTINCT agent_name FROM sba_history WHERE agent_name IS NOT NULL ORDER BY agent_name ASC")
        return [row[0] for row in cursor.fetchall()]

def get_sba_history(limit=50, agent_name=None):
    """Fetches the most recent background SBA scores for the dashboard."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        if agent_name:
            cursor.execute("""
                SELECT id, timestamp, agent_name, score, severity, nature, factors
                FROM sba_history 
                WHERE agent_name = ?
                ORDER BY id DESC 
                LIMIT ?
            """, (agent_name, limit))
        else:
            cursor.execute("""
                SELECT id, timestamp, agent_name, score, severity, nature, factors
                FROM sba_history 
                ORDER BY id DESC 
                LIMIT ?
            """, (limit,))
        
        results = []
        for row in cursor.fetchall():
            results.append({
                "id": row["id"],
                "timestamp": row["timestamp"],
                "agent_name": row["agent_name"],
                "score": row["score"],
                "severity": row["severity"],
                "nature": row["nature"],
                "factors": json.loads(row["factors"]) if row["factors"] else []
            })
        # Reverse to get chronological order for charting
        return results[::-1]
