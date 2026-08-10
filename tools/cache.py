import sqlite3
import json
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class ThreatIntelCache:
    """
    Local SQLite Cache for Threat Intelligence API results.
    Prevents burning API tokens/rate limits for identical IoCs.
    """
    def __init__(self, db_path: str = "soc_cache.db"):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.cursor = self.conn.cursor()
        self._init_db()

    def _init_db(self):
        self.cursor.execute('''
            CREATE TABLE IF NOT EXISTS ioc_cache (
                ioc_value TEXT PRIMARY KEY,
                ioc_type TEXT,
                data TEXT,
                timestamp DATETIME
            )
        ''')
        self.conn.commit()

    def get(self, ioc_value: str, max_age_hours: int = 24) -> Optional[Dict[str, Any]]:
        self.cursor.execute('SELECT data, timestamp FROM ioc_cache WHERE ioc_value = ?', (ioc_value,))
        row = self.cursor.fetchone()
        if row:
            data_json, timestamp_str = row
            timestamp = datetime.fromisoformat(timestamp_str)
            # If the cache entry is still fresh
            if datetime.now() - timestamp < timedelta(hours=max_age_hours):
                return json.loads(data_json)
            else:
                logger.info(f"[Cache Expired] {ioc_value}")
        return None

    def set(self, ioc_value: str, ioc_type: str, data: Dict[str, Any]):
        timestamp_str = datetime.now().isoformat()
        self.cursor.execute('''
            INSERT OR REPLACE INTO ioc_cache (ioc_value, ioc_type, data, timestamp)
            VALUES (?, ?, ?, ?)
        ''', (ioc_value, ioc_type, json.dumps(data), timestamp_str))
        self.conn.commit()
