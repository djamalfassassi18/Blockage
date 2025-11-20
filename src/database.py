import sqlite3
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

def init_database(db_path='security.db'):
    """Initialise la base de données SQLite"""
    try:
        with sqlite3.connect(db_path) as conn:
            # Table des tentatives de connexion
            conn.execute('''
                CREATE TABLE IF NOT EXISTS login_attempts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    username TEXT,
                    success INTEGER DEFAULT 0,
                    attempt_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Table des IPs bloquées
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL UNIQUE,
                    block_reason TEXT,
                    block_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    unblock_time TIMESTAMP
                )
            ''')
            
            conn.commit()
        
        print("✅ Base de données initialisée avec succès")
        
    except Exception as e:
        print(f"❌ Erreur initialisation base de données: {str(e)}")
        raise

def get_db_connection(db_path='security.db'):
    """Retourne une connexion à la base de données"""
    return sqlite3.connect(db_path)
