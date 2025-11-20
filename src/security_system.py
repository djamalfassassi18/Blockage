import sqlite3
import threading
from datetime import datetime, timedelta
import logging

logger = logging.getLogger(__name__)

class AntiBruteForceSystem:
    def __init__(self, db_path='security.db'):
        self.db_path = db_path
        self.max_attempts = 5
        self.time_window = 900  # 15 minutes en secondes
        self.block_duration = 3600  # 1 heure en secondes
        self.lock = threading.Lock()
        
    def record_login_attempt(self, ip_address, username, success):
        """Enregistre une tentative de connexion"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    '''INSERT INTO login_attempts 
                    (ip_address, username, success, attempt_time) 
                    VALUES (?, ?, ?, ?)''',
                    (ip_address, username, 1 if success else 0, datetime.now())
                )
                conn.commit()
        except Exception as e:
            logger.error(f"Erreur enregistrement tentative: {str(e)}")

    def get_recent_failed_attempts(self, ip_address):
        """Récupère les tentatives échouées récentes pour une IP"""
        time_threshold = datetime.now() - timedelta(seconds=self.time_window)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    '''SELECT COUNT(*) FROM login_attempts 
                    WHERE ip_address = ? AND success = 0 AND attempt_time > ?''',
                    (ip_address, time_threshold)
                )
                return cursor.fetchone()[0]
        except Exception as e:
            logger.error(f"Erreur récupération tentatives: {str(e)}")
            return 0

    def is_ip_blocked(self, ip_address):
        """Vérifie si une IP est actuellement bloquée"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute(
                    '''SELECT 1 FROM blocked_ips 
                    WHERE ip_address = ? AND unblock_time > ?''',
                    (ip_address, datetime.now())
                )
                return cursor.fetchone() is not None
        except Exception as e:
            logger.error(f"Erreur vérification blocage: {str(e)}")
            return False

    def block_ip(self, ip_address, reason="Tentatives de connexion excessives"):
        """Bloque une IP pour la durée définie"""
        try:
            unblock_time = datetime.now() + timedelta(seconds=self.block_duration)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    '''INSERT OR REPLACE INTO blocked_ips 
                    (ip_address, block_reason, block_time, unblock_time) 
                    VALUES (?, ?, ?, ?)''',
                    (ip_address, reason, datetime.now(), unblock_time)
                )
                conn.commit()
            
            logger.warning(f"IP bloquée: {ip_address} - Raison: {reason}")
            return True
        except Exception as e:
            logger.error(f"Erreur blocage IP: {str(e)}")
            return False

    def check_and_block(self, ip_address, username):
        """Vérifie les tentatives et bloque si nécessaire"""
        with self.lock:
            if self.is_ip_blocked(ip_address):
                return False, "Votre adresse IP est temporairement bloquée pour cause de tentatives de connexion excessives. Veuillez réessayer dans 1 heure."
            
            failed_attempts = self.get_recent_failed_attempts(ip_address)
            
            if failed_attempts >= self.max_attempts:
                self.block_ip(ip_address)
                return False, "Trop de tentatives de connexion échouées. Votre adresse IP a été bloquée temporairement."
            
            return True, f"Tentatives récentes: {failed_attempts}/{self.max_attempts}"

    def unblock_ip(self, ip_address):
        """Débloque manuellement une IP"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'DELETE FROM blocked_ips WHERE ip_address = ?',
                    (ip_address,)
                )
                conn.commit()
            
            logger.info(f"IP débloquée manuellement: {ip_address}")
            return True
        except Exception as e:
            logger.error(f"Erreur déblocage IP: {str(e)}")
            return False

    def get_security_stats(self):
        """Récupère les statistiques de sécurité"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Nombre d'IPs bloquées
                cursor = conn.execute(
                    'SELECT COUNT(*) FROM blocked_ips WHERE unblock_time > ?',
                    (datetime.now(),)
                )
                blocked_count = cursor.fetchone()[0]

                # Tentatives échouées dernières 24h
                time_threshold = datetime.now() - timedelta(hours=24)
                cursor = conn.execute(
                    'SELECT COUNT(*) FROM login_attempts WHERE success = 0 AND attempt_time > ?',
                    (time_threshold,)
                )
                failed_attempts = cursor.fetchone()[0]

                # Total des connexions
                cursor = conn.execute('SELECT COUNT(*) FROM login_attempts')
                total_attempts = cursor.fetchone()[0]

                # Top IPs suspectes
                cursor = conn.execute('''
                    SELECT ip_address, COUNT(*) as attempts 
                    FROM login_attempts 
                    WHERE success = 0 AND attempt_time > ?
                    GROUP BY ip_address 
                    ORDER BY attempts DESC 
                    LIMIT 5
                ''', (time_threshold,))
                top_suspicious = cursor.fetchall()

            return {
                'blocked_ips': blocked_count,
                'failed_attempts_24h': failed_attempts,
                'total_attempts': total_attempts,
                'top_suspicious': [
                    {'ip': row[0], 'attempts': row[1]} for row in top_suspicious
                ]
            }
        except Exception as e:
            logger.error(f"Erreur statistiques: {str(e)}")
            return {}

    def get_blocked_ips(self):
        """Récupère la liste des IPs bloquées"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.execute('''
                    SELECT ip_address, block_reason, block_time, unblock_time 
                    FROM blocked_ips 
                    WHERE unblock_time > ?
                    ORDER BY block_time DESC
                ''', (datetime.now(),))
                
                blocked_ips = []
                for row in cursor.fetchall():
                    blocked_ips.append({
                        'ip_address': row[0],
                        'reason': row[1],
                        'block_time': row[2],
                        'unblock_time': row[3],
                        'time_remaining': str((datetime.fromisoformat(row[3]) - datetime.now()).seconds // 60) + ' min'
                    })
                
                return blocked_ips
        except Exception as e:
            logger.error(f"Erreur récupération IPs bloquées: {str(e)}")
            return []

    def cleanup_old_records(self):
        """Nettoie les anciennes entrées de la base de données"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Supprime les tentatives de connexion vieilles de 7 jours
                old_attempts = datetime.now() - timedelta(days=7)
                conn.execute('DELETE FROM login_attempts WHERE attempt_time < ?', (old_attempts,))
                
                # Supprime les IPs débloquées
                conn.execute('DELETE FROM blocked_ips WHERE unblock_time < ?', (datetime.now(),))
                
                conn.commit()
            
            logger.info("Nettoyage des anciens enregistrements effectué")
        except Exception as e:
            logger.error(f"Erreur nettoyage: {str(e)}")
