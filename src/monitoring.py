import threading
import time
import logging
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MimeText
from email.mime.multipart import MimeMultipart

logger = logging.getLogger(__name__)

class SecurityMonitor:
    def __init__(self, security_system, check_interval=300):  # 5 minutes
        self.security_system = security_system
        self.check_interval = check_interval
        self.alert_threshold = 10
        self.last_alert_time = None
        self.alert_cooldown = 3600  # 1 heure entre les alertes
        
        # Configuration email (à adapter)
        self.smtp_config = {
            'server': 'smtp.gmail.com',
            'port': 587,
            'username': 'votre_email@gmail.com',
            'password': 'votre_mot_de_passe_app',
            'from_email': 'security@votre-domaine.com',
            'to_email': 'admin@votre-domaine.com'
        }
        
        self.running = False
        self.thread = None

    def start_monitoring(self):
        """Démarre la surveillance en arrière-plan"""
        self.running = True
        self.thread = threading.Thread(target=self._monitoring_loop, daemon=True)
        self.thread.start()
        logger.info("Système de monitoring démarré")

    def stop_monitoring(self):
        """Arrête la surveillance"""
        self.running = False
        if self.thread:
            self.thread.join()
        logger.info("Système de monitoring arrêté")

    def _monitoring_loop(self):
        """Boucle principale de surveillance"""
        while self.running:
            try:
                self.check_security_status()
                self.security_system.cleanup_old_records()
                time.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"Erreur dans la boucle de monitoring: {str(e)}")
                time.sleep(60)  # Attendre 1 minute en cas d'erreur

    def check_security_status(self):
        """Vérifie l'état de sécurité et envoie des alertes si nécessaire"""
        try:
            stats = self.security_system.get_security_stats()
            blocked_count = stats.get('blocked_ips', 0)
            
            if blocked_count >= self.alert_threshold:
                self.send_security_alert(stats)
                
        except Exception as e:
            logger.error(f"Erreur vérification statut sécurité: {str(e)}")

    def send_security_alert(self, stats):
        """Envoie une alerte par email"""
        # Vérifier le cooldown
        if (self.last_alert_time and 
            (datetime.now() - self.last_alert_time).seconds < self.alert_cooldown):
            return

        subject = f"🚨 Alerte Sécurité - {stats['blocked_ips']} IPs bloquées"
        
        body = f"""
        ALERTE DE SÉCURITÉ - SYSTÈME ANTI-BRUTE FORCE
        
        Statut du système:
        • IPs actuellement bloquées: {stats['blocked_ips']}
        • Tentatives échouées (24h): {stats['failed_attempts_24h']}
        • Total des tentatives: {stats['total_attempts']}
        
        Top des IPs suspectes:
        """
        
        for i, ip_data in enumerate(stats.get('top_suspicious', []), 1):
            body += f"  {i}. {ip_data['ip']} - {ip_data['attempts']} tentatives\n"
        
        body += f"""
        Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        
        Veuillez vérifier le tableau de bord de sécurité pour plus de détails.
        
        Cordialement,
        Système de Sécurité Anti-Brute Force
        """
        
        try:
            self._send_email(subject, body)
            self.last_alert_time = datetime.now()
            logger.info("Alerte de sécurité envoyée")
        except Exception as e:
            logger.error(f"Erreur envoi alerte: {str(e)}")

    def _send_email(self, subject, body):
        """Envoie un email (méthode à adapter selon votre configuration SMTP)"""
        # Cette méthode est un exemple - À ADAPTER pour votre environnement
        try:
            msg = MimeMultipart()
            msg['Subject'] = subject
            msg['From'] = self.smtp_config['from_email']
            msg['To'] = self.smtp_config['to_email']
            
            text_part = MimeText(body, 'plain')
            msg.attach(text_part)
            
            # Décommentez et adaptez cette section pour envoyer des emails réels
            """
            with smtplib.SMTP(self.smtp_config['server'], self.smtp_config['port']) as server:
                server.starttls()
                server.login(self.smtp_config['username'], self.smtp_config['password'])
                server.send_message(msg)
            """
            
            # Pour l'instant, on log juste l'email
            logger.info(f"EMAIL ALERTE: {subject}\n{body}")
            
        except Exception as e:
            logger.error(f"Erreur configuration email: {str(e)}")
            raise

    def get_monitoring_stats(self):
        """Retourne les statistiques de monitoring"""
        return {
            'running': self.running,
            'last_alert': self.last_alert_time.isoformat() if self.last_alert_time else None,
            'check_interval': self.check_interval,
            'alert_threshold': self.alert_threshold
        }