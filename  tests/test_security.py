import unittest
import tempfile
import os
import sys
from datetime import datetime, timedelta

# Ajouter le répertoire src au path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from security_system import AntiBruteForceSystem
from database import init_database

class TestAntiBruteForce(unittest.TestCase):
    
    def setUp(self):
        """Configuration avant chaque test"""
        # Créer une base de données temporaire
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.security_system = AntiBruteForceSystem(self.db_path)
        self.security_system.max_attempts = 3
        self.security_system.time_window = 60  # 1 minute pour les tests
        init_database(self.db_path)
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_record_login_attempt(self):
        """Test l'enregistrement des tentatives de connexion"""
        ip = "192.168.1.100"
        username = "testuser"
        
        # Enregistrer une tentative réussie
        self.security_system.record_login_attempt(ip, username, True)
        
        # Enregistrer une tentative échouée
        self.security_system.record_login_attempt(ip, username, False)
        
        # Vérifier le comptage
        failed_attempts = self.security_system.get_recent_failed_attempts(ip)
        self.assertEqual(failed_attempts, 1)
    
    def test_auto_blocking(self):
        """Test le blocage automatique après trop de tentatives"""
        ip = "192.168.1.101"
        username = "testuser"
        
        # Simuler le nombre maximum de tentatives
        for i in range(self.security_system.max_attempts):
            self.security_system.record_login_attempt(ip, username, False)
        
        # Vérifier que l'IP est bloquée
        allowed, message = self.security_system.check_and_block(ip, username)
        self.assertFalse(allowed)
        self.assertIn("bloquée", message)
    
    def test_successful_login_reset(self):
        """Test qu'une connexion réussie ne déclenche pas de blocage"""
        ip = "192.168.1.102"
        username = "testuser"
        
        # Quelques échecs
        for i in range(2):
            self.security_system.record_login_attempt(ip, username, False)
        
        # Une réussite
        self.security_system.record_login_attempt(ip, username, True)
        
        # Vérifier que l'IP n'est pas bloquée
        allowed, message = self.security_system.check_and_block(ip, username)
        self.assertTrue(allowed)
    
    def test_manual_unblock(self):
        """Test le déblocage manuel d'une IP"""
        ip = "192.168.1.103"
        username = "testuser"
        
        # Bloquer l'IP
        for i in range(self.security_system.max_attempts + 1):
            self.security_system.record_login_attempt(ip, username, False)
        
        # Vérifier qu'elle est bloquée
        self.assertTrue(self.security_system.is_ip_blocked(ip))
        
        # Débloquer manuellement
        success = self.security_system.unblock_ip(ip)
        self.assertTrue(success)
        
        # Vérifier qu'elle n'est plus bloquée
        self.assertFalse(self.security_system.is_ip_blocked(ip))
    
    def test_statistics(self):
        """Test la génération des statistiques"""
        ip1 = "192.168.1.104"
        ip2 = "192.168.1.105"
        
        # Générer quelques tentatives
        for i in range(3):
            self.security_system.record_login_attempt(ip1, "user1", False)
            self.security_system.record_login_attempt(ip2, "user2", True)
        
        # Bloquer une IP
        self.security_system.block_ip(ip1, "Test")
        
        # Récupérer les stats
        stats = self.security_system.get_security_stats()
        
        self.assertIn('blocked_ips', stats)
        self.assertIn('failed_attempts_24h', stats)
        self.assertIn('total_attempts', stats)
        self.assertIn('top_suspicious', stats)

if __name__ == '__main__':
    unittest.main()