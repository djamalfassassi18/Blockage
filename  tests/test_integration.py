import unittest
import tempfile
import os
import sys
import time

# Ajouter le répertoire src au path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from security_system import AntiBruteForceSystem
from database import init_database

class TestIntegration(unittest.TestCase):
    
    def setUp(self):
        """Configuration avant chaque test"""
        self.db_fd, self.db_path = tempfile.mkstemp()
        self.security_system = AntiBruteForceSystem(self.db_path)
        self.security_system.max_attempts = 3
        self.security_system.time_window = 2  # 2 secondes pour les tests
        init_database(self.db_path)
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_complete_attack_scenario(self):
        """Test un scénario complet d'attaque et de défense"""
        attacker_ip = "192.168.1.200"
        username = "victim"
        
        print("\n=== Scénario d'Attaque Brute Force ===")
        
        # Phase 1: Tentatives légitimes
        print("Phase 1: Tentatives normales")
        for i in range(2):
            allowed, message = self.security_system.check_and_block(attacker_ip, username)
            self.security_system.record_login_attempt(attacker_ip, username, False)
            print(f"  Tentative {i+1}: {message}")
            self.assertTrue(allowed)
        
        # Phase 2: Dépassement du seuil
        print("Phase 2: Dépassement du seuil")
        allowed, message = self.security_system.check_and_block(attacker_ip, username)
        self.security_system.record_login_attempt(attacker_ip, username, False)
        print(f"  Tentative 3: {message}")
        
        # Vérifier le blocage
        allowed, message = self.security_system.check_and_block(attacker_ip, username)
        print(f"  Statut après blocage: {message}")
        self.assertFalse(allowed)
        self.assertIn("bloquée", message)
        
        # Phase 3: Tentative après blocage
        print("Phase 3: Tentative après blocage")
        allowed, message = self.security_system.check_and_block(attacker_ip, username)
        print(f"  Tentative bloquée: {message}")
        self.assertFalse(allowed)
        
        # Vérifier les statistiques
        stats = self.security_system.get_security_stats()
        print(f"  IPs bloquées: {stats['blocked_ips']}")
        self.assertEqual(stats['blocked_ips'], 1)
        
        print("=== Scénario terminé avec succès ===")
    
    def test_multiple_ips(self):
        """Test avec plusieurs IPs simultanées"""
        ips = ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
        
        for ip in ips:
            # Chaque IP dépasse le seuil
            for i in range(self.security_system.max_attempts + 1):
                self.security_system.record_login_attempt(ip, "user", False)
        
        # Vérifier que toutes les IPs sont bloquées
        stats = self.security_system.get_security_stats()
        self.assertEqual(stats['blocked_ips'], len(ips))
        
        # Vérifier chaque IP individuellement
        for ip in ips:
            self.assertTrue(self.security_system.is_ip_blocked(ip))

if __name__ == '__main__':
    unittest.main()