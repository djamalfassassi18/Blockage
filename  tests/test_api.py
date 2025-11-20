import unittest
import tempfile
import os
import sys
from unittest.mock import patch

# Ajouter le répertoire src au path
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'src'))

from app import app
from database import init_database

class TestAPI(unittest.TestCase):
    
    def setUp(self):
        """Configuration avant chaque test"""
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Base de données temporaire
        self.db_fd, self.db_path = tempfile.mkstemp()
        app.config['DATABASE_PATH'] = self.db_path
        
        self.client = app.test_client()
        init_database(self.db_path)
    
    def tearDown(self):
        """Nettoyage après chaque test"""
        os.close(self.db_fd)
        os.unlink(self.db_path)
    
    def test_login_success(self):
        """Test une connexion réussie"""
        with patch('app.check_credentials') as mock_check:
            mock_check.return_value = True
            
            response = self.client.post('/api/login', 
                json={'username': 'admin', 'password': 'admin123'},
                headers={'Content-Type': 'application/json'}
            )
            
            data = response.get_json()
            self.assertEqual(response.status_code, 200)
            self.assertTrue(data['success'])
            self.assertIn('Connexion réussie', data['message'])
    
    def test_login_failure(self):
        """Test un échec de connexion"""
        with patch('app.check_credentials') as mock_check:
            mock_check.return_value = False
            
            response = self.client.post('/api/login', 
                json={'username': 'admin', 'password': 'wrong'},
                headers={'Content-Type': 'application/json'}
            )
            
            data = response.get_json()
            self.assertEqual(response.status_code, 200)
            self.assertFalse(data['success'])
            self.assertIn('incorrects', data['message'])
    
    def test_login_blocked_ip(self):
        """Test la réponse pour une IP bloquée"""
        # Simuler une IP bloquée
        with patch('app.security_system.check_and_block') as mock_check:
            mock_check.return_value = (False, "IP bloquée")
            
            response = self.client.post('/api/login', 
                json={'username': 'admin', 'password': 'admin123'},
                headers={'Content-Type': 'application/json'}
            )
            
            data = response.get_json()
            self.assertEqual(response.status_code, 403)
            self.assertFalse(data['success'])
            self.assertTrue(data['blocked'])
    
    def test_stats_unauthorized(self):
        """Test l'accès non autorisé aux statistiques"""
        response = self.client.get('/api/stats')
        self.assertEqual(response.status_code, 401)
    
    def test_blocked_ips_unauthorized(self):
        """Test l'accès non autorisé à la liste des IPs bloquées"""
        response = self.client.get('/api/blocked-ips')
        self.assertEqual(response.status_code, 401)

if __name__ == '__main__':
    unittest.main()