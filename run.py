#!/usr/bin/env python3
import sys
import os

# Ajouter le répertoire src au path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from database import init_database
from app import app
import argparse

def main():
    parser = argparse.ArgumentParser(description='Système Anti-Brute Force')
    parser.add_argument('--init-db', action='store_true', help='Initialiser la base de données')
    parser.add_argument('--host', default='0.0.0.0', help='Adresse IP du serveur')
    parser.add_argument('--port', type=int, default=5000, help='Port du serveur')
    parser.add_argument('--debug', action='store_true', help='Mode debug')
    
    args = parser.parse_args()
    
    if args.init_db:
        print("🗃️ Initialisation de la base de données...")
        init_database()
        print("✅ Base de données initialisée avec succès!")
        return
    
    # Démarrer l'application
    print(f"🚀 Démarrage du serveur sur {args.host}:{args.port}")
    print("📊 Interface web: http://localhost:5000")
    print("🔐 Tableau de bord: http://localhost:5000/dashboard")
    print("🔑 Comptes de test: admin/admin123, user/user123, test/test123")
    print("⏹️  Appuyez sur Ctrl+C pour arrêter le serveur")
    
    app.run(
        host=args.host,
        port=args.port,
        debug=args.debug
    )

if __name__ == '__main__':
    main()
