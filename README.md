
# 🔐 Système Anti-Brute Force avec Blocage Automatique

Un système de sécurité complet pour détecter et bloquer automatiquement les attaques par brute force.

## 🚀 Fonctionnalités

- **Détection en temps réel** des tentatives de connexion répétées
- **Blocage automatique** des IPs suspectes
- **Interface web** intuitive pour la gestion
- **Tableau de bord** de surveillance en temps réel
- **API RESTful** pour l'intégration
- **Base de données sécurisée** avec historique

## 🛠️ Installation

### Prérequis
- Python 3.8+
- pip

### Installation rapide
```bash
# Cloner le dépôt
git clone https://github.com/votre-username/anti-brute-force.git
cd anti-brute-force

# Créer l'environnement virtuel
python3 -m venv venv
source venv/bin/activate

# Installer les dépendances
pip install -r requirements.txt

# Initialiser la base de données
python run.py --init-db

# Démarrer l'application
python run.py