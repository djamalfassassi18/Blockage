from flask import Flask, render_template, request, jsonify, session, redirect, url_for
from security_system import AntiBruteForceSystem
import logging
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'votre_cle_secrete_tres_longue_ici_changez_moi'

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialisation des composants
security_system = AntiBruteForceSystem()

# Page de connexion
@app.route('/')
def login_page():
    return render_template('login.html')

# API de connexion
@app.route('/api/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        if not data:
            return jsonify({'success': False, 'message': 'Données JSON requises'}), 400
        
        username = data.get('username', '').strip()
        password = data.get('password', '').strip()
        ip_address = request.remote_addr

        logger.info(f"Tentative de connexion depuis {ip_address} - Utilisateur: {username}")

        # Vérification préalable de blocage
        allowed, message = security_system.check_and_block(ip_address, username)
        if not allowed:
            logger.warning(f"Connexion refusée - IP bloquée: {ip_address} - Raison: {message}")
            return jsonify({
                'success': False, 
                'message': message,
                'blocked': True
            }), 403

        # Vérification des identifiants
        is_valid = check_credentials(username, password)
        
        if is_valid:
            security_system.record_login_attempt(ip_address, username, True)
            session['user'] = username
            session['ip'] = ip_address
            session['login_time'] = datetime.now().isoformat()
            
            logger.info(f"Connexion réussie: {username} depuis {ip_address}")
            return jsonify({
                'success': True, 
                'message': 'Connexion réussie',
                'redirect': '/dashboard'
            })
        else:
            security_system.record_login_attempt(ip_address, username, False)
            failed_attempts = security_system.get_recent_failed_attempts(ip_address)
            
            logger.warning(f"Échec connexion: {username} depuis {ip_address} - Tentatives: {failed_attempts}")
            return jsonify({
                'success': False, 
                'message': 'Identifiants incorrects',
                'attempts_remaining': security_system.max_attempts - failed_attempts
            })

    except Exception as e:
        logger.error(f"Erreur lors de la connexion: {str(e)}")
        return jsonify({'success': False, 'message': 'Erreur interne du serveur'}), 500

# Tableau de bord administrateur
@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/')
    
    return render_template('dashboard.html')

# API pour les statistiques
@app.route('/api/stats')
def get_stats():
    if 'user' not in session:
        return jsonify({'error': 'Non autorisé'}), 401
    
    stats = security_system.get_security_stats()
    return jsonify(stats)

# API pour les IPs bloquées
@app.route('/api/blocked-ips')
def get_blocked_ips():
    if 'user' not in session:
        return jsonify({'error': 'Non autorisé'}), 401
    
    blocked_ips = security_system.get_blocked_ips()
    return jsonify(blocked_ips)

# API pour débloquer une IP
@app.route('/api/unblock-ip/<ip_address>', methods=['POST'])
def unblock_ip(ip_address):
    if 'user' not in session:
        return jsonify({'error': 'Non autorisé'}), 401
    
    success = security_system.unblock_ip(ip_address)
    if success:
        logger.info(f"IP débloquée manuellement: {ip_address} par {session['user']}")
        return jsonify({'success': True, 'message': f'IP {ip_address} débloquée'})
    else:
        return jsonify({'success': False, 'message': 'IP non trouvée'})

# Déconnexion
@app.route('/logout')
def logout():
    username = session.get('user')
    session.clear()
    logger.info(f"Déconnexion: {username}")
    return redirect('/')

def check_credentials(username, password):
    """
    Fonction de vérification des identifiants
    À remplacer par votre propre logique d'authentification
    """
    # Exemple simple - À ADAPTER pour la production
    valid_users = {
        'admin': 'admin123',
        'user': 'user123',
        'test': 'test123'
    }
    return valid_users.get(username) == password

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
