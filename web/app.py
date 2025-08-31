"""
Веб-интерфейс администратора для CASB системы
Flask приложение с современным дизайном

Автор: AI Assistant
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, flash
from flask_cors import CORS
import json
import logging
import os
import sys
from datetime import datetime, timedelta
from functools import wraps

# Добавляем корневую директорию в путь для импорта модулей CASB
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.casb import CASBCore, AccessLevel, CloudProvider, ThreatLevel
from auth.mfa_auth import MFAAuthenticator
from monitoring.cloud_monitor import CloudActivityMonitor, EventType, Severity
from dlp.data_protection import DataProtectionEngine, DataClassification
from policies.policy_engine import PolicyEngine, PolicyType, PolicyScope

# Настройка логирования
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'casb_web_secret_key_change_in_production'
CORS(app)

# Инициализация компонентов CASB
casb_core = CASBCore()
mfa_auth = MFAAuthenticator(casb_core.db_path)
cloud_monitor = CloudActivityMonitor(casb_core.db_path)
dlp_engine = DataProtectionEngine(casb_core.db_path)
policy_engine = PolicyEngine(casb_core.db_path)

def login_required(f):
    """Декоратор для проверки авторизации"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_token' not in session:
            return redirect(url_for('login'))
        
        user_id = casb_core.validate_session_token(session['user_token'])
        if not user_id:
            session.pop('user_token', None)
            return redirect(url_for('login'))
        
        return f(*args, **kwargs)
    return decorated_function

def get_current_user():
    """Получение текущего пользователя"""
    if 'user_token' not in session:
        return None
    
    user_id = casb_core.validate_session_token(session['user_token'])
    if user_id:
        return casb_core._get_user(user_id)
    
    return None

@app.route('/')
def index():
    """Главная страница"""
    if 'user_token' in session:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Страница входа"""
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        
        token = casb_core.authenticate_user(username, password, ip_address)
        
        if token:
            session['user_token'] = token
            session['username'] = username
            flash('Вход выполнен успешно', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Неверные учетные данные', 'error')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Выход из системы"""
    session.clear()
    flash('Выход выполнен успешно', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    """Главная панель управления"""
    # Получаем метрики
    casb_metrics = casb_core.get_dashboard_metrics()
    monitoring_metrics = cloud_monitor.get_activity_dashboard(hours=24)
    dlp_metrics = dlp_engine.get_dlp_dashboard(days=7)
    policy_metrics = policy_engine.get_policy_statistics(days=7)
    
    current_user = get_current_user()
    
    return render_template('dashboard.html', 
                         casb_metrics=casb_metrics,
                         monitoring_metrics=monitoring_metrics,
                         dlp_metrics=dlp_metrics,
                         policy_metrics=policy_metrics,
                         current_user=current_user)

@app.route('/users')
@login_required
def users():
    """Управление пользователями"""
    return render_template('users.html')

@app.route('/services')
@login_required
def services():
    """Управление облачными сервисами"""
    return render_template('services.html')

@app.route('/monitoring')
@login_required
def monitoring():
    """Мониторинг активности"""
    timeline = cloud_monitor.get_threat_timeline(hours=24)
    return render_template('monitoring.html', timeline=timeline)

@app.route('/dlp')
@login_required
def dlp():
    """Data Loss Prevention"""
    quarantine_list = dlp_engine.get_quarantine_list()
    scan_history = dlp_engine.get_scan_history(days=7)
    
    return render_template('dlp.html', 
                         quarantine_list=quarantine_list,
                         scan_history=scan_history)

@app.route('/policies')
@login_required
def policies():
    """Управление политиками"""
    return render_template('policies.html')

@app.route('/reports')
@login_required
def reports():
    """Отчеты и аналитика"""
    return render_template('reports.html')

# API endpoints

@app.route('/api/users', methods=['GET', 'POST'])
@login_required
def api_users():
    """API для управления пользователями"""
    if request.method == 'POST':
        data = request.json
        try:
            user = casb_core.create_user(
                username=data['username'],
                email=data['email'],
                department=data['department'],
                access_level=AccessLevel(data['access_level']),
                password=data['password']
            )
            return jsonify({'success': True, 'user_id': user.user_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    # GET - возвращаем список пользователей (упрощенная версия)
    return jsonify({'users': []})

@app.route('/api/services', methods=['GET', 'POST'])
@login_required
def api_services():
    """API для управления облачными сервисами"""
    if request.method == 'POST':
        data = request.json
        try:
            service = casb_core.register_cloud_service(
                name=data['name'],
                provider=CloudProvider(data['provider']),
                endpoint=data['endpoint'],
                api_key=data['api_key'],
                service_type=data['service_type'],
                risk_level=ThreatLevel(data['risk_level'])
            )
            return jsonify({'success': True, 'service_id': service.service_id})
        except Exception as e:
            return jsonify({'success': False, 'error': str(e)}), 400
    
    return jsonify({'services': []})

@app.route('/api/access-request', methods=['POST'])
@login_required
def api_access_request():
    """API для запроса доступа"""
    data = request.json
    current_user = get_current_user()
    
    if not current_user:
        return jsonify({'success': False, 'error': 'Не авторизован'}), 401
    
    try:
        access_request = casb_core.request_access(
            user_id=current_user.user_id,
            service_id=data['service_id'],
            action=data['action'],
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', '')
        )
        
        return jsonify({
            'success': True,
            'request_id': access_request.request_id,
            'approved': access_request.approved,
            'risk_score': access_request.risk_score
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/mfa/setup', methods=['POST'])
@login_required
def api_mfa_setup():
    """API для настройки MFA"""
    data = request.json
    current_user = get_current_user()
    
    if not current_user:
        return jsonify({'success': False, 'error': 'Не авторизован'}), 401
    
    try:
        method_type = data['method_type']
        
        if method_type == 'totp':
            secret, qr_code = mfa_auth.setup_totp(current_user.user_id, current_user.username)
            return jsonify({
                'success': True,
                'secret': secret,
                'qr_code': qr_code
            })
        elif method_type == 'sms':
            method_id = mfa_auth.setup_sms(current_user.user_id, data['phone_number'])
            return jsonify({'success': True, 'method_id': method_id})
        elif method_type == 'email':
            method_id = mfa_auth.setup_email(current_user.user_id, data['email'])
            return jsonify({'success': True, 'method_id': method_id})
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/dlp/scan', methods=['POST'])
@login_required
def api_dlp_scan():
    """API для сканирования контента"""
    data = request.json
    current_user = get_current_user()
    
    try:
        report = dlp_engine.scan_content(
            content=data['content'],
            file_name=data.get('file_name', ''),
            file_size=len(data['content'].encode()),
            user_id=current_user.user_id if current_user else ''
        )
        
        return jsonify({
            'success': True,
            'scan_id': report.scan_id,
            'classification': report.classification.value,
            'risk_score': report.risk_score,
            'patterns_found': len(report.patterns_found),
            'action_taken': report.action_taken.value,
            'scan_result': report.scan_result.value
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/monitoring/events')
@login_required
def api_monitoring_events():
    """API для получения событий мониторинга"""
    hours = request.args.get('hours', 24, type=int)
    
    try:
        dashboard_data = cloud_monitor.get_activity_dashboard(hours=hours)
        timeline = cloud_monitor.get_threat_timeline(hours=hours)
        
        return jsonify({
            'success': True,
            'dashboard': dashboard_data,
            'timeline': timeline
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/policies/evaluate', methods=['POST'])
@login_required
def api_policies_evaluate():
    """API для оценки политик"""
    context = request.json
    
    try:
        evaluations = policy_engine.evaluate_policies(context)
        execution_results = policy_engine.execute_policy_actions(evaluations)
        
        return jsonify({
            'success': True,
            'evaluations': len(evaluations),
            'matched_policies': len([e for e in evaluations if e.matched]),
            'execution_results': execution_results
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.route('/api/stats/summary')
@login_required
def api_stats_summary():
    """API для получения сводной статистики"""
    try:
        summary = {
            'casb': casb_core.get_dashboard_metrics(),
            'monitoring': cloud_monitor.get_activity_dashboard(hours=24),
            'dlp': dlp_engine.get_dlp_dashboard(days=7),
            'policies': policy_engine.get_policy_statistics(days=7),
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({'success': True, 'summary': summary})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400

@app.errorhandler(404)
def not_found(error):
    return render_template('error.html', error_code=404, error_message="Страница не найдена"), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('error.html', error_code=500, error_message="Внутренняя ошибка сервера"), 500

if __name__ == '__main__':
    # Создаем директории для шаблонов и статических файлов
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
