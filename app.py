#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
CASB Security System - Main Application
Главное приложение системы Cloud Access Security Broker
"""

import os
import sys
import yaml
import logging
from datetime import datetime
from flask import Flask, request, jsonify, render_template, redirect, url_for, flash, session
from flask_cors import CORS

# Добавление текущей директории в Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Импорт модулей CASB
try:
    from core.casb import CASBCore
    from auth.mfa_auth import MFAAuthenticator
    from monitoring.cloud_monitor import CloudActivityMonitor
    from dlp.data_protection import DataProtectionEngine
    from policies.policy_engine import PolicyEngine
    from api.cloud_integration import create_api_app
except ImportError as e:
    print(f"Ошибка импорта модулей CASB: {e}")
    print("Убедитесь что все модули находятся в правильных директориях")
    sys.exit(1)

class CASBApplication:
    """Главный класс CASB приложения"""
    
    def __init__(self, config_path=None):
        self.config_path = config_path or os.getenv('CASB_CONFIG_PATH', 'config.yaml')
        self.config = self._load_config()
        
        # Инициализация Flask приложения
        self.app = Flask(__name__)
        self._setup_flask()
        
        # Инициализация компонентов CASB
        self._init_casb_components()
        
        # Настройка маршрутов
        self._setup_routes()
        
        # Настройка логирования
        self._setup_logging()
    
    def _load_config(self):
        """Загрузка конфигурации из YAML файла"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except Exception as e:
            print(f"Ошибка загрузки конфигурации: {e}")
            # Возврат базовой конфигурации
            return {
                'system': {'secret_key': 'dev-secret-key', 'debug': True},
                'server': {'host': '0.0.0.0', 'port': 5000},
                'database': {'path': 'data/casb.db'}
            }
    
    def _setup_flask(self):
        """Настройка Flask приложения"""
        # Основные настройки
        self.app.config['SECRET_KEY'] = self.config['system']['secret_key']
        self.app.config['DEBUG'] = self.config['system'].get('debug', False)
        
        # Настройка CORS
        CORS(self.app, origins=self.config.get('api', {}).get('cors_origins', ['*']))
        
        # Настройка сессий
        self.app.config['PERMANENT_SESSION_LIFETIME'] = self.config['server'].get('session_timeout', 3600)
    
    def _init_casb_components(self):
        """Инициализация компонентов CASB"""
        db_path = self.config['database']['path']
        
        # Создание директории для базы данных
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        # Инициализация компонентов
        self.casb_core = CASBCore()
        self.mfa_auth = MFAAuthenticator(db_path)
        self.cloud_monitoring = CloudActivityMonitor(db_path)
        self.dlp_protection = DataProtectionEngine(db_path)
        self.policy_manager = PolicyEngine(db_path)
        
        # Регистрация API Blueprint
        api_app = create_api_app()
        self.app.register_blueprint(api_app, url_prefix='/api')
    
    def _setup_logging(self):
        """Настройка системы логирования"""
        log_config = self.config.get('monitoring', {})
        log_level = getattr(logging, log_config.get('log_level', 'INFO').upper())
        
        # Создание директории для логов
        log_dir = 'logs'
        os.makedirs(log_dir, exist_ok=True)
        
        # Настройка логгера
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(f'{log_dir}/casb.log'),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        self.logger = logging.getLogger('CASB')
        self.logger.info("CASB система инициализирована")
    
    def _setup_routes(self):
        """Настройка маршрутов Flask"""
        
        @self.app.route('/')
        def index():
            """Главная страница - редирект на дашборд"""
            if 'user_id' in session:
                return redirect(url_for('dashboard'))
            return redirect(url_for('login'))
        
        @self.app.route('/login', methods=['GET', 'POST'])
        def login():
            """Страница входа в систему"""
            if request.method == 'POST':
                username = request.form.get('username')
                password = request.form.get('password')
                
                # Аутентификация пользователя
                user = self.casb_core.authenticate_user(username, password)
                if user:
                    session['user_id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']
                    
                    # Логирование успешного входа
                    self.casb_core.log_audit_event(
                        user['id'], 'login', 'user', user['id'],
                        {'ip': request.remote_addr, 'user_agent': request.user_agent.string}
                    )
                    
                    flash('Вход выполнен успешно', 'success')
                    return redirect(url_for('dashboard'))
                else:
                    flash('Неверные учетные данные', 'error')
            
            return render_template('login.html')
        
        @self.app.route('/logout')
        def logout():
            """Выход из системы"""
            if 'user_id' in session:
                # Логирование выхода
                self.casb_core.log_audit_event(
                    session['user_id'], 'logout', 'user', session['user_id'],
                    {'ip': request.remote_addr}
                )
            
            session.clear()
            flash('Вы вышли из системы', 'info')
            return redirect(url_for('login'))
        
        @self.app.route('/dashboard')
        def dashboard():
            """Панель управления"""
            if 'user_id' not in session:
                return redirect(url_for('login'))
            
            # Получение статистики для дашборда
            try:
                casb_metrics = self.casb_core.get_dashboard_metrics()
                monitoring_metrics = self.cloud_monitoring.get_activity_dashboard(hours=24)
                stats = {
                    'total_requests': casb_metrics.get('metrics', {}).get('total_requests', 0),
                    'blocked_requests': casb_metrics.get('metrics', {}).get('blocked_requests', 0),
                    'threat_detections': monitoring_metrics.get('summary', {}).get('active_alerts', 0),
                    'active_users': casb_metrics.get('summary', {}).get('active_users', 0),
                    'dlp_events': 0,  # Will be implemented later
                    'active_policies': 0  # Will be implemented later
                }
            except Exception as e:
                self.logger.error(f"Ошибка получения статистики: {e}")
                stats = {
                    'total_requests': 0,
                    'blocked_requests': 0,
                    'threat_detections': 0,
                    'active_users': 0,
                    'dlp_events': 0,
                    'active_policies': 0
                }
            
            return render_template('dashboard.html', stats=stats, user=session)
        
        @self.app.route('/health')
        def health_check():
            """Health check endpoint для мониторинга"""
            try:
                # Проверка компонентов системы
                health_status = {
                    'status': 'healthy',
                    'timestamp': datetime.now().isoformat(),
                    'version': '1.0.0',
                    'components': {
                        'database': 'healthy' if self.casb_core else 'unhealthy',
                        'mfa': 'healthy' if self.mfa_auth else 'unhealthy',
                        'monitoring': 'healthy' if self.cloud_monitoring else 'unhealthy',
                        'dlp': 'healthy' if self.dlp_protection else 'unhealthy',
                        'policies': 'healthy' if self.policy_manager else 'unhealthy'
                    }
                }
                
                # Проверка базы данных
                try:
                    self.casb_core.get_user_by_id('test')
                    health_status['components']['database'] = 'healthy'
                except:
                    health_status['components']['database'] = 'unhealthy'
                    health_status['status'] = 'degraded'
                
                return jsonify(health_status), 200
                
            except Exception as e:
                self.logger.error(f"Health check failed: {e}")
                return jsonify({
                    'status': 'unhealthy',
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                }), 500
        
        @self.app.route('/metrics')
        def metrics():
            """Prometheus metrics endpoint"""
            try:
                metrics_data = self._collect_metrics()
                return metrics_data, 200, {'Content-Type': 'text/plain; charset=utf-8'}
            except Exception as e:
                self.logger.error(f"Metrics collection failed: {e}")
                return "# Metrics collection failed\n", 500
        
        @self.app.errorhandler(404)
        def not_found(error):
            """Обработка 404 ошибок"""
            return render_template('errors/404.html'), 404
        
        @self.app.errorhandler(500)
        def internal_error(error):
            """Обработка 500 ошибок"""
            self.logger.error(f"Internal server error: {error}")
            return render_template('errors/500.html'), 500
        
        @self.app.before_request
        def before_request():
            """Обработка запросов до их выполнения"""
            # Логирование запросов
            if request.endpoint not in ['health_check', 'metrics']:
                self.logger.info(f"Request: {request.method} {request.path} from {request.remote_addr}")
            
            # Проверка блокировки IP
            if self._is_ip_blocked(request.remote_addr):
                self.logger.warning(f"Blocked request from IP: {request.remote_addr}")
                return jsonify({'error': 'Access denied'}), 403
        
        @self.app.after_request
        def after_request(response):
            """Обработка ответов после их выполнения"""
            # Добавление заголовков безопасности
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            
            return response
    
    def _collect_metrics(self):
        """Сбор метрик для Prometheus"""
        metrics = []
        
        # Метрики запросов
        total_requests = len(self.casb_core.access_requests)
        blocked_requests = len([r for r in self.casb_core.access_requests if r['status'] == 'blocked'])
        
        metrics.append(f"casb_total_requests {total_requests}")
        metrics.append(f"casb_blocked_requests {blocked_requests}")
        
        # Метрики пользователей
        active_users = len([u for u in self.casb_core.users if u['is_active']])
        metrics.append(f"casb_active_users {active_users}")
        
        # Метрики безопасности
        threat_detections = len([e for e in self.cloud_monitoring.events if e['severity'] in ['high', 'critical']])
        metrics.append(f"casb_threat_detections {threat_detections}")
        
        # Метрики DLP
        dlp_events = len(self.dlp_protection.scan_results)
        high_risk_files = len([r for r in self.dlp_protection.scan_results if r.get('risk_score', 0) > 70])
        metrics.append(f"casb_dlp_events {dlp_events}")
        metrics.append(f"casb_high_risk_files {high_risk_files}")
        
        # Метрики политик
        active_policies = len([p for p in self.policy_manager.policies if p['is_active']])
        metrics.append(f"casb_active_policies {active_policies}")
        
        return '\n'.join(metrics) + '\n'
    
    def _is_ip_blocked(self, ip_address):
        """Проверка блокировки IP адреса"""
        # Простая проверка блокировки IP
        # В реальной системе здесь должна быть более сложная логика
        blocked_ips = ['192.168.1.100', '10.0.0.50']  # Пример заблокированных IP
        return ip_address in blocked_ips
    
    def run(self):
        """Запуск Flask приложения"""
        host = self.config['server'].get('host', '0.0.0.0')
        port = self.config['server'].get('port', 5000)
        debug = self.config['system'].get('debug', False)
        
        self.logger.info(f"Запуск CASB Security System на {host}:{port}")
        
        # SSL настройки
        ssl_context = None
        if self.config['server'].get('ssl_enabled', False):
            ssl_cert = self.config['server'].get('ssl_cert_path')
            ssl_key = self.config['server'].get('ssl_key_path')
            
            if ssl_cert and ssl_key and os.path.exists(ssl_cert) and os.path.exists(ssl_key):
                ssl_context = (ssl_cert, ssl_key)
                self.logger.info("SSL включен")
            else:
                self.logger.warning("SSL сертификаты не найдены, запуск без SSL")
        
        try:
            self.app.run(
                host=host,
                port=port,
                debug=debug,
                ssl_context=ssl_context,
                threaded=True
            )
        except Exception as e:
            self.logger.error(f"Ошибка запуска приложения: {e}")
            sys.exit(1)

def create_app(config_path=None):
    """Factory function для создания Flask приложения"""
    casb_app = CASBApplication(config_path)
    return casb_app.app

def main():
    """Основная функция запуска"""
    # Обработка аргументов командной строки
    if len(sys.argv) > 1:
        if sys.argv[1] in ['-h', '--help']:
            print("CASB Security System")
            print("Использование: python app.py [config_path]")
            print("  config_path - путь к файлу конфигурации (по умолчанию: config.yaml)")
            return
        elif sys.argv[1] in ['-v', '--version']:
            print("CASB Security System v1.0.0")
            return
        else:
            config_path = sys.argv[1]
    else:
        config_path = None
    
    # Создание и запуск приложения
    try:
        casb_app = CASBApplication(config_path)
        casb_app.run()
    except KeyboardInterrupt:
        print("\nОстановка CASB системы...")
    except Exception as e:
        print(f"Критическая ошибка: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()
