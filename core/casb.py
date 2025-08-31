"""
Cloud Access Security Broker (CASB) - Российский аналог
Система контроля доступа к облачным сервисам

Автор: AI Assistant
Версия: 1.0
"""

import asyncio
import json
import logging
import hashlib
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, asdict
import sqlite3
import threading
from cryptography.fernet import Fernet
import requests
import jwt

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('casb.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class CloudProvider(Enum):
    """Поддерживаемые облачные провайдеры"""
    AWS = "aws"
    AZURE = "azure"
    GOOGLE_CLOUD = "gcp"
    YANDEX_CLOUD = "yandex"
    MAIL_RU_CLOUD = "mailru"
    SBERCLOUD = "sber"
    CUSTOM = "custom"

class AccessLevel(Enum):
    """Уровни доступа"""
    READ_ONLY = "read"
    READ_WRITE = "write"
    ADMIN = "admin"
    DENIED = "denied"

class ThreatLevel(Enum):
    """Уровни угроз"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class User:
    """Модель пользователя"""
    user_id: str
    username: str
    email: str
    department: str
    access_level: AccessLevel
    mfa_enabled: bool = False
    last_login: Optional[datetime] = None
    active: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class CloudService:
    """Модель облачного сервиса"""
    service_id: str
    name: str
    provider: CloudProvider
    endpoint: str
    api_key: str
    service_type: str  # storage, compute, database, etc.
    risk_level: ThreatLevel
    enabled: bool = True

@dataclass
class AccessRequest:
    """Запрос на доступ к облачному сервису"""
    request_id: str
    user_id: str
    service_id: str
    requested_action: str
    timestamp: datetime
    ip_address: str
    user_agent: str
    approved: bool = False
    risk_score: float = 0.0

@dataclass
class SecurityPolicy:
    """Политика безопасности"""
    policy_id: str
    name: str
    description: str
    rules: Dict[str, Any]
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

class CASBCore:
    """Основной класс CASB системы"""
    
    def __init__(self, config_path: str = "config/casb_config.json"):
        self.config = self._load_config(config_path)
        self.db_path = self.config.get('database', 'casb.db')
        self.encryption_key = self._get_or_create_encryption_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Инициализация базы данных
        self._init_database()
        
        # Кэши
        self.users_cache = {}
        self.services_cache = {}
        self.policies_cache = {}
        
        # Метрики
        self.metrics = {
            'total_requests': 0,
            'blocked_requests': 0,
            'threat_detections': 0,
            'active_sessions': 0
        }
        
        logger.info("CASB система инициализирована")
    
    def _load_config(self, config_path: str) -> Dict:
        """Загрузка конфигурации"""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Конфигурационный файл {config_path} не найден, используются настройки по умолчанию")
            return {
                'database': 'casb.db',
                'jwt_secret': 'default_secret_change_in_production',
                'session_timeout': 3600,
                'max_failed_attempts': 5,
                'threat_threshold': 0.7
            }
    
    def _get_or_create_encryption_key(self) -> bytes:
        """Получение или создание ключа шифрования"""
        key_file = 'casb.key'
        try:
            with open(key_file, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    def _init_database(self):
        """Инициализация базы данных SQLite"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                department TEXT,
                access_level TEXT,
                mfa_enabled BOOLEAN DEFAULT FALSE,
                password_hash TEXT,
                last_login TIMESTAMP,
                active BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица облачных сервисов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_services (
                service_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                provider TEXT,
                endpoint TEXT,
                api_key_encrypted TEXT,
                service_type TEXT,
                risk_level TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица запросов доступа
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS access_requests (
                request_id TEXT PRIMARY KEY,
                user_id TEXT,
                service_id TEXT,
                requested_action TEXT,
                timestamp TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,
                approved BOOLEAN DEFAULT FALSE,
                risk_score REAL,
                FOREIGN KEY (user_id) REFERENCES users (user_id),
                FOREIGN KEY (service_id) REFERENCES cloud_services (service_id)
            )
        ''')
        
        # Таблица политик безопасности
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                rules TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица аудита
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                action TEXT,
                resource TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                result TEXT,
                details TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
        logger.info("База данных инициализирована")
    
    def encrypt_data(self, data: str) -> str:
        """Шифрование данных"""
        return self.cipher.encrypt(data.encode()).decode()
    
    def decrypt_data(self, encrypted_data: str) -> str:
        """Расшифровка данных"""
        return self.cipher.decrypt(encrypted_data.encode()).decode()
    
    def generate_user_id(self, username: str) -> str:
        """Генерация уникального ID пользователя"""
        return hashlib.sha256(f"{username}_{time.time()}".encode()).hexdigest()[:16]
    
    def generate_session_token(self, user_id: str) -> str:
        """Генерация JWT токена сессии"""
        payload = {
            'user_id': user_id,
            'exp': datetime.utcnow() + timedelta(seconds=self.config['session_timeout']),
            'iat': datetime.utcnow()
        }
        return jwt.encode(payload, self.config['jwt_secret'], algorithm='HS256')
    
    def validate_session_token(self, token: str) -> Optional[str]:
        """Валидация JWT токена"""
        try:
            payload = jwt.decode(token, self.config['jwt_secret'], algorithms=['HS256'])
            return payload['user_id']
        except jwt.ExpiredSignatureError:
            logger.warning("Истекший токен сессии")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Недействительный токен")
            return None
    
    def create_user(self, username: str, email: str, department: str, 
                   access_level: AccessLevel, password: str) -> User:
        """Создание нового пользователя"""
        user_id = self.generate_user_id(username)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        user = User(
            user_id=user_id,
            username=username,
            email=email,
            department=department,
            access_level=access_level
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO users (user_id, username, email, department, access_level, password_hash)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, username, email, department, access_level.value, password_hash))
        
        conn.commit()
        conn.close()
        
        self.users_cache[user_id] = user
        self._log_audit(user_id, "USER_CREATED", f"user:{user_id}", "SUCCESS", 
                       f"Создан пользователь {username}")
        
        logger.info(f"Создан пользователь: {username}")
        return user
    
    def authenticate_user(self, username: str, password: str, ip_address: str) -> Optional[str]:
        """Аутентификация пользователя"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, active FROM users 
            WHERE username = ? AND password_hash = ?
        ''', (username, password_hash))
        
        result = cursor.fetchone()
        conn.close()
        
        if result and result[1]:  # user exists and is active
            user_id = result[0]
            token = self.generate_session_token(user_id)
            
            # Обновляем время последнего входа
            self._update_last_login(user_id)
            
            self._log_audit(user_id, "LOGIN", f"user:{user_id}", "SUCCESS", 
                           f"Успешный вход с IP {ip_address}")
            
            logger.info(f"Успешная аутентификация пользователя: {username}")
            return token
        else:
            self._log_audit(None, "LOGIN_FAILED", f"username:{username}", "FAILURE", 
                           f"Неудачная попытка входа с IP {ip_address}")
            logger.warning(f"Неудачная попытка входа: {username}")
            return None
    
    def _update_last_login(self, user_id: str):
        """Обновление времени последнего входа"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE user_id = ?
        ''', (user_id,))
        
        conn.commit()
        conn.close()
    
    def register_cloud_service(self, name: str, provider: CloudProvider, 
                              endpoint: str, api_key: str, service_type: str,
                              risk_level: ThreatLevel) -> CloudService:
        """Регистрация облачного сервиса"""
        service_id = hashlib.sha256(f"{name}_{provider.value}_{time.time()}".encode()).hexdigest()[:16]
        
        # Шифруем API ключ
        encrypted_api_key = self.encrypt_data(api_key)
        
        service = CloudService(
            service_id=service_id,
            name=name,
            provider=provider,
            endpoint=endpoint,
            api_key=api_key,  # В объекте храним расшифрованный
            service_type=service_type,
            risk_level=risk_level
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO cloud_services 
            (service_id, name, provider, endpoint, api_key_encrypted, service_type, risk_level)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (service_id, name, provider.value, endpoint, encrypted_api_key, 
              service_type, risk_level.value))
        
        conn.commit()
        conn.close()
        
        self.services_cache[service_id] = service
        self._log_audit(None, "SERVICE_REGISTERED", f"service:{service_id}", "SUCCESS", 
                       f"Зарегистрирован сервис {name}")
        
        logger.info(f"Зарегистрирован облачный сервис: {name}")
        return service
    
    def request_access(self, user_id: str, service_id: str, action: str, 
                      ip_address: str, user_agent: str) -> AccessRequest:
        """Запрос доступа к облачному сервису"""
        request_id = hashlib.sha256(f"{user_id}_{service_id}_{action}_{time.time()}".encode()).hexdigest()[:16]
        
        access_request = AccessRequest(
            request_id=request_id,
            user_id=user_id,
            service_id=service_id,
            requested_action=action,
            timestamp=datetime.now(),
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        # Анализ рисков
        risk_score = self._calculate_risk_score(access_request)
        access_request.risk_score = risk_score
        
        # Принятие решения о доступе
        access_request.approved = self._evaluate_access_policy(access_request)
        
        # Сохранение в базу данных
        self._save_access_request(access_request)
        
        self.metrics['total_requests'] += 1
        if not access_request.approved:
            self.metrics['blocked_requests'] += 1
        
        if risk_score > self.config.get('threat_threshold', 0.7):
            self.metrics['threat_detections'] += 1
            logger.warning(f"Обнаружена потенциальная угроза: {request_id}, риск: {risk_score}")
        
        self._log_audit(user_id, "ACCESS_REQUEST", f"service:{service_id}", 
                       "APPROVED" if access_request.approved else "DENIED",
                       f"Действие: {action}, Риск: {risk_score:.2f}")
        
        return access_request
    
    def _calculate_risk_score(self, request: AccessRequest) -> float:
        """Расчет оценки риска"""
        risk_score = 0.0
        
        # Получаем информацию о пользователе и сервисе
        user = self._get_user(request.user_id)
        service = self._get_service(request.service_id)
        
        if not user or not service:
            return 1.0  # Максимальный риск для неизвестных объектов
        
        # Факторы риска:
        
        # 1. Уровень риска сервиса
        if service.risk_level == ThreatLevel.CRITICAL:
            risk_score += 0.4
        elif service.risk_level == ThreatLevel.HIGH:
            risk_score += 0.3
        elif service.risk_level == ThreatLevel.MEDIUM:
            risk_score += 0.2
        
        # 2. Время доступа (нерабочие часы)
        current_hour = request.timestamp.hour
        if current_hour < 8 or current_hour > 18:
            risk_score += 0.2
        
        # 3. Новый IP адрес
        if not self._is_known_ip(request.user_id, request.ip_address):
            risk_score += 0.3
        
        # 4. Тип действия
        dangerous_actions = ['delete', 'modify', 'admin', 'config']
        if any(action in request.requested_action.lower() for action in dangerous_actions):
            risk_score += 0.2
        
        # 5. Частота запросов
        recent_requests = self._get_recent_requests(request.user_id, minutes=10)
        if len(recent_requests) > 10:
            risk_score += 0.3
        
        return min(risk_score, 1.0)
    
    def _evaluate_access_policy(self, request: AccessRequest) -> bool:
        """Оценка запроса на основе политик безопасности"""
        user = self._get_user(request.user_id)
        service = self._get_service(request.service_id)
        
        if not user or not service or not user.active:
            return False
        
        # Проверка уровня доступа пользователя
        if user.access_level == AccessLevel.DENIED:
            return False
        
        # Проверка требования MFA для критичных сервисов
        if service.risk_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL] and not user.mfa_enabled:
            logger.warning(f"MFA требуется для доступа к {service.name}")
            return False
        
        # Проверка оценки риска
        if request.risk_score > self.config.get('threat_threshold', 0.7):
            return False
        
        # Проверка политик
        for policy in self._get_active_policies():
            if not self._check_policy_compliance(request, policy):
                logger.info(f"Запрос блокирован политикой: {policy.name}")
                return False
        
        return True
    
    def _check_policy_compliance(self, request: AccessRequest, policy: SecurityPolicy) -> bool:
        """Проверка соответствия политике безопасности"""
        rules = policy.rules
        
        # Проверка временных ограничений
        if 'time_restrictions' in rules:
            time_rules = rules['time_restrictions']
            current_hour = request.timestamp.hour
            
            if 'allowed_hours' in time_rules:
                start, end = time_rules['allowed_hours']
                if not (start <= current_hour <= end):
                    return False
        
        # Проверка IP ограничений
        if 'ip_restrictions' in rules:
            allowed_ips = rules['ip_restrictions'].get('allowed_ips', [])
            blocked_ips = rules['ip_restrictions'].get('blocked_ips', [])
            
            if blocked_ips and request.ip_address in blocked_ips:
                return False
            
            if allowed_ips and request.ip_address not in allowed_ips:
                return False
        
        # Проверка ограничений по отделам
        if 'department_restrictions' in rules:
            user = self._get_user(request.user_id)
            allowed_departments = rules['department_restrictions'].get('allowed_departments', [])
            
            if allowed_departments and user.department not in allowed_departments:
                return False
        
        return True
    
    def _save_access_request(self, request: AccessRequest):
        """Сохранение запроса доступа в базу данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO access_requests 
            (request_id, user_id, service_id, requested_action, timestamp, 
             ip_address, user_agent, approved, risk_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (request.request_id, request.user_id, request.service_id, 
              request.requested_action, request.timestamp, request.ip_address,
              request.user_agent, request.approved, request.risk_score))
        
        conn.commit()
        conn.close()
    
    def _get_user(self, user_id: str) -> Optional[User]:
        """Получение пользователя"""
        if user_id in self.users_cache:
            return self.users_cache[user_id]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM users WHERE user_id = ?', (user_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            user = User(
                user_id=result[0],
                username=result[1],
                email=result[2],
                department=result[3],
                access_level=AccessLevel(result[4]),
                mfa_enabled=bool(result[5]),
                last_login=datetime.fromisoformat(result[7]) if result[7] else None,
                active=bool(result[8])
            )
            self.users_cache[user_id] = user
            return user
        
        return None
    
    def _get_service(self, service_id: str) -> Optional[CloudService]:
        """Получение облачного сервиса"""
        if service_id in self.services_cache:
            return self.services_cache[service_id]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM cloud_services WHERE service_id = ?', (service_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            # Расшифровываем API ключ
            decrypted_api_key = self.decrypt_data(result[4])
            
            service = CloudService(
                service_id=result[0],
                name=result[1],
                provider=CloudProvider(result[2]),
                endpoint=result[3],
                api_key=decrypted_api_key,
                service_type=result[5],
                risk_level=ThreatLevel(result[6]),
                enabled=bool(result[7])
            )
            self.services_cache[service_id] = service
            return service
        
        return None
    
    def _get_active_policies(self) -> List[SecurityPolicy]:
        """Получение активных политик безопасности"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM security_policies WHERE enabled = TRUE')
        results = cursor.fetchall()
        conn.close()
        
        policies = []
        for result in results:
            policy = SecurityPolicy(
                policy_id=result[0],
                name=result[1],
                description=result[2],
                rules=json.loads(result[3]),
                enabled=bool(result[4])
            )
            policies.append(policy)
        
        return policies
    
    def _is_known_ip(self, user_id: str, ip_address: str) -> bool:
        """Проверка, является ли IP адрес известным для пользователя"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Проверяем последние 30 дней
        threshold = datetime.now() - timedelta(days=30)
        
        cursor.execute('''
            SELECT COUNT(*) FROM access_requests 
            WHERE user_id = ? AND ip_address = ? AND timestamp > ?
        ''', (user_id, ip_address, threshold))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def _get_recent_requests(self, user_id: str, minutes: int = 10) -> List[AccessRequest]:
        """Получение недавних запросов пользователя"""
        threshold = datetime.now() - timedelta(minutes=minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM access_requests 
            WHERE user_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
        ''', (user_id, threshold))
        
        results = cursor.fetchall()
        conn.close()
        
        requests = []
        for result in results:
            access_request = AccessRequest(
                request_id=result[0],
                user_id=result[1],
                service_id=result[2],
                requested_action=result[3],
                timestamp=datetime.fromisoformat(result[4]),
                ip_address=result[5],
                user_agent=result[6],
                approved=bool(result[7]),
                risk_score=result[8]
            )
            requests.append(access_request)
        
        return requests
    
    def _log_audit(self, user_id: Optional[str], action: str, resource: str, 
                   result: str, details: str, ip_address: str = "unknown"):
        """Запись в журнал аудита"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO audit_log (user_id, action, resource, ip_address, result, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (user_id, action, resource, ip_address, result, details))
        
        conn.commit()
        conn.close()
    
    def create_security_policy(self, name: str, description: str, rules: Dict[str, Any]) -> SecurityPolicy:
        """Создание политики безопасности"""
        policy_id = hashlib.sha256(f"{name}_{time.time()}".encode()).hexdigest()[:16]
        
        policy = SecurityPolicy(
            policy_id=policy_id,
            name=name,
            description=description,
            rules=rules
        )
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_policies (policy_id, name, description, rules)
            VALUES (?, ?, ?, ?)
        ''', (policy_id, name, description, json.dumps(rules, ensure_ascii=False)))
        
        conn.commit()
        conn.close()
        
        self.policies_cache[policy_id] = policy
        logger.info(f"Создана политика безопасности: {name}")
        
        return policy
    
    def get_dashboard_metrics(self) -> Dict[str, Any]:
        """Получение метрик для дашборда"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Статистика за последние 24 часа
        last_24h = datetime.now() - timedelta(hours=24)
        
        cursor.execute('''
            SELECT COUNT(*) FROM access_requests WHERE timestamp > ?
        ''', (last_24h,))
        requests_24h = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM access_requests 
            WHERE timestamp > ? AND approved = FALSE
        ''', (last_24h,))
        blocked_24h = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM access_requests 
            WHERE timestamp > ? AND risk_score > ?
        ''', (last_24h, self.config.get('threat_threshold', 0.7)))
        threats_24h = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM users WHERE active = TRUE')
        active_users = cursor.fetchone()[0]
        
        cursor.execute('SELECT COUNT(*) FROM cloud_services WHERE enabled = TRUE')
        active_services = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'metrics': self.metrics,
            'last_24h': {
                'requests': requests_24h,
                'blocked': blocked_24h,
                'threats': threats_24h
            },
            'summary': {
                'active_users': active_users,
                'active_services': active_services,
                'policies_count': len(self.policies_cache)
            }
        }
    
    def get_threat_analysis(self, days: int = 7) -> Dict[str, Any]:
        """Анализ угроз за период"""
        threshold_date = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Топ угроз по IP адресам
        cursor.execute('''
            SELECT ip_address, COUNT(*) as attempts, AVG(risk_score) as avg_risk
            FROM access_requests 
            WHERE timestamp > ? AND risk_score > ?
            GROUP BY ip_address
            ORDER BY avg_risk DESC, attempts DESC
            LIMIT 10
        ''', (threshold_date, 0.5))
        
        top_threats_ip = cursor.fetchall()
        
        # Топ заблокированных действий
        cursor.execute('''
            SELECT requested_action, COUNT(*) as blocked_count
            FROM access_requests 
            WHERE timestamp > ? AND approved = FALSE
            GROUP BY requested_action
            ORDER BY blocked_count DESC
            LIMIT 10
        ''', (threshold_date,))
        
        top_blocked_actions = cursor.fetchall()
        
        conn.close()
        
        return {
            'period_days': days,
            'top_threat_ips': [
                {'ip': ip, 'attempts': attempts, 'avg_risk': round(risk, 2)}
                for ip, attempts, risk in top_threats_ip
            ],
            'top_blocked_actions': [
                {'action': action, 'count': count}
                for action, count in top_blocked_actions
            ]
        }
    
    def export_audit_report(self, start_date: datetime, end_date: datetime) -> List[Dict]:
        """Экспорт отчета аудита"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT al.*, u.username 
            FROM audit_log al
            LEFT JOIN users u ON al.user_id = u.user_id
            WHERE al.timestamp BETWEEN ? AND ?
            ORDER BY al.timestamp DESC
        ''', (start_date, end_date))
        
        results = cursor.fetchall()
        conn.close()
        
        audit_records = []
        for result in results:
            record = {
                'log_id': result[0],
                'user_id': result[1],
                'username': result[8] if result[8] else 'Unknown',
                'action': result[2],
                'resource': result[3],
                'timestamp': result[4],
                'ip_address': result[5],
                'result': result[6],
                'details': result[7]
            }
            audit_records.append(record)
        
        return audit_records
    
    def shutdown(self):
        """Корректное завершение работы системы"""
        logger.info("Завершение работы CASB системы")
        # Очистка кэшей
        self.users_cache.clear()
        self.services_cache.clear()
        self.policies_cache.clear()

if __name__ == "__main__":
    # Пример использования
    casb = CASBCore()
    
    # Создание тестового пользователя
    user = casb.create_user(
        username="admin",
        email="admin@company.ru",
        department="IT",
        access_level=AccessLevel.ADMIN,
        password="secure_password_123"
    )
    
    # Регистрация облачного сервиса
    service = casb.register_cloud_service(
        name="Yandex Object Storage",
        provider=CloudProvider.YANDEX_CLOUD,
        endpoint="https://storage.yandexcloud.net",
        api_key="test_api_key",
        service_type="storage",
        risk_level=ThreatLevel.MEDIUM
    )
    
    print("CASB система запущена и готова к работе!")
    print(f"Создан пользователь: {user.username}")
    print(f"Зарегистрирован сервис: {service.name}")
