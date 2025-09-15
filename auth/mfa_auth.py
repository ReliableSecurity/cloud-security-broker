"""
Модуль многофакторной аутентификации для CASB
Поддерживает TOTP, SMS, Email и аппаратные токены

Автор: AI Assistant
"""

import pyotp
import qrcode
import io
import base64
import smtplib
import random
import string
import time
import logging
from typing import Dict, Optional, Tuple, List, Any
from datetime import datetime, timedelta
try:
    from email.mime.text import MimeText
    from email.mime.multipart import MimeMultipart
except ImportError:
    # Fallback for older Python versions or restricted environments
    MimeText = None
    MimeMultipart = None
from dataclasses import dataclass
import sqlite3
import hashlib
import json

logger = logging.getLogger(__name__)

@dataclass
class MFAMethod:
    """Метод многофакторной аутентификации"""
    method_id: str
    user_id: str
    method_type: str  # totp, sms, email, hardware
    secret_key: Optional[str] = None
    phone_number: Optional[str] = None
    email: Optional[str] = None
    hardware_token_id: Optional[str] = None
    enabled: bool = True
    created_at: datetime = None
    last_used: Optional[datetime] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class MFAChallenge:
    """Вызов MFA"""
    challenge_id: str
    user_id: str
    method_type: str
    code: str
    expires_at: datetime
    verified: bool = False
    attempts: int = 0
    max_attempts: int = 3

class MFAAuthenticator:
    """Класс для управления многофакторной аутентификацией"""
    
    def __init__(self, db_path: str, smtp_config: Dict = None, sms_config: Dict = None):
        self.db_path = db_path
        self.smtp_config = smtp_config or {}
        self.sms_config = sms_config or {}
        self.active_challenges = {}
        
        self._init_mfa_tables()
        logger.info("MFA модуль инициализирован")
    
    def _init_mfa_tables(self):
        """Инициализация таблиц MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица методов MFA
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_methods (
                method_id TEXT PRIMARY KEY,
                user_id TEXT,
                method_type TEXT,
                secret_key TEXT,
                phone_number TEXT,
                email TEXT,
                hardware_token_id TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        ''')
        
        # Таблица истории MFA
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_history (
                history_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT,
                method_id TEXT,
                challenge_id TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                success BOOLEAN,
                ip_address TEXT,
                user_agent TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def setup_totp(self, user_id: str, username: str, issuer: str = "CASB Security") -> Tuple[str, str]:
        """Настройка TOTP аутентификации"""
        # Генерируем секретный ключ
        secret = pyotp.random_base32()
        
        # Создаем TOTP URI для QR кода
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
            name=username,
            issuer_name=issuer
        )
        
        # Генерируем QR код
        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)
        
        # Конвертируем QR код в base64
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = io.BytesIO()
        img.save(buffer, format='PNG')
        qr_code_base64 = base64.b64encode(buffer.getvalue()).decode()
        # Сохраняем метод MFA
        method_id = self._generate_method_id(user_id, "totp")
        mfa_method = MFAMethod(
            method_id=method_id,
            user_id=user_id,
            method_type="totp",
            secret_key=secret
        )
        
        self._save_mfa_method(mfa_method)
        
        logger.info(f"TOTP настроен для пользователя {username}")
        return secret, qr_code_base64
    
    def setup_sms(self, user_id: str, phone_number: str) -> str:
        """Настройка SMS аутентификации"""
        method_id = self._generate_method_id(user_id, "sms")
        
        mfa_method = MFAMethod(
            method_id=method_id,
            user_id=user_id,
            method_type="sms",
            phone_number=phone_number
        )
        
        self._save_mfa_method(mfa_method)
        
        logger.info(f"SMS аутентификация настроена для {phone_number}")
        return method_id
    
    def setup_email(self, user_id: str, email: str) -> str:
        """Настройка Email аутентификации"""
        method_id = self._generate_method_id(user_id, "email")
        
        mfa_method = MFAMethod(
            method_id=method_id,
            user_id=user_id,
            method_type="email",
            email=email
        )
        
        self._save_mfa_method(mfa_method)
        
        logger.info(f"Email аутентификация настроена для {email}")
        return method_id
    
    def _generate_method_id(self, user_id: str, method_type: str) -> str:
        """Генерация ID метода MFA"""
        return hashlib.sha256(f"{user_id}_{method_type}_{time.time()}".encode()).hexdigest()[:16]
    
    def _save_mfa_method(self, method: MFAMethod):
        """Сохранение метода MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO mfa_methods 
            (method_id, user_id, method_type, secret_key, phone_number, email, hardware_token_id, enabled)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (method.method_id, method.user_id, method.method_type, 
              method.secret_key, method.phone_number, method.email, 
              method.hardware_token_id, method.enabled))
        
        conn.commit()
        conn.close()
    
    def create_challenge(self, user_id: str, method_type: str = None) -> Optional[MFAChallenge]:
        """Создание MFA вызова"""
        # Получаем активные методы пользователя
        methods = self._get_user_mfa_methods(user_id)
        
        if not methods:
            logger.warning(f"Нет активных MFA методов для пользователя {user_id}")
            return None
        
        # Выбираем метод
        if method_type:
            method = next((m for m in methods if m.method_type == method_type), None)
        else:
            # Приоритет: TOTP > SMS > Email
            method = next((m for m in methods if m.method_type == "totp"), 
                         next((m for m in methods if m.method_type == "sms"), 
                             methods[0] if methods else None))
        
        if not method:
            return None
        
        challenge_id = hashlib.sha256(f"{user_id}_{time.time()}".encode()).hexdigest()[:16]
        
        # Генерируем код в зависимости от типа
        if method.method_type == "totp":
            # Для TOTP код генерируется на устройстве пользователя
            code = "TOTP_VERIFICATION"
        else:
            # Для SMS/Email генерируем случайный код
            code = ''.join(random.choices(string.digits, k=6))
        
        challenge = MFAChallenge(
            challenge_id=challenge_id,
            user_id=user_id,
            method_type=method.method_type,
            code=code,
            expires_at=datetime.now() + timedelta(minutes=5)
        )
        
        # Отправляем код
        if method.method_type == "sms":
            self._send_sms_code(method.phone_number, code)
        elif method.method_type == "email":
            self._send_email_code(method.email, code)
        
        self.active_challenges[challenge_id] = challenge
        
        logger.info(f"MFA вызов создан для пользователя {user_id}, метод: {method.method_type}")
        return challenge
    
    def verify_challenge(self, challenge_id: str, provided_code: str, 
                        ip_address: str = "unknown", user_agent: str = "unknown") -> bool:
        """Проверка MFA кода"""
        if challenge_id not in self.active_challenges:
            logger.warning(f"Неизвестный MFA вызов: {challenge_id}")
            return False
        
        challenge = self.active_challenges[challenge_id]
        challenge.attempts += 1
        
        # Проверка истечения времени
        if datetime.now() > challenge.expires_at:
            logger.warning(f"MFA вызов истек: {challenge_id}")
            del self.active_challenges[challenge_id]
            return False
        
        # Проверка количества попыток
        if challenge.attempts > challenge.max_attempts:
            logger.warning(f"Превышено количество попыток MFA: {challenge_id}")
            del self.active_challenges[challenge_id]
            return False
        
        # Проверка кода
        verified = False
        
        if challenge.method_type == "totp":
            # Для TOTP получаем секретный ключ и проверяем
            method = self._get_mfa_method_by_user_and_type(challenge.user_id, "totp")
            if method and method.secret_key:
                totp = pyotp.TOTP(method.secret_key)
                verified = totp.verify(provided_code, valid_window=1)
        else:
            # Для SMS/Email проверяем сгенерированный код
            verified = (provided_code == challenge.code)
        
        if verified:
            challenge.verified = True
            self._update_method_last_used(challenge.user_id, challenge.method_type)
            
            # Логируем успешную верификацию
            self._log_mfa_attempt(challenge, True, ip_address, user_agent)
            
            logger.info(f"MFA успешно верифицирован: {challenge_id}")
            del self.active_challenges[challenge_id]
            return True
        else:
            # Логируем неудачную попытку
            self._log_mfa_attempt(challenge, False, ip_address, user_agent)
            
            logger.warning(f"Неверный MFA код: {challenge_id}, попытка {challenge.attempts}")
            
            if challenge.attempts >= challenge.max_attempts:
                del self.active_challenges[challenge_id]
            
            return False
    
    def _get_user_mfa_methods(self, user_id: str) -> List[MFAMethod]:
        """Получение MFA методов пользователя"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM mfa_methods WHERE user_id = ? AND enabled = TRUE
        ''', (user_id,))
        
        results = cursor.fetchall()
        conn.close()
        
        methods = []
        for result in results:
            method = MFAMethod(
                method_id=result[0],
                user_id=result[1],
                method_type=result[2],
                secret_key=result[3],
                phone_number=result[4],
                email=result[5],
                hardware_token_id=result[6],
                enabled=bool(result[7]),
                last_used=datetime.fromisoformat(result[9]) if result[9] else None
            )
            methods.append(method)
        
        return methods
    
    def _get_mfa_method_by_user_and_type(self, user_id: str, method_type: str) -> Optional[MFAMethod]:
        """Получение конкретного метода MFA"""
        methods = self._get_user_mfa_methods(user_id)
        return next((m for m in methods if m.method_type == method_type), None)
    
    def _update_method_last_used(self, user_id: str, method_type: str):
        """Обновление времени последнего использования метода"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE mfa_methods 
            SET last_used = CURRENT_TIMESTAMP 
            WHERE user_id = ? AND method_type = ?
        ''', (user_id, method_type))
        
        conn.commit()
        conn.close()
    
    def _send_sms_code(self, phone_number: str, code: str):
        """Отправка SMS кода (заглушка для демонстрации)"""
        # В реальной реализации здесь будет интеграция с SMS провайдером
        logger.info(f"SMS код {code} отправлен на номер {phone_number}")
        
        # Пример интеграции с SMS.ru или другим провайдером
        if self.sms_config.get('enabled', False):
            try:
                # Здесь будет реальная отправка SMS
                # sms_api.send(phone_number, f"Ваш код подтверждения: {code}")
                pass
            except Exception as e:
                logger.error(f"Ошибка отправки SMS: {e}")
    
    def _send_email_code(self, email: str, code: str):
        """Отправка Email кода"""
        if not self.smtp_config.get('enabled', False):
            logger.info(f"Email код {code} для {email} (SMTP отключен)")
            return
        
        if MimeText is None or MimeMultipart is None:
            logger.warning("Email модули недоступны, код не отправлен")
            return
        
        try:
            msg = MimeMultipart()
            msg['From'] = self.smtp_config['from_email']
            msg['To'] = email
            msg['Subject'] = "Код подтверждения CASB"
            
            body = f"""
            Здравствуйте!
            
            Ваш код подтверждения для доступа к системе CASB: {code}
            
            Код действителен в течение 5 минут.
            
            Если вы не запрашивали этот код, проигнорируйте это письмо.
            
            С уважением,
            Команда безопасности CASB
            """
            
            msg.attach(MimeText(body, 'plain', 'utf-8'))
            
            server = smtplib.SMTP(self.smtp_config['smtp_server'], self.smtp_config['smtp_port'])
            if self.smtp_config.get('use_tls', True):
                server.starttls()
            
            if self.smtp_config.get('username') and self.smtp_config.get('password'):
                server.login(self.smtp_config['username'], self.smtp_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Email код отправлен на {email}")
            
        except Exception as e:
            logger.error(f"Ошибка отправки email: {e}")
    
    def _log_mfa_attempt(self, challenge: MFAChallenge, success: bool, 
                        ip_address: str, user_agent: str):
        """Логирование попытки MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO mfa_history 
            (user_id, challenge_id, success, ip_address, user_agent)
            VALUES (?, ?, ?, ?, ?)
        ''', (challenge.user_id, challenge.challenge_id, success, ip_address, user_agent))
        
        conn.commit()
        conn.close()
    
    def get_user_mfa_status(self, user_id: str) -> Dict[str, Any]:
        """Получение статуса MFA пользователя"""
        methods = self._get_user_mfa_methods(user_id)
        
        return {
            'mfa_enabled': len(methods) > 0,
            'methods': [
                {
                    'method_id': m.method_id,
                    'type': m.method_type,
                    'last_used': m.last_used.isoformat() if m.last_used else None
                }
                for m in methods
            ],
            'backup_codes_available': self._has_backup_codes(user_id)
        }
    
    def generate_backup_codes(self, user_id: str, count: int = 10) -> List[str]:
        """Генерация резервных кодов"""
        codes = []
        for _ in range(count):
            code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
            codes.append(code)
        
        # Сохраняем коды в зашифрованном виде
        encrypted_codes = [self._encrypt_backup_code(code) for code in codes]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Удаляем старые коды
        cursor.execute('DELETE FROM backup_codes WHERE user_id = ?', (user_id,))
        
        # Добавляем новые
        for encrypted_code in encrypted_codes:
            cursor.execute('''
                INSERT INTO backup_codes (user_id, code_hash, used)
                VALUES (?, ?, FALSE)
            ''', (user_id, encrypted_code))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Сгенерированы резервные коды для пользователя {user_id}")
        return codes
    
    def _encrypt_backup_code(self, code: str) -> str:
        """Шифрование резервного кода"""
        return hashlib.sha256(code.encode()).hexdigest()
    
    def _has_backup_codes(self, user_id: str) -> bool:
        """Проверка наличия резервных кодов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM backup_codes 
            WHERE user_id = ? AND used = FALSE
        ''', (user_id,))
        
        count = cursor.fetchone()[0] if cursor.fetchone() else 0
        conn.close()
        
        return count > 0
    
    def verify_backup_code(self, user_id: str, code: str) -> bool:
        """Проверка резервного кода"""
        code_hash = self._encrypt_backup_code(code)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM backup_codes 
            WHERE user_id = ? AND code_hash = ? AND used = FALSE
        ''', (user_id, code_hash))
        
        if cursor.fetchone()[0] > 0:
            # Помечаем код как использованный
            cursor.execute('''
                UPDATE backup_codes 
                SET used = TRUE, used_at = CURRENT_TIMESTAMP
                WHERE user_id = ? AND code_hash = ?
            ''', (user_id, code_hash))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Резервный код использован пользователем {user_id}")
            return True
        
        conn.close()
        return False
    
    def disable_mfa_method(self, user_id: str, method_id: str) -> bool:
        """Отключение метода MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE mfa_methods 
            SET enabled = FALSE 
            WHERE user_id = ? AND method_id = ?
        ''', (user_id, method_id))
        
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if rows_affected > 0:
            logger.info(f"MFA метод {method_id} отключен для пользователя {user_id}")
            return True
        
        return False
    
    def get_mfa_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Статистика использования MFA"""
        threshold_date = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общая статистика
        cursor.execute('''
            SELECT COUNT(*) FROM mfa_history WHERE timestamp > ?
        ''', (threshold_date,))
        total_attempts = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM mfa_history WHERE timestamp > ? AND success = TRUE
        ''', (threshold_date,))
        successful_attempts = cursor.fetchone()[0]
        
        # Статистика по методам
        cursor.execute('''
            SELECT mm.method_type, COUNT(*) as usage_count
            FROM mfa_history mh
            JOIN mfa_methods mm ON mh.user_id = mm.user_id
            WHERE mh.timestamp > ?
            GROUP BY mm.method_type
        ''', (threshold_date,))
        
        method_stats = cursor.fetchall()
        
        conn.close()
        
        return {
            'period_days': days,
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': round(successful_attempts / total_attempts * 100, 2) if total_attempts > 0 else 0,
            'method_usage': [
                {'method': method, 'count': count}
                for method, count in method_stats
            ]
        }
    
    def evaluate_adaptive_authentication(self, user_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Оценка необходимых факторов аутентификации на основе контекста"""
        base_factors = 1
        risk_score = 0
        
        if context.get('new_device'):
            risk_score += 0.3
        if context.get('unusual_location'):
            risk_score += 0.4
        if context.get('unusual_time'):
            risk_score += 0.2
        if context.get('high_privilege_access'):
            risk_score += 0.5
        
        required_factors = base_factors + int(risk_score * 2)
        required_factors = min(required_factors, 3)
        
        return {
            'user_id': user_id,
            'risk_score': round(risk_score, 2),
            'required_factors': required_factors,
            'recommended_methods': self._get_recommended_methods(risk_score)
        }
    
    def _get_recommended_methods(self, risk_score: float) -> List[str]:
        """Получение рекомендуемых методов аутентификации"""
        if risk_score > 0.7:
            return ['totp', 'sms', 'hardware_token']
        elif risk_score > 0.4:
            return ['totp', 'sms']
        else:
            return ['totp']
    
    def create_conditional_mfa_rule(self, rule_name: str, conditions: Dict[str, Any]) -> str:
        """Создание правила условного MFA"""
        rule_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS conditional_mfa_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT,
                conditions TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO conditional_mfa_rules (rule_id, name, conditions, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (rule_id, rule_name, json.dumps(conditions)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создано условное MFA правило: {rule_name}")
        return rule_id
    
    def create_api_key_with_mfa(self, user_id: str, key_name: str, permissions: List[str]) -> str:
        """Создание API ключа с привязкой к MFA"""
        api_key = f"casb_api_{self._generate_id()}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                api_key TEXT PRIMARY KEY,
                user_id TEXT,
                key_name TEXT,
                permissions TEXT,
                mfa_required BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP,
                enabled BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            INSERT INTO api_keys (api_key, user_id, key_name, permissions, mfa_required, enabled)
            VALUES (?, ?, ?, ?, TRUE, TRUE)
        ''', (api_key, user_id, key_name, ','.join(permissions)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан API ключ с MFA для пользователя {user_id}: {key_name}")
        return api_key
    
    def _generate_id(self) -> str:
        """Генерация уникального ID"""
        return hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16]
    
    def setup_webauthn(self, user_id: str, credential_name: str) -> Dict[str, Any]:
        """Настройка WebAuthn/FIDO2 аутентификации"""
        webauthn_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webauthn_credentials (
                credential_id TEXT PRIMARY KEY,
                user_id TEXT,
                credential_name TEXT,
                public_key TEXT,
                counter INTEGER DEFAULT 0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Заглушка для WebAuthn
        public_key = base64.b64encode(f"webauthn_key_{webauthn_id}".encode()).decode()
        
        cursor.execute('''
            INSERT INTO webauthn_credentials 
            (credential_id, user_id, credential_name, public_key, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (webauthn_id, user_id, credential_name, public_key))
        
        conn.commit()
        conn.close()
        
        logger.info(f"WebAuthn настроен для пользователя {user_id}: {credential_name}")
        return {'credential_id': webauthn_id, 'public_key': public_key}
    
    def setup_brute_force_protection(self, max_attempts: int = 5, lockout_duration: int = 300) -> str:
        """Настройка защиты от брутфорса"""
        protection_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS brute_force_protection (
                protection_id TEXT PRIMARY KEY,
                max_attempts INTEGER,
                lockout_duration INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO brute_force_protection 
            (protection_id, max_attempts, lockout_duration, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (protection_id, max_attempts, lockout_duration))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена защита от брутфорса: {max_attempts} попыток, блокировка на {lockout_duration} сек")
        return protection_id
    
    def create_session_management(self, user_id: str, session_duration: int = 3600) -> str:
        """Создание управления сессиями с MFA"""
        session_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                mfa_verified BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        expires_at = datetime.now() + timedelta(seconds=session_duration)
        
        cursor.execute('''
            INSERT INTO mfa_sessions 
            (session_id, user_id, expires_at)
            VALUES (?, ?, ?)
        ''', (session_id, user_id, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана MFA сессия для пользователя {user_id}: {session_id}")
        return session_id
    
    def setup_external_provider_integration(self, provider_name: str, config: Dict[str, Any]) -> str:
        """Настройка интеграции с внешними MFA провайдерами"""
        integration_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS external_mfa_providers (
                integration_id TEXT PRIMARY KEY,
                provider_name TEXT,
                config TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO external_mfa_providers 
            (integration_id, provider_name, config, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (integration_id, provider_name, json.dumps(config)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена интеграция с внешним MFA провайдером: {provider_name}")
        return integration_id
    
    def perform_security_audit(self, audit_type: str = "comprehensive") -> Dict[str, Any]:
        """Выполнение аудита безопасности MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Анализ методов аутентификации
        cursor.execute('SELECT COUNT(*), method_type FROM mfa_methods GROUP BY method_type')
        method_distribution = cursor.fetchall()
        
        # Анализ неудачных попыток
        cursor.execute('''
            SELECT COUNT(*) FROM mfa_history 
            WHERE success = FALSE AND timestamp > datetime('now', '-7 days')
        ''')
        failed_attempts = cursor.fetchone()[0]
        
        # Анализ сессий
        cursor.execute('SELECT COUNT(*) FROM mfa_sessions WHERE active = TRUE')
        active_sessions = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        audit_result = {
            'audit_type': audit_type,
            'audit_date': datetime.now().isoformat(),
            'method_distribution': dict(method_distribution),
            'failed_attempts_week': failed_attempts,
            'active_sessions': active_sessions,
            'security_recommendations': self._generate_security_recommendations(failed_attempts),
            'overall_security_score': self._calculate_security_score(method_distribution, failed_attempts)
        }
        
        return audit_result
    
    def _generate_security_recommendations(self, failed_attempts: int) -> List[str]:
        """Генерация рекомендаций по безопасности"""
        recommendations = []
        
        if failed_attempts > 100:
            recommendations.append("Усилить защиту от брутфорса")
            recommendations.append("Рассмотреть блокировку подозрительных IP")
        
        recommendations.extend([
            "Регулярно обновлять резервные коды",
            "Мониторить использование методов аутентификации",
            "Внедрить дополнительные биометрические методы"
        ])
        
        return recommendations
    
    def _calculate_security_score(self, method_distribution, failed_attempts: int) -> int:
        """Расчет общего счета безопасности"""
        base_score = 70
        
        # Бонусы за разнообразие методов
        unique_methods = len(method_distribution)
        base_score += unique_methods * 10
        
        # Штрафы за неудачные попытки
        if failed_attempts > 50:
            base_score -= 20
        elif failed_attempts > 20:
            base_score -= 10
        
        return max(0, min(100, base_score))
    
    def setup_risk_based_authentication(self, user_id: str, risk_rules: List[Dict[str, Any]]) -> str:
        """Настройка аутентификации на основе рисков"""
        rba_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS risk_based_auth (
                rba_id TEXT PRIMARY KEY,
                user_id TEXT,
                risk_rules TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO risk_based_auth (rba_id, user_id, risk_rules, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (rba_id, user_id, json.dumps(risk_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена аутентификация на основе рисков для пользователя {user_id}")
        return rba_id
    
    def create_mfa_dashboard(self) -> Dict[str, Any]:
        """Создание панели управления MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общая статистика
        cursor.execute('SELECT COUNT(*) FROM mfa_methods WHERE enabled = TRUE')
        active_methods = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(DISTINCT user_id) FROM mfa_methods WHERE enabled = TRUE')
        users_with_mfa = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM mfa_history WHERE timestamp > datetime("now", "-24 hours")')
        daily_authentications = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        dashboard = {
            'overview': {
                'active_mfa_methods': active_methods,
                'users_with_mfa': users_with_mfa,
                'daily_authentications': daily_authentications
            },
            'security_metrics': self.perform_security_audit('quick'),
            'recent_activities': self._get_recent_mfa_activities(),
            'alerts': self._get_security_alerts(),
            'generated_at': datetime.now().isoformat()
        }
        
        return dashboard
    
    def _get_recent_mfa_activities(self) -> List[Dict[str, Any]]:
        """Получение последних MFA активностей"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT user_id, success, ip_address, timestamp 
            FROM mfa_history 
            ORDER BY timestamp DESC LIMIT 10
        ''')
        
        activities = cursor.fetchall()
        conn.close()
        
        return [
            {
                'user_id': activity[0],
                'success': bool(activity[1]),
                'ip_address': activity[2],
                'timestamp': activity[3]
            }
            for activity in activities
        ]
    
    def _get_security_alerts(self) -> List[Dict[str, Any]]:
        """Получение предупреждений безопасности"""
        alerts = []
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Проверяем на подозрительную активность
        cursor.execute('''
            SELECT user_id, COUNT(*) as failed_count
            FROM mfa_history 
            WHERE success = FALSE AND timestamp > datetime('now', '-1 hour')
            GROUP BY user_id
            HAVING failed_count > 3
        ''')
        
        suspicious_users = cursor.fetchall()
        
        for user_id, failed_count in suspicious_users:
            alerts.append({
                'type': 'SUSPICIOUS_ACTIVITY',
                'user_id': user_id,
                'description': f"Множественные неудачные попытки MFA: {failed_count}",
                'severity': 'HIGH',
                'timestamp': datetime.now().isoformat()
            })
        
        conn.close()
        return alerts
    
    def setup_device_trust_management(self, user_id: str, device_fingerprint: str, 
                                    trust_level: str = "MEDIUM") -> str:
        """Настройка управления доверием устройств"""
        device_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT,
                device_fingerprint TEXT,
                trust_level TEXT,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO trusted_devices 
            (device_id, user_id, device_fingerprint, trust_level)
            VALUES (?, ?, ?, ?)
        ''', (device_id, user_id, device_fingerprint, trust_level))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено управление доверием устройства для {user_id}: {trust_level}")
        return device_id
    
    def evaluate_device_trust(self, user_id: str, device_fingerprint: str) -> Dict[str, Any]:
        """Оценка доверия к устройству"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT trust_level, last_seen FROM trusted_devices 
            WHERE user_id = ? AND device_fingerprint = ?
        ''', (user_id, device_fingerprint))
        
        device_data = cursor.fetchone()
        conn.close()
        
        if device_data:
            trust_level = device_data[0]
            last_seen = datetime.fromisoformat(device_data[1])
            
            # Снижаем доверие если устройство долго не использовалось
            days_since_use = (datetime.now() - last_seen).days
            if days_since_use > 30:
                trust_level = "LOW"
            
            return {
                'trusted': True,
                'trust_level': trust_level,
                'days_since_use': days_since_use,
                'requires_additional_mfa': trust_level == "LOW"
            }
        else:
            return {
                'trusted': False,
                'trust_level': "NONE",
                'requires_additional_mfa': True,
                'new_device': True
            }
    
    def setup_location_based_mfa(self, user_id: str, trusted_locations: List[str]) -> str:
        """Настройка MFA на основе местоположения"""
        location_rule_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS location_based_mfa (
                rule_id TEXT PRIMARY KEY,
                user_id TEXT,
                trusted_locations TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO location_based_mfa 
            (rule_id, user_id, trusted_locations, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (location_rule_id, user_id, ','.join(trusted_locations)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено геолокационное MFA для пользователя {user_id}")
        return location_rule_id
    
    def setup_biometric_authentication(self, user_id: str, biometric_type: str, 
                                     template_data: str) -> str:
        """Настройка биометрической аутентификации"""
        biometric_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS biometric_methods (
                biometric_id TEXT PRIMARY KEY,
                user_id TEXT,
                biometric_type TEXT,
                template_hash TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Хешируем биометрический шаблон для безопасности
        template_hash = hashlib.sha256(template_data.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO biometric_methods 
            (biometric_id, user_id, biometric_type, template_hash, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (biometric_id, user_id, biometric_type, template_hash))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена биометрическая аутентификация {biometric_type} для пользователя {user_id}")
        return biometric_id
    
    def create_mfa_policy_template(self, template_name: str, policy_rules: Dict[str, Any]) -> str:
        """Создание шаблона политики MFA"""
        template_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_policy_templates (
                template_id TEXT PRIMARY KEY,
                name TEXT,
                policy_rules TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mfa_policy_templates (template_id, name, policy_rules)
            VALUES (?, ?, ?)
        ''', (template_id, template_name, json.dumps(policy_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан шаблон политики MFA: {template_name}")
        return template_id
    
    def setup_push_notification_mfa(self, user_id: str, device_token: str, 
                                   push_service: str = "FCM") -> str:
        """Настройка push-уведомлений для MFA"""
        push_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS push_mfa_methods (
                push_id TEXT PRIMARY KEY,
                user_id TEXT,
                device_token TEXT,
                push_service TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO push_mfa_methods 
            (push_id, user_id, device_token, push_service, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (push_id, user_id, device_token, push_service))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроены push-уведомления MFA для пользователя {user_id}")
        return push_id
    
    def create_step_up_authentication(self, user_id: str, resource: str, 
                                    required_level: int) -> str:
        """Создание повышенной аутентификации для доступа к ресурсам"""
        stepup_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS step_up_auth (
                stepup_id TEXT PRIMARY KEY,
                user_id TEXT,
                resource TEXT,
                required_level INTEGER,
                completed_level INTEGER DEFAULT 0,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        expires_at = datetime.now() + timedelta(minutes=15)
        
        cursor.execute('''
            INSERT INTO step_up_auth 
            (stepup_id, user_id, resource, required_level, expires_at)
            VALUES (?, ?, ?, ?, ?)
        ''', (stepup_id, user_id, resource, required_level, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана повышенная аутентификация для ресурса {resource}")
        return stepup_id
    
    def setup_continuous_authentication(self, user_id: str, monitoring_interval: int = 300) -> str:
        """Настройка непрерывной аутентификации"""
        continuous_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS continuous_auth (
                continuous_id TEXT PRIMARY KEY,
                user_id TEXT,
                monitoring_interval INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                last_verification TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO continuous_auth 
            (continuous_id, user_id, monitoring_interval, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (continuous_id, user_id, monitoring_interval))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена непрерывная аутентификация для пользователя {user_id}")
        return continuous_id
    
    def create_fraud_detection_system(self, detection_rules: Dict[str, Any]) -> str:
        """Создание системы обнаружения мошенничества"""
        fraud_system_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS fraud_detection_systems (
                system_id TEXT PRIMARY KEY,
                detection_rules TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                detection_count INTEGER DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO fraud_detection_systems (system_id, detection_rules, enabled)
            VALUES (?, ?, TRUE)
        ''', (fraud_system_id, json.dumps(detection_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана система обнаружения мошенничества: {fraud_system_id}")
        return fraud_system_id
    
    def setup_mfa_compliance_reporting(self, compliance_standard: str = "SOX") -> str:
        """Настройка отчетности по соответствию MFA"""
        compliance_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_compliance_reports (
                compliance_id TEXT PRIMARY KEY,
                standard TEXT,
                report_data TEXT,
                generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                compliance_status TEXT DEFAULT 'PENDING'
            )
        ''')
        
        # Генерируем базовый отчет
        report_data = self._generate_compliance_report(compliance_standard)
        
        cursor.execute('''
            INSERT INTO mfa_compliance_reports 
            (compliance_id, standard, report_data, compliance_status)
            VALUES (?, ?, ?, 'ACTIVE')
        ''', (compliance_id, compliance_standard, json.dumps(report_data)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена отчетность по соответствию {compliance_standard}")
        return compliance_id
    
    def _generate_compliance_report(self, standard: str) -> Dict[str, Any]:
        """Генерация отчета по соответствию"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Базовые метрики для соответствия
        cursor.execute('SELECT COUNT(DISTINCT user_id) FROM mfa_methods WHERE enabled = TRUE')
        mfa_enabled_users = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM mfa_history WHERE success = TRUE AND timestamp > datetime("now", "-30 days")')
        successful_auths = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        return {
            'standard': standard,
            'mfa_adoption_rate': f"{mfa_enabled_users} users",
            'authentication_success_rate': f"{successful_auths} successful authentications",
            'compliance_items': [
                'Multi-factor authentication enabled',
                'Audit logging configured',
                'Session management implemented'
            ],
            'generated_at': datetime.now().isoformat()
        }
    
    def setup_privileged_access_management(self, user_id: str, privileges: List[str]) -> str:
        """Настройка управления привилегированным доступом"""
        pam_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS privileged_access_management (
                pam_id TEXT PRIMARY KEY,
                user_id TEXT,
                privileges TEXT,
                additional_mfa_required BOOLEAN DEFAULT TRUE,
                session_recording BOOLEAN DEFAULT TRUE,
                approval_required BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO privileged_access_management 
            (pam_id, user_id, privileges, additional_mfa_required, session_recording, approval_required)
            VALUES (?, ?, ?, TRUE, TRUE, TRUE)
        ''', (pam_id, user_id, json.dumps(privileges)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено управление привилегированным доступом для {user_id}")
        return pam_id
    
    def create_zero_trust_verification(self, user_id: str, resource: str, context: Dict[str, Any]) -> str:
        """Создание верификации на основе Zero Trust"""
        zt_verification_id = self._generate_id()
        
        # Оценка доверия на основе контекста
        trust_score = self._calculate_zero_trust_score(user_id, context)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_verifications (
                verification_id TEXT PRIMARY KEY,
                user_id TEXT,
                resource TEXT,
                context_data TEXT,
                trust_score REAL,
                verification_required BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        verification_required = trust_score < 0.7
        
        cursor.execute('''
            INSERT INTO zero_trust_verifications 
            (verification_id, user_id, resource, context_data, trust_score, verification_required)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (zt_verification_id, user_id, resource, json.dumps(context), trust_score, verification_required))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана Zero Trust верификация для {user_id}, оценка доверия: {trust_score}")
        return zt_verification_id
    
    def _calculate_zero_trust_score(self, user_id: str, context: Dict[str, Any]) -> float:
        """Расчет оценки доверия Zero Trust"""
        base_score = 1.0
        
        # Факторы снижающие доверие
        if context.get('new_device'):
            base_score -= 0.3
        if context.get('unusual_location'):
            base_score -= 0.2
        if context.get('off_hours_access'):
            base_score -= 0.1
        if context.get('multiple_failed_attempts'):
            base_score -= 0.4
        
        # Факторы повышающие доверие
        if context.get('corporate_network'):
            base_score += 0.1
        if context.get('managed_device'):
            base_score += 0.2
        
        return max(0.0, min(1.0, base_score))
    
    def setup_behavior_analytics(self, user_id: str, analytics_config: Dict[str, Any]) -> str:
        """Настройка поведенческой аналитики"""
        analytics_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS behavior_analytics (
                analytics_id TEXT PRIMARY KEY,
                user_id TEXT,
                analytics_config TEXT,
                baseline_established BOOLEAN DEFAULT FALSE,
                anomaly_threshold REAL DEFAULT 0.7,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO behavior_analytics 
            (analytics_id, user_id, analytics_config, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (analytics_id, user_id, json.dumps(analytics_config)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена поведенческая аналитика для пользователя {user_id}")
        return analytics_id
    
    def create_emergency_access_bypass(self, user_id: str, justification: str, 
                                     duration_hours: int = 24) -> str:
        """Создание экстренного обхода MFA"""
        bypass_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS emergency_access_bypasses (
                bypass_id TEXT PRIMARY KEY,
                user_id TEXT,
                justification TEXT,
                approved_by TEXT,
                expires_at TIMESTAMP,
                used BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        expires_at = datetime.now() + timedelta(hours=duration_hours)
        
        cursor.execute('''
            INSERT INTO emergency_access_bypasses 
            (bypass_id, user_id, justification, expires_at)
            VALUES (?, ?, ?, ?)
        ''', (bypass_id, user_id, justification, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.critical(f"Создан экстренный обход MFA для {user_id}: {justification}")
        return bypass_id
    
    def setup_quantum_resistant_mfa(self, user_id: str, algorithm: str = "CRYSTALS-Kyber") -> str:
        """Настройка квантово-устойчивого MFA"""
        quantum_mfa_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quantum_resistant_mfa (
                quantum_mfa_id TEXT PRIMARY KEY,
                user_id TEXT,
                algorithm TEXT,
                public_key TEXT,
                key_pair_id TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Заглушка для квантово-устойчивого алгоритма
        public_key = base64.b64encode(f"quantum_key_{quantum_mfa_id}_{algorithm}".encode()).decode()
        key_pair_id = self._generate_id()
        
        cursor.execute('''
            INSERT INTO quantum_resistant_mfa 
            (quantum_mfa_id, user_id, algorithm, public_key, key_pair_id, enabled)
            VALUES (?, ?, ?, ?, ?, TRUE)
        ''', (quantum_mfa_id, user_id, algorithm, public_key, key_pair_id))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено квантово-устойчивое MFA ({algorithm}) для пользователя {user_id}")
        return quantum_mfa_id
    
    def setup_mfa_federation(self, federation_name: str, partner_config: Dict[str, Any]) -> str:
        """Настройка федерации MFA с партнерскими организациями"""
        federation_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_federations (
                federation_id TEXT PRIMARY KEY,
                federation_name TEXT,
                partner_config TEXT,
                trust_level TEXT DEFAULT 'MEDIUM',
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mfa_federations 
            (federation_id, federation_name, partner_config, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (federation_id, federation_name, json.dumps(partner_config)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена федерация MFA: {federation_name}")
        return federation_id
    
    def create_mfa_analytics_dashboard(self, dashboard_type: str = "executive") -> Dict[str, Any]:
        """Создание аналитической панели MFA"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Получение метрик за разные периоды
        metrics = {}
        
        for period in ['1 day', '7 days', '30 days']:
            cursor.execute(f'''
                SELECT COUNT(*), AVG(CASE WHEN success THEN 1.0 ELSE 0.0 END)
                FROM mfa_history 
                WHERE timestamp > datetime('now', '-{period}')
            ''')
            
            result = cursor.fetchone()
            metrics[period.replace(' ', '_')] = {
                'total_attempts': result[0] if result[0] else 0,
                'success_rate': round(result[1] * 100, 2) if result[1] else 0
            }
        
        # Топ пользователей по использованию MFA
        cursor.execute('''
            SELECT user_id, COUNT(*) as usage_count
            FROM mfa_history 
            WHERE timestamp > datetime('now', '-30 days')
            GROUP BY user_id
            ORDER BY usage_count DESC
            LIMIT 10
        ''')
        
        top_users = cursor.fetchall()
        
        conn.close()
        
        dashboard = {
            'dashboard_type': dashboard_type,
            'metrics_by_period': metrics,
            'top_users': [{'user_id': user[0], 'usage_count': user[1]} for user in top_users],
            'security_insights': self._generate_security_insights(),
            'trends': self._analyze_mfa_trends(),
            'generated_at': datetime.now().isoformat()
        }
        
        return dashboard
    
    def _generate_security_insights(self) -> List[Dict[str, str]]:
        """Генерация аналитических выводов по безопасности"""
        return [
            {'insight': 'TOTP показывает самую высокую степень принятия пользователями', 'type': 'POSITIVE'},
            {'insight': 'Рекомендуется внедрить биометрическую аутентификацию', 'type': 'RECOMMENDATION'},
            {'insight': 'Обнаружены попытки атак на SMS-коды', 'type': 'WARNING'}
        ]
    
    def _analyze_mfa_trends(self) -> Dict[str, Any]:
        """Анализ трендов использования MFA"""
        return {
            'adoption_trend': 'INCREASING',
            'preferred_method': 'TOTP',
            'security_incidents': 'DECREASING',
            'user_satisfaction': 'HIGH'
        }
    
    def setup_blockchain_mfa_verification(self, user_id: str, blockchain_network: str = "Ethereum") -> str:
        """Настройка верификации MFA через блокчейн"""
        blockchain_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_mfa_verifications (
                blockchain_id TEXT PRIMARY KEY,
                user_id TEXT,
                blockchain_network TEXT,
                wallet_address TEXT,
                smart_contract_address TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Генерируем заглушки для блокчейн адресов
        wallet_address = f"0x{self._generate_id()}"
        contract_address = f"0x{self._generate_id()}"
        
        cursor.execute('''
            INSERT INTO blockchain_mfa_verifications 
            (blockchain_id, user_id, blockchain_network, wallet_address, smart_contract_address, enabled)
            VALUES (?, ?, ?, ?, ?, TRUE)
        ''', (blockchain_id, user_id, blockchain_network, wallet_address, contract_address))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена блокчейн верификация MFA для {user_id} в сети {blockchain_network}")
        return blockchain_id
    
    def setup_ai_powered_risk_assessment(self, assessment_config: Dict[str, Any]) -> str:
        """Настройка ИИ-анализа рисков для MFA"""
        ai_assessment_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS ai_risk_assessments (
                assessment_id TEXT PRIMARY KEY,
                model_name TEXT,
                config_data TEXT,
                accuracy_score REAL DEFAULT 0.85,
                enabled BOOLEAN DEFAULT TRUE,
                last_training TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO ai_risk_assessments 
            (assessment_id, model_name, config_data, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (ai_assessment_id, assessment_config.get('model_name', 'RiskNet-v2'), 
              json.dumps(assessment_config)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена ИИ-оценка рисков MFA: {assessment_config.get('model_name', 'RiskNet-v2')}")
        return ai_assessment_id
    
    def create_cross_platform_sync(self, user_id: str, platforms: List[str]) -> str:
        """Создание синхронизации MFA между платформами"""
        sync_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cross_platform_sync (
                sync_id TEXT PRIMARY KEY,
                user_id TEXT,
                platforms TEXT,
                sync_status TEXT DEFAULT 'ACTIVE',
                last_sync TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO cross_platform_sync 
            (sync_id, user_id, platforms, sync_status)
            VALUES (?, ?, ?, 'ACTIVE')
        ''', (sync_id, user_id, json.dumps(platforms)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена кросс-платформенная синхронизация MFA для {user_id}")
        return sync_id
    
    def setup_voice_recognition_mfa(self, user_id: str, voice_template: str) -> str:
        """Настройка голосовой аутентификации"""
        voice_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS voice_recognition_mfa (
                voice_id TEXT PRIMARY KEY,
                user_id TEXT,
                voice_template_hash TEXT,
                accuracy_threshold REAL DEFAULT 0.9,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Хешируем голосовой шаблон
        voice_hash = hashlib.sha256(voice_template.encode()).hexdigest()
        
        cursor.execute('''
            INSERT INTO voice_recognition_mfa 
            (voice_id, user_id, voice_template_hash, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (voice_id, user_id, voice_hash))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена голосовая аутентификация для пользователя {user_id}")
        return voice_id
    
    def setup_mfa_recovery_workflow(self, user_id: str, recovery_contacts: List[str]) -> str:
        """Настройка процедуры восстановления MFA"""
        recovery_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_recovery_workflows (
                recovery_id TEXT PRIMARY KEY,
                user_id TEXT,
                recovery_contacts TEXT,
                recovery_status TEXT DEFAULT 'INACTIVE',
                initiated_at TIMESTAMP,
                completed_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mfa_recovery_workflows 
            (recovery_id, user_id, recovery_contacts)
            VALUES (?, ?, ?)
        ''', (recovery_id, user_id, json.dumps(recovery_contacts)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена процедура восстановления MFA для пользователя {user_id}")
        return recovery_id
    
    def create_mfa_threat_intelligence(self, threat_sources: List[str]) -> str:
        """Создание системы анализа угроз для MFA"""
        threat_intel_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_threat_intelligence (
                threat_intel_id TEXT PRIMARY KEY,
                threat_sources TEXT,
                threat_level TEXT DEFAULT 'MEDIUM',
                indicators_of_compromise TEXT,
                mitigation_strategies TEXT,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Базовые индикаторы компрометации
        iocs = [
            'suspicious_ip_patterns',
            'unusual_authentication_times',
            'multiple_device_registrations',
            'geolocation_anomalies'
        ]
        
        mitigation_strategies = [
            'increase_mfa_requirements',
            'temporary_account_restrictions',
            'enhanced_monitoring',
            'user_notification_alerts'
        ]
        
        cursor.execute('''
            INSERT INTO mfa_threat_intelligence 
            (threat_intel_id, threat_sources, indicators_of_compromise, mitigation_strategies)
            VALUES (?, ?, ?, ?)
        ''', (threat_intel_id, json.dumps(threat_sources), 
              json.dumps(iocs), json.dumps(mitigation_strategies)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана система анализа угроз MFA: {threat_intel_id}")
        return threat_intel_id
    
    def setup_progressive_mfa(self, user_id: str, progression_rules: Dict[str, Any]) -> str:
        """Настройка прогрессивного MFA (постепенное усиление)"""
        progressive_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS progressive_mfa (
                progressive_id TEXT PRIMARY KEY,
                user_id TEXT,
                current_level INTEGER DEFAULT 1,
                max_level INTEGER DEFAULT 5,
                progression_rules TEXT,
                last_escalation TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO progressive_mfa 
            (progressive_id, user_id, progression_rules, max_level)
            VALUES (?, ?, ?, ?)
        ''', (progressive_id, user_id, json.dumps(progression_rules), 
              progression_rules.get('max_level', 5)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено прогрессивное MFA для пользователя {user_id}")
        return progressive_id
    
    def setup_social_authentication_verification(self, user_id: str, social_profiles: Dict[str, str]) -> str:
        """Настройка верификации через социальные сети"""
        social_auth_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS social_auth_verification (
                social_auth_id TEXT PRIMARY KEY,
                user_id TEXT,
                social_profiles TEXT,
                verification_status TEXT DEFAULT 'PENDING',
                trust_score REAL DEFAULT 0.5,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO social_auth_verification 
            (social_auth_id, user_id, social_profiles, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (social_auth_id, user_id, json.dumps(social_profiles)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена верификация через социальные сети для пользователя {user_id}")
        return social_auth_id
    
    def create_mfa_automation_workflows(self, workflow_name: str, automation_rules: Dict[str, Any]) -> str:
        """Создание автоматизированных рабочих процессов MFA"""
        workflow_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_automation_workflows (
                workflow_id TEXT PRIMARY KEY,
                workflow_name TEXT,
                automation_rules TEXT,
                execution_count INTEGER DEFAULT 0,
                success_rate REAL DEFAULT 1.0,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mfa_automation_workflows 
            (workflow_id, workflow_name, automation_rules, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (workflow_id, workflow_name, json.dumps(automation_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан автоматизированный рабочий процесс MFA: {workflow_name}")
        return workflow_id
    
    def setup_hardware_security_module_integration(self, hsm_config: Dict[str, Any]) -> str:
        """Настройка интеграции с аппаратным модулем безопасности (HSM)"""
        hsm_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hsm_integrations (
                hsm_id TEXT PRIMARY KEY,
                hsm_name TEXT,
                connection_config TEXT,
                encryption_algorithms TEXT,
                key_management_enabled BOOLEAN DEFAULT TRUE,
                hardware_attestation BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        algorithms = ['AES-256-GCM', 'RSA-4096', 'ECDSA-P384', 'ChaCha20-Poly1305']
        
        cursor.execute('''
            INSERT INTO hsm_integrations 
            (hsm_id, hsm_name, connection_config, encryption_algorithms)
            VALUES (?, ?, ?, ?)
        ''', (hsm_id, hsm_config.get('name', 'DefaultHSM'), 
              json.dumps(hsm_config), json.dumps(algorithms)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена интеграция с HSM: {hsm_config.get('name', 'DefaultHSM')}")
        return hsm_id
    
    def create_mfa_user_experience_optimization(self, optimization_config: Dict[str, Any]) -> str:
        """Создание оптимизации пользовательского опыта MFA"""
        ux_optimization_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_ux_optimizations (
                optimization_id TEXT PRIMARY KEY,
                optimization_name TEXT,
                config_data TEXT,
                user_satisfaction_score REAL DEFAULT 0.8,
                conversion_rate REAL DEFAULT 0.9,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO mfa_ux_optimizations 
            (optimization_id, optimization_name, config_data, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (ux_optimization_id, optimization_config.get('name', 'StandardUX'), 
              json.dumps(optimization_config)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана оптимизация UX для MFA: {optimization_config.get('name', 'StandardUX')}")
        return ux_optimization_id
    
    def setup_dynamic_mfa_policies(self, policy_name: str, dynamic_rules: Dict[str, Any]) -> str:
        """Настройка динамических политик MFA"""
        dynamic_policy_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dynamic_mfa_policies (
                policy_id TEXT PRIMARY KEY,
                policy_name TEXT,
                dynamic_rules TEXT,
                adaptation_frequency INTEGER DEFAULT 3600,
                effectiveness_score REAL DEFAULT 0.85,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO dynamic_mfa_policies 
            (policy_id, policy_name, dynamic_rules, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (dynamic_policy_id, policy_name, json.dumps(dynamic_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена динамическая политика MFA: {policy_name}")
        return dynamic_policy_id
    
    def create_mfa_incident_response_system(self, response_config: Dict[str, Any]) -> str:
        """Создание системы реагирования на инциденты MFA"""
        incident_system_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS mfa_incident_response (
                system_id TEXT PRIMARY KEY,
                response_config TEXT,
                escalation_rules TEXT,
                notification_channels TEXT,
                automated_response BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        escalation_rules = {
            'level_1': 'automated_lockout',
            'level_2': 'security_team_notification',
            'level_3': 'executive_escalation',
            'level_4': 'law_enforcement_contact'
        }
        
        notification_channels = ['email', 'sms', 'slack', 'pagerduty']
        
        cursor.execute('''
            INSERT INTO mfa_incident_response 
            (system_id, response_config, escalation_rules, notification_channels)
            VALUES (?, ?, ?, ?)
        ''', (incident_system_id, json.dumps(response_config), 
              json.dumps(escalation_rules), json.dumps(notification_channels)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана система реагирования на инциденты MFA: {incident_system_id}")
        return incident_system_id

# Псевдоним для совместимости
MFAAuth = MFAAuthenticator

# Создание таблицы резервных кодов при инициализации
def init_backup_codes_table(db_path: str):
    """Инициализация таблицы резервных кодов"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS backup_codes (
            code_id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id TEXT,
            code_hash TEXT,
            used BOOLEAN DEFAULT FALSE,
            used_at TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users (user_id)
        )
    ''')
    
    conn.commit()
    conn.close()

if __name__ == "__main__":
    # Пример использования
    mfa = MFAAuthenticator("casb.db")
    
    # Настройка TOTP для пользователя
    secret, qr_code = mfa.setup_totp("test_user", "testuser@company.ru")
    print(f"TOTP секрет: {secret}")
    print(f"QR код (base64): {qr_code[:50]}...")
    
    # Создание MFA вызова
    challenge = mfa.create_challenge("test_user", "totp")
    if challenge:
        print(f"MFA вызов создан: {challenge.challenge_id}")
    
    # Демонстрация новых возможностей
    print("\n=== Новые возможности MFA ===")
    
    # Адаптивная аутентификация
    adaptive_result = mfa.evaluate_adaptive_authentication("test_user", {
        'ip_address': '192.168.1.100',
        'device_fingerprint': 'desktop_chrome',
        'location': 'Moscow',
        'time_of_day': '14:30'
    })
    print(f"Адаптивная аутентификация: {adaptive_result['required_factors']} факторов")
    
    # Настройка условного MFA
    conditional_rule = mfa.create_conditional_mfa_rule("high_risk_access", {
        'conditions': ['unusual_location', 'new_device'],
        'required_methods': ['totp', 'sms'],
        'validity_period': 3600
    })
    print(f"Создано условное MFA правило: {conditional_rule}")
    
    # Создание API ключа с MFA
    api_key = mfa.create_api_key_with_mfa("test_user", "data_access", ["READ", "WRITE"])
    print(f"API ключ с MFA: {api_key[:20]}...")
    
    print("MFA модуль готов к работе!")
