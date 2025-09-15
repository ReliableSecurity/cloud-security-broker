#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Security Module for CASB
Implements Zero-Trust Architecture, Advanced Threat Detection, and Enhanced Encryption

Автор: AI Assistant
"""

import os
import time
import hashlib
import hmac
import secrets
import ipaddress
import logging
import json
import sqlite3
import asyncio
from typing import Dict, List, Optional, Any, Tuple, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import bcrypt
import jwt
from functools import wraps
import threading
import re

logger = logging.getLogger(__name__)

class ThreatLevel(Enum):
    """Уровни угроз"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

class SecurityAction(Enum):
    """Действия безопасности"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    MONITOR = "monitor"
    ALERT = "alert"

@dataclass
class SecurityContext:
    """Контекст безопасности для запроса"""
    user_id: str
    session_id: str
    ip_address: str
    user_agent: str
    timestamp: datetime
    device_fingerprint: Optional[str] = None
    geo_location: Optional[Dict[str, str]] = None
    risk_score: int = 0
    trust_level: int = 0
    authenticated: bool = False
    mfa_verified: bool = False

@dataclass
class ThreatIntelligence:
    """Данные об угрозах"""
    indicator: str
    indicator_type: str  # ip, domain, hash, url
    threat_level: ThreatLevel
    source: str
    description: str
    first_seen: datetime
    last_seen: datetime
    confidence: int  # 0-100

@dataclass
class SecurityEvent:
    """Событие безопасности"""
    event_id: str
    context: SecurityContext
    event_type: str
    description: str
    threat_level: ThreatLevel
    action_taken: SecurityAction
    timestamp: datetime
    evidence: Dict[str, Any]

class AdvancedEncryption:
    """Расширенное шифрование"""
    
    def __init__(self, master_key: Optional[bytes] = None):
        self.master_key = master_key or self._generate_master_key()
        self.backend = default_backend()
    
    def _generate_master_key(self) -> bytes:
        """Генерация мастер-ключа"""
        return secrets.token_bytes(32)  # 256-bit key
    
    def encrypt_aes_gcm(self, data: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes, bytes]:
        """Шифрование AES-GCM"""
        # Генерируем случайный IV
        iv = secrets.token_bytes(12)  # 96-bit IV для GCM
        
        # Создаем шифр
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv), backend=self.backend)
        encryptor = cipher.encryptor()
        
        # Добавляем ассоциированные данные если есть
        if associated_data:
            encryptor.authenticate_additional_data(associated_data)
        
        # Шифруем данные
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        return ciphertext, iv, encryptor.tag
    
    def decrypt_aes_gcm(self, ciphertext: bytes, iv: bytes, tag: bytes, 
                       associated_data: Optional[bytes] = None) -> bytes:
        """Расшифровка AES-GCM"""
        cipher = Cipher(algorithms.AES(self.master_key), modes.GCM(iv, tag), backend=self.backend)
        decryptor = cipher.decryptor()
        
        # Добавляем ассоциированные данные если есть
        if associated_data:
            decryptor.authenticate_additional_data(associated_data)
        
        # Расшифровываем данные
        return decryptor.update(ciphertext) + decryptor.finalize()
    
    def encrypt_rsa(self, data: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Шифрование RSA"""
        return public_key.encrypt(
            data,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def decrypt_rsa(self, ciphertext: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Расшифровка RSA"""
        return private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    
    def generate_rsa_keypair(self, key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """Генерация RSA ключей"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def derive_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Генерация ключа из пароля"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        return kdf.derive(password.encode())

class ZeroTrustEngine:
    """Движок Zero-Trust архитектуры"""
    
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}
        self.trust_policies = {}
        self.device_registry = {}
        self.session_manager = {}
        
        self._init_zero_trust_tables()
        self._load_trust_policies()
        
        # Фоновые задачи
        self.monitoring_active = True
        self.trust_monitor_thread = threading.Thread(target=self._monitor_trust_levels, daemon=True)
        self.trust_monitor_thread.start()
    
    def _init_zero_trust_tables(self):
        """Инициализация таблиц Zero-Trust"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица устройств
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id TEXT PRIMARY KEY,
                user_id TEXT,
                device_fingerprint TEXT,
                device_name TEXT,
                trust_score INTEGER DEFAULT 50,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                status TEXT DEFAULT 'active',
                risk_factors TEXT
            )
        ''')
        
        # Таблица сессий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trust_sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT,
                device_id TEXT,
                trust_level INTEGER,
                risk_score INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                status TEXT DEFAULT 'active'
            )
        ''')
        
        # Таблица политик доверия
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS trust_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                conditions TEXT,
                actions TEXT,
                trust_threshold INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_trust_policies(self):
        """Загрузка политик доверия"""
        default_policies = [
            {
                'name': 'Unknown Device Policy',
                'conditions': {'device_known': False},
                'actions': {'require_mfa': True, 'limit_access': True},
                'trust_threshold': 30
            },
            {
                'name': 'Suspicious IP Policy',
                'conditions': {'ip_reputation': 'bad'},
                'actions': {'block_access': True, 'alert': True},
                'trust_threshold': 10
            },
            {
                'name': 'High Risk Location',
                'conditions': {'geo_location': 'high_risk'},
                'actions': {'require_additional_verification': True},
                'trust_threshold': 20
            }
        ]
        
        for policy in default_policies:
            policy_id = hashlib.sha256(policy['name'].encode()).hexdigest()[:16]
            self.trust_policies[policy_id] = policy
    
    def evaluate_trust(self, context: SecurityContext) -> int:
        """Оценка уровня доверия"""
        trust_score = 50  # Базовый уровень
        
        # Проверка известного устройства
        device_trust = self._evaluate_device_trust(context)
        trust_score += device_trust
        
        # Проверка IP репутации
        ip_trust = self._evaluate_ip_trust(context.ip_address)
        trust_score += ip_trust
        
        # Проверка поведенческих паттернов
        behavior_trust = self._evaluate_behavior_trust(context)
        trust_score += behavior_trust
        
        # Проверка времени доступа
        time_trust = self._evaluate_time_trust(context.timestamp)
        trust_score += time_trust
        
        # Нормализуем к диапазону 0-100
        trust_score = max(0, min(100, trust_score))
        
        return trust_score
    
    def _evaluate_device_trust(self, context: SecurityContext) -> int:
        """Оценка доверия устройству"""
        if not context.device_fingerprint:
            return -20  # Неизвестное устройство
        
        # Проверяем в базе данных
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT trust_score, last_seen FROM trusted_devices 
            WHERE device_fingerprint = ? AND user_id = ?
        ''', (context.device_fingerprint, context.user_id))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            # Новое устройство
            self._register_device(context)
            return -15
        
        trust_score, last_seen = result
        last_seen_dt = datetime.fromisoformat(last_seen)
        
        # Бонус за регулярное использование
        days_since_last = (context.timestamp - last_seen_dt).days
        if days_since_last <= 1:
            return trust_score - 50 + 20  # Регулярное использование
        elif days_since_last <= 7:
            return trust_score - 50 + 10
        else:
            return trust_score - 50 - 10  # Редко используемое устройство
    
    def _evaluate_ip_trust(self, ip_address: str) -> int:
        """Оценка доверия IP адресу"""
        try:
            ip = ipaddress.ip_address(ip_address)
            
            # Проверка частных сетей
            if ip.is_private:
                return 10
            
            # Проверка в списках угроз (заглушка)
            if self._is_malicious_ip(ip_address):
                return -30
            
            # Проверка геолокации (заглушка)
            geo_risk = self._get_geo_risk(ip_address)
            return -geo_risk * 5
            
        except ValueError:
            return -20  # Невалидный IP
    
    def _evaluate_behavior_trust(self, context: SecurityContext) -> int:
        """Оценка поведенческого доверия"""
        # Анализ паттернов доступа (заглушка)
        # В реальной системе здесь будет ML модель
        
        behavior_score = 0
        
        # Проверка User-Agent
        if self._is_suspicious_user_agent(context.user_agent):
            behavior_score -= 15
        
        # Проверка частоты запросов
        if self._is_high_frequency_user(context.user_id):
            behavior_score -= 10
        
        return behavior_score
    
    def _evaluate_time_trust(self, timestamp: datetime) -> int:
        """Оценка временного доверия"""
        hour = timestamp.hour
        
        # Рабочее время (9-18) - выше доверие
        if 9 <= hour <= 18:
            return 5
        # Вечернее время (18-22) - нормальное доверие
        elif 18 <= hour <= 22:
            return 0
        # Ночное время (22-6) - пониженное доверие
        else:
            return -10
    
    def _register_device(self, context: SecurityContext):
        """Регистрация нового устройства"""
        device_id = hashlib.sha256(
            f"{context.user_id}_{context.device_fingerprint}_{time.time()}"
        ).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO trusted_devices 
            (device_id, user_id, device_fingerprint, device_name, trust_score)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, context.user_id, context.device_fingerprint, 
              f"Device-{device_id[:8]}", 30))  # Низкое начальное доверие
        
        conn.commit()
        conn.close()
        
        logger.info(f"Зарегистрировано новое устройство: {device_id}")
    
    def _is_malicious_ip(self, ip_address: str) -> bool:
        """Проверка IP в списках угроз (заглушка)"""
        # В реальной системе здесь будет интеграция с threat intelligence feeds
        malicious_ips = ['192.168.1.100', '10.0.0.50']  # Пример
        return ip_address in malicious_ips
    
    def _get_geo_risk(self, ip_address: str) -> int:
        """Получение риска геолокации (заглушка)"""
        # В реальной системе здесь будет интеграция с geo-IP сервисами
        high_risk_countries = ['CN', 'RU', 'NK']  # Пример
        # Возвращаем риск 0-10
        return 3  # Средний риск для примера
    
    def _is_suspicious_user_agent(self, user_agent: str) -> bool:
        """Проверка подозрительного User-Agent"""
        suspicious_patterns = [
            r'bot',
            r'crawler',
            r'spider',
            r'curl',
            r'wget'
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                return True
        
        return False
    
    def _is_high_frequency_user(self, user_id: str) -> bool:
        """Проверка высокочастотных запросов"""
        # Проверяем количество запросов за последние 5 минут
        cutoff_time = datetime.now() - timedelta(minutes=5)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM trust_sessions 
            WHERE user_id = ? AND last_activity > ?
        ''', (user_id, cutoff_time))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 100  # Более 100 запросов за 5 минут
    
    def _monitor_trust_levels(self):
        """Мониторинг уровней доверия"""
        while self.monitoring_active:
            try:
                self._update_device_trust_scores()
                self._cleanup_expired_sessions()
                time.sleep(300)  # Каждые 5 минут
            except Exception as e:
                logger.error(f"Ошибка мониторинга доверия: {e}")
                time.sleep(60)
    
    def _update_device_trust_scores(self):
        """Обновление рейтингов доверия устройств"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Получаем все активные устройства
        cursor.execute('SELECT device_id, trust_score, last_seen FROM trusted_devices')
        devices = cursor.fetchall()
        
        for device_id, trust_score, last_seen in devices:
            last_seen_dt = datetime.fromisoformat(last_seen)
            days_inactive = (datetime.now() - last_seen_dt).days
            
            # Снижаем доверие за неактивность
            if days_inactive > 30:
                new_trust_score = max(0, trust_score - 5)
                cursor.execute(
                    'UPDATE trusted_devices SET trust_score = ? WHERE device_id = ?',
                    (new_trust_score, device_id)
                )
        
        conn.commit()
        conn.close()
    
    def _cleanup_expired_sessions(self):
        """Очистка истекших сессий"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE trust_sessions SET status = 'expired'
            WHERE expires_at < CURRENT_TIMESTAMP AND status = 'active'
        ''')
        
        conn.commit()
        conn.close()

class ThreatDetectionEngine:
    """Движок обнаружения угроз"""
    
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}
        self.threat_indicators = {}
        self.ml_models = {}  # Заглушка для ML моделей
        
        self._init_threat_tables()
        self._load_threat_intelligence()
    
    def _init_threat_tables(self):
        """Инициализация таблиц для обнаружения угроз"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_indicators (
                indicator_id TEXT PRIMARY KEY,
                indicator TEXT NOT NULL,
                indicator_type TEXT NOT NULL,
                threat_level TEXT NOT NULL,
                source TEXT,
                description TEXT,
                confidence INTEGER,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS threat_events (
                event_id TEXT PRIMARY KEY,
                user_id TEXT,
                threat_type TEXT,
                description TEXT,
                severity TEXT,
                indicators TEXT,
                context TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_threat_intelligence(self):
        """Загрузка данных об угрозах"""
        # Пример данных об угрозах
        threat_data = [
            {
                'indicator': '192.168.1.100',
                'type': 'ip',
                'level': ThreatLevel.HIGH,
                'source': 'Internal Blacklist',
                'description': 'Known malicious IP'
            },
            {
                'indicator': 'malware.exe',
                'type': 'filename',
                'level': ThreatLevel.CRITICAL,
                'source': 'AV Engine',
                'description': 'Known malware file'
            }
        ]
        
        for data in threat_data:
            indicator_id = hashlib.sha256(
                f"{data['indicator']}_{data['type']}".encode()
            ).hexdigest()[:16]
            
            self.threat_indicators[indicator_id] = ThreatIntelligence(
                indicator=data['indicator'],
                indicator_type=data['type'],
                threat_level=data['level'],
                source=data['source'],
                description=data['description'],
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=90
            )
    
    def analyze_request(self, context: SecurityContext) -> Tuple[ThreatLevel, List[str]]:
        """Анализ запроса на угрозы"""
        threats = []
        max_threat_level = ThreatLevel.NONE
        
        # Проверка IP адреса
        ip_threats = self._check_ip_threats(context.ip_address)
        threats.extend(ip_threats)
        
        # Проверка User-Agent
        ua_threats = self._check_user_agent_threats(context.user_agent)
        threats.extend(ua_threats)
        
        # Проверка поведенческих аномалий
        behavior_threats = self._check_behavior_anomalies(context)
        threats.extend(behavior_threats)
        
        # Определяем максимальный уровень угрозы
        for threat in threats:
            threat_level = self._get_threat_level(threat)
            if threat_level.value > max_threat_level.value:
                max_threat_level = threat_level
        
        return max_threat_level, threats
    
    def _check_ip_threats(self, ip_address: str) -> List[str]:
        """Проверка угроз по IP адресу"""
        threats = []
        
        for indicator_id, threat_intel in self.threat_indicators.items():
            if (threat_intel.indicator_type == 'ip' and 
                threat_intel.indicator == ip_address):
                threats.append(f"Malicious IP detected: {ip_address}")
        
        return threats
    
    def _check_user_agent_threats(self, user_agent: str) -> List[str]:
        """Проверка угроз в User-Agent"""
        threats = []
        
        # Проверка подозрительных паттернов
        malicious_patterns = [
            r'sqlmap',
            r'nikto',
            r'nmap',
            r'masscan',
            r'<script>',
            r'union.*select',
            r'drop.*table'
        ]
        
        for pattern in malicious_patterns:
            if re.search(pattern, user_agent, re.IGNORECASE):
                threats.append(f"Suspicious User-Agent pattern: {pattern}")
        
        return threats
    
    def _check_behavior_anomalies(self, context: SecurityContext) -> List[str]:
        """Проверка поведенческих аномалий"""
        threats = []
        
        # Проверка на быструю смену IP адресов
        if self._detect_ip_hopping(context.user_id, context.ip_address):
            threats.append("Rapid IP address changes detected")
        
        # Проверка на подозрительное время доступа
        if self._detect_unusual_access_time(context.user_id, context.timestamp):
            threats.append("Unusual access time pattern")
        
        return threats
    
    def _detect_ip_hopping(self, user_id: str, current_ip: str) -> bool:
        """Обнаружение быстрой смены IP адресов"""
        # Проверяем последние 5 IP адресов за час
        cutoff_time = datetime.now() - timedelta(hours=1)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT DISTINCT source_ip FROM cloud_events 
            WHERE user_id = ? AND timestamp > ?
            ORDER BY timestamp DESC
            LIMIT 5
        ''', (user_id, cutoff_time))
        
        recent_ips = [row[0] for row in cursor.fetchall()]
        conn.close()
        
        # Если более 3 разных IP за час - подозрительно
        return len(set(recent_ips)) > 3
    
    def _detect_unusual_access_time(self, user_id: str, timestamp: datetime) -> bool:
        """Обнаружение необычного времени доступа"""
        hour = timestamp.hour
        
        # Проверяем обычное время доступа пользователя
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM cloud_events 
            WHERE user_id = ? AND 
                  strftime('%H', timestamp) BETWEEN ? AND ?
        ''', (user_id, str(hour-1).zfill(2), str(hour+1).zfill(2)))
        
        similar_time_count = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM cloud_events WHERE user_id = ?
        ''', (user_id,))
        
        total_count = cursor.fetchone()[0]
        conn.close()
        
        if total_count < 10:
            return False  # Недостаточно данных
        
        # Если менее 5% активности в это время - необычно
        return (similar_time_count / total_count) < 0.05
    
    def _get_threat_level(self, threat_description: str) -> ThreatLevel:
        """Определение уровня угрозы"""
        if 'malicious ip' in threat_description.lower():
            return ThreatLevel.HIGH
        elif 'suspicious' in threat_description.lower():
            return ThreatLevel.MEDIUM
        elif 'unusual' in threat_description.lower():
            return ThreatLevel.LOW
        else:
            return ThreatLevel.MEDIUM

class AdvancedSecurityManager:
    """Главный менеджер расширенной безопасности"""
    
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}
        
        # Инициализируем компоненты
        self.encryption = AdvancedEncryption()
        self.zero_trust = ZeroTrustEngine(db_path, self.config.get('zero_trust', {}))
        self.threat_detection = ThreatDetectionEngine(db_path, self.config.get('threat_detection', {}))
        
        # Безопасность API
        self.api_keys = {}
        self.rate_limits = {}
        
        self._init_security_tables()
        
        logger.info("Advanced Security Manager инициализирован")
    
    def _init_security_tables(self):
        """Инициализация таблиц безопасности"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS api_keys (
                key_id TEXT PRIMARY KEY,
                key_hash TEXT NOT NULL,
                user_id TEXT,
                permissions TEXT,
                rate_limit INTEGER DEFAULT 1000,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                active BOOLEAN DEFAULT TRUE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_events (
                event_id TEXT PRIMARY KEY,
                user_id TEXT,
                event_type TEXT,
                description TEXT,
                threat_level TEXT,
                context TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resolved BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def secure_request(self, context: SecurityContext) -> Tuple[SecurityAction, Dict[str, Any]]:
        """Безопасная обработка запроса"""
        # Оценка доверия
        trust_level = self.zero_trust.evaluate_trust(context)
        context.trust_level = trust_level
        
        # Анализ угроз
        threat_level, threats = self.threat_detection.analyze_request(context)
        
        # Вычисляем риск-скор
        risk_score = self._calculate_risk_score(trust_level, threat_level, threats)
        context.risk_score = risk_score
        
        # Определяем действие
        action = self._determine_security_action(risk_score, threat_level)
        
        # Логируем событие
        event = SecurityEvent(
            event_id=secrets.token_hex(16),
            context=context,
            event_type='request_analysis',
            description=f"Trust: {trust_level}, Threats: {len(threats)}",
            threat_level=threat_level,
            action_taken=action,
            timestamp=datetime.now(),
            evidence={'threats': threats, 'risk_score': risk_score}
        )
        
        self._log_security_event(event)
        
        return action, {
            'trust_level': trust_level,
            'threat_level': threat_level.name,
            'risk_score': risk_score,
            'threats': threats,
            'recommendations': self._get_security_recommendations(action)
        }
    
    def _calculate_risk_score(self, trust_level: int, threat_level: ThreatLevel, threats: List[str]) -> int:
        """Расчет риск-скора"""
        # Базовый риск от уровня доверия (инвертированный)
        risk_score = 100 - trust_level
        
        # Добавляем риск от угроз
        threat_multipliers = {
            ThreatLevel.NONE: 0,
            ThreatLevel.LOW: 10,
            ThreatLevel.MEDIUM: 25,
            ThreatLevel.HIGH: 50,
            ThreatLevel.CRITICAL: 100
        }
        
        risk_score += threat_multipliers.get(threat_level, 0)
        
        # Добавляем риск за количество угроз
        risk_score += len(threats) * 5
        
        # Нормализуем к диапазону 0-100
        return max(0, min(100, risk_score))
    
    def _determine_security_action(self, risk_score: int, threat_level: ThreatLevel) -> SecurityAction:
        """Определение действия безопасности"""
        if threat_level == ThreatLevel.CRITICAL or risk_score >= 90:
            return SecurityAction.BLOCK
        elif threat_level == ThreatLevel.HIGH or risk_score >= 70:
            return SecurityAction.QUARANTINE
        elif threat_level == ThreatLevel.MEDIUM or risk_score >= 50:
            return SecurityAction.MONITOR
        elif threat_level == ThreatLevel.LOW or risk_score >= 30:
            return SecurityAction.ALERT
        else:
            return SecurityAction.ALLOW
    
    def _get_security_recommendations(self, action: SecurityAction) -> List[str]:
        """Получение рекомендаций по безопасности"""
        recommendations = {
            SecurityAction.BLOCK: [
                "Заблокировать доступ",
                "Провести расследование инцидента",
                "Уведомить службу безопасности"
            ],
            SecurityAction.QUARANTINE: [
                "Ограничить доступ к критическим ресурсам",
                "Требовать дополнительную аутентификацию",
                "Усилить мониторинг активности"
            ],
            SecurityAction.MONITOR: [
                "Увеличить частоту мониторинга",
                "Регистрировать все действия",
                "Подготовить к блокировке при эскалации"
            ],
            SecurityAction.ALERT: [
                "Создать предупреждение",
                "Уведомить администратора",
                "Продолжить мониторинг"
            ],
            SecurityAction.ALLOW: [
                "Разрешить доступ",
                "Стандартное логирование"
            ]
        }
        
        return recommendations.get(action, ["Неизвестное действие"])
    
    def _log_security_event(self, event: SecurityEvent):
        """Логирование события безопасности"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_events 
            (event_id, user_id, event_type, description, threat_level, context)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (
            event.event_id,
            event.context.user_id,
            event.event_type,
            event.description,
            event.threat_level.name,
            json.dumps(asdict(event.context), default=str)
        ))
        
        conn.commit()
        conn.close()
    
    def generate_api_key(self, user_id: str, permissions: List[str], 
                        rate_limit: int = 1000, expires_in_days: int = 365) -> str:
        """Генерация API ключа"""
        # Генерируем ключ
        api_key = secrets.token_urlsafe(32)
        key_id = hashlib.sha256(api_key.encode()).hexdigest()[:16]
        
        # Хешируем ключ для хранения
        key_hash = bcrypt.hashpw(api_key.encode(), bcrypt.gensalt()).decode()
        
        # Сохраняем в БД
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        expires_at = datetime.now() + timedelta(days=expires_in_days)
        
        cursor.execute('''
            INSERT INTO api_keys 
            (key_id, key_hash, user_id, permissions, rate_limit, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (key_id, key_hash, user_id, json.dumps(permissions), rate_limit, expires_at))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Сгенерирован API ключ для пользователя {user_id}")
        
        return f"casb_{api_key}"
    
    def validate_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Валидация API ключа"""
        if not api_key.startswith('casb_'):
            return None
        
        key = api_key[5:]  # Убираем префикс
        key_id = hashlib.sha256(key.encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT key_hash, user_id, permissions, rate_limit, expires_at, active
            FROM api_keys WHERE key_id = ?
        ''', (key_id,))
        
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return None
        
        key_hash, user_id, permissions, rate_limit, expires_at, active = result
        
        # Проверяем хеш
        if not bcrypt.checkpw(key.encode(), key_hash.encode()):
            return None
        
        # Проверяем активность
        if not active:
            return None
        
        # Проверяем срок действия
        if datetime.now() > datetime.fromisoformat(expires_at):
            return None
        
        return {
            'user_id': user_id,
            'permissions': json.loads(permissions),
            'rate_limit': rate_limit
        }
    
    def check_rate_limit(self, user_id: str, endpoint: str, limit: int = 100) -> bool:
        """Проверка лимита запросов"""
        current_time = time.time()
        window_start = current_time - 60  # 1 минута
        
        key = f"{user_id}:{endpoint}"
        
        if key not in self.rate_limits:
            self.rate_limits[key] = []
        
        # Удаляем старые записи
        self.rate_limits[key] = [
            timestamp for timestamp in self.rate_limits[key] 
            if timestamp > window_start
        ]
        
        # Проверяем лимит
        if len(self.rate_limits[key]) >= limit:
            return False
        
        # Добавляем текущий запрос
        self.rate_limits[key].append(current_time)
        return True

def security_required(trust_threshold: int = 50, require_mfa: bool = False):
    """Декоратор для защиты эндпоинтов"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Получаем контекст из request (Flask)
            from flask import request, session, jsonify
            
            context = SecurityContext(
                user_id=session.get('user_id', 'anonymous'),
                session_id=session.get('session_id', 'unknown'),
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string,
                timestamp=datetime.now(),
                mfa_verified=session.get('mfa_verified', False)
            )
            
            # Проверяем MFA если требуется
            if require_mfa and not context.mfa_verified:
                return jsonify({'error': 'MFA required'}), 403
            
            # Проверяем безопасность (заглушка)
            # В реальном приложении здесь будет полная проверка
            if context.user_id == 'anonymous':
                return jsonify({'error': 'Authentication required'}), 401
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator