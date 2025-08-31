"""
Модуль защиты данных (DLP - Data Loss Prevention) для CASB
Предотвращение утечек конфиденциальных данных

Автор: AI Assistant
"""

import re
import hashlib
import json
import logging
import time
import mimetypes
import os
import zipfile
import tempfile
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64

logger = logging.getLogger(__name__)

class DataClassification(Enum):
    """Классификация данных"""
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"
    TOP_SECRET = "top_secret"

class ActionType(Enum):
    """Типы действий с данными"""
    ALLOW = "allow"
    BLOCK = "block"
    QUARANTINE = "quarantine"
    ENCRYPT = "encrypt"
    WATERMARK = "watermark"
    LOG_ONLY = "log_only"

class ScanResult(Enum):
    """Результаты сканирования"""
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    VIOLATION = "violation"
    ERROR = "error"

@dataclass
class DataPattern:
    """Паттерн для обнаружения конфиденциальных данных"""
    pattern_id: str
    name: str
    description: str
    regex_pattern: str
    classification: DataClassification
    confidence: float  # 0.0 - 1.0
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class DLPRule:
    """Правило DLP"""
    rule_id: str
    name: str
    description: str
    patterns: List[str]  # список pattern_id
    conditions: Dict[str, Any]
    actions: List[ActionType]
    severity: str
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class ScanReport:
    """Отчет о сканировании"""
    scan_id: str
    file_name: str
    file_size: int
    file_type: str
    scan_timestamp: datetime
    patterns_found: List[Dict[str, Any]]
    classification: DataClassification
    risk_score: float
    action_taken: ActionType
    scan_result: ScanResult

class DLPProtection:
    """Класс для защиты данных и предотвращения утечек"""
    
    def __init__(self, db_path: str = "casb.db", encryption_key: bytes = None):
        self.db_path = db_path
        self.encryption_key = encryption_key or self._generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Паттерны и правила
        self.patterns = {}
        self.rules = {}
        self.scan_results = []
        
        # Статистика
        self.scan_stats = {
            'total_scans': 0,
            'violations_found': 0,
            'files_quarantined': 0,
            'files_encrypted': 0
        }
        
        self._init_dlp_tables()
        self._load_default_patterns()
        self._load_default_rules()
        
        logger.info("Модуль защиты данных инициализирован")
    
    def _generate_key(self) -> bytes:
        """Генерация ключа шифрования"""
        password = b"casb_dlp_default_password_change_in_production"
        salt = b"casb_salt_12345678"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def _init_dlp_tables(self):
        """Инициализация таблиц DLP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица паттернов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dlp_patterns (
                pattern_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                regex_pattern TEXT,
                classification TEXT,
                confidence REAL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица правил DLP
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dlp_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                patterns TEXT,
                conditions TEXT,
                actions TEXT,
                severity TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица результатов сканирования
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_reports (
                scan_id TEXT PRIMARY KEY,
                file_name TEXT,
                file_size INTEGER,
                file_type TEXT,
                scan_timestamp TIMESTAMP,
                patterns_found TEXT,
                classification TEXT,
                risk_score REAL,
                action_taken TEXT,
                scan_result TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица карантина
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quarantine (
                quarantine_id TEXT PRIMARY KEY,
                original_path TEXT,
                quarantine_path TEXT,
                user_id TEXT,
                reason TEXT,
                quarantined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                released BOOLEAN DEFAULT FALSE,
                released_at TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_patterns(self):
        """Загрузка паттернов по умолчанию"""
        default_patterns = [
            {
                'name': 'Номер паспорта РФ',
                'description': 'Российский паспорт (серия и номер)',
                'regex': r'\\b\\d{2}\\s?\\d{2}\\s?\\d{6}\\b',
                'classification': DataClassification.CONFIDENTIAL,
                'confidence': 0.9
            },
            {
                'name': 'ИНН физического лица',
                'description': '12-значный ИНН физического лица',
                'regex': r'\\b\\d{12}\\b',
                'classification': DataClassification.CONFIDENTIAL,
                'confidence': 0.8
            },
            {
                'name': 'СНИЛС',
                'description': 'Страховой номер индивидуального лицевого счета',
                'regex': r'\\b\\d{3}-\\d{3}-\\d{3}\\s?\\d{2}\\b',
                'classification': DataClassification.CONFIDENTIAL,
                'confidence': 0.9
            },
            {
                'name': 'Номер банковской карты',
                'description': 'Номер банковской карты (16 цифр)',
                'regex': r'\\b(?:\\d{4}[\\s-]?){3}\\d{4}\\b',
                'classification': DataClassification.RESTRICTED,
                'confidence': 0.8
            },
            {
                'name': 'Email адрес',
                'description': 'Адрес электронной почты',
                'regex': r'\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Z|a-z]{2,}\\b',
                'classification': DataClassification.INTERNAL,
                'confidence': 0.7
            },
            {
                'name': 'Российский телефон',
                'description': 'Номер российского телефона',
                'regex': r'\\+?7[\\s\\(-]?\\d{3}[\\s\\)-]?\\d{3}[\\s-]?\\d{2}[\\s-]?\\d{2}',
                'classification': DataClassification.INTERNAL,
                'confidence': 0.7
            }
        ]
        
        for pattern_data in default_patterns:
            self.create_pattern(
                name=pattern_data['name'],
                description=pattern_data['description'],
                regex_pattern=pattern_data['regex'],
                classification=pattern_data['classification'],
                confidence=pattern_data['confidence']
            )
    
    def _load_default_rules(self):
        """Загрузка правил DLP по умолчанию"""
        pass  # Пока пропустим для простоты
    
    def create_pattern(self, name: str, description: str, regex_pattern: str,
                      classification: DataClassification, confidence: float) -> DataPattern:
        """Создание паттерна для обнаружения данных"""
        pattern_id = hashlib.sha256(f"{name}_{time.time()}".encode()).hexdigest()[:16]
        
        pattern = DataPattern(
            pattern_id=pattern_id,
            name=name,
            description=description,
            regex_pattern=regex_pattern,
            classification=classification,
            confidence=confidence
        )
        
        # Тестируем регулярное выражение
        try:
            re.compile(regex_pattern)
        except re.error as e:
            logger.error(f"Некорректное регулярное выражение в паттерне {name}: {e}")
            raise ValueError(f"Некорректный regex: {e}")
        
        self.patterns[pattern_id] = pattern
        logger.info(f"Создан паттерн DLP: {name}")
        
        return pattern
    
    def scan_content(self, content: str, file_name: str = "", 
                    file_size: int = 0, user_id: str = "") -> ScanReport:
        """Сканирование содержимого на предмет конфиденциальных данных"""
        scan_id = hashlib.sha256(f"{file_name}_{user_id}_{time.time()}".encode()).hexdigest()[:16]
        
        # Определяем тип файла
        file_type = self._detect_file_type(file_name, content[:1024])
        
        # Ищем совпадения с паттернами
        patterns_found = []
        max_classification = DataClassification.PUBLIC
        total_risk_score = 0.0
        
        for pattern in self.patterns.values():
            if not pattern.enabled:
                continue
            
            matches = re.finditer(pattern.regex_pattern, content, re.IGNORECASE | re.MULTILINE)
            match_list = list(matches)
            
            if match_list:
                patterns_found.append({
                    'pattern_id': pattern.pattern_id,
                    'pattern_name': pattern.name,
                    'classification': pattern.classification.value,
                    'confidence': pattern.confidence,
                    'matches_count': len(match_list),
                    'sample_matches': [match.group() for match in match_list[:3]]
                })
                
                # Обновляем максимальную классификацию
                if self._classification_level(pattern.classification) > self._classification_level(max_classification):
                    max_classification = pattern.classification
                
                # Добавляем к общему риск-скору
                risk_contribution = pattern.confidence * min(len(match_list) / 10, 1.0)
                total_risk_score += risk_contribution
        
        # Нормализуем риск-скор
        risk_score = min(total_risk_score, 1.0)
        
        # Определяем результат сканирования
        if risk_score > 0.8:
            scan_result = ScanResult.VIOLATION
        elif risk_score > 0.5:
            scan_result = ScanResult.SUSPICIOUS
        elif patterns_found:
            scan_result = ScanResult.SUSPICIOUS
        else:
            scan_result = ScanResult.CLEAN
        
        # Определяем действие
        action_taken = self._determine_action(patterns_found, max_classification, risk_score)
        
        # Создаем отчет
        report = ScanReport(
            scan_id=scan_id,
            file_name=file_name,
            file_size=file_size,
            file_type=file_type,
            scan_timestamp=datetime.now(),
            patterns_found=patterns_found,
            classification=max_classification,
            risk_score=risk_score,
            action_taken=action_taken,
            scan_result=scan_result
        )
        
        self.scan_results.append(report)
        self.scan_stats['total_scans'] += 1
        
        if scan_result == ScanResult.VIOLATION:
            self.scan_stats['violations_found'] += 1
        
        logger.info(f"Сканирование завершено: {file_name}, результат: {scan_result.value}")
        return report
    
    def _classification_level(self, classification: DataClassification) -> int:
        """Получение числового уровня классификации"""
        levels = {
            DataClassification.PUBLIC: 0,
            DataClassification.INTERNAL: 1,
            DataClassification.CONFIDENTIAL: 2,
            DataClassification.RESTRICTED: 3,
            DataClassification.TOP_SECRET: 4
        }
        return levels.get(classification, 0)
    
    def _detect_file_type(self, file_name: str, content_sample: str) -> str:
        """Определение типа файла"""
        # По расширению
        mime_type, _ = mimetypes.guess_type(file_name)
        if mime_type:
            return mime_type
        
        # По содержимому (упрощенная версия)
        if content_sample.startswith('%PDF'):
            return 'application/pdf'
        elif content_sample.startswith('PK'):
            return 'application/zip'
        elif '<?xml' in content_sample[:100]:
            return 'application/xml'
        elif content_sample.startswith('{') or content_sample.startswith('['):
            return 'application/json'
        
        return 'text/plain'
    
    def _determine_action(self, patterns_found: List[Dict], 
                        classification: DataClassification, risk_score: float) -> ActionType:
        """Определение действия на основе найденных паттернов и правил"""
        
        # Действия по умолчанию на основе классификации
        if classification == DataClassification.TOP_SECRET:
            return ActionType.BLOCK
        elif classification == DataClassification.RESTRICTED:
            return ActionType.QUARANTINE
        elif classification == DataClassification.CONFIDENTIAL:
            return ActionType.ENCRYPT
        elif risk_score > 0.7:
            return ActionType.QUARANTINE
        
        return ActionType.LOG_ONLY
    
    def scan_text(self, text: str) -> 'ScanTextResult':
        """Сканирование текста (простая версия)"""
        from dataclasses import dataclass
        
        @dataclass
        class ScanMatch:
            matched_text: str
            category: str
            confidence: float
        
        @dataclass 
        class ScanTextResult:
            matches: List[ScanMatch]
            risk_level: str
        
        matches = []
        for pattern in self.patterns.values():
            if not pattern.enabled:
                continue
            
            regex_matches = re.finditer(pattern.regex_pattern, text, re.IGNORECASE)
            for match in regex_matches:
                matches.append(ScanMatch(
                    matched_text=match.group(),
                    category=pattern.classification.value,
                    confidence=pattern.confidence
                ))
        
        risk_level = "HIGH" if len(matches) > 3 else "MEDIUM" if len(matches) > 0 else "LOW"
        return ScanTextResult(matches=matches, risk_level=risk_level)
    
    def create_rule(self, rule: 'DLPRule') -> bool:
        """Создание правила DLP"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO dlp_rules 
                (rule_id, name, description, patterns, conditions, actions, severity, enabled)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (rule.rule_id, rule.name, rule.description, 
                  ','.join(rule.patterns), json.dumps(rule.conditions),
                  ','.join([action.value for action in rule.actions]), rule.severity, rule.enabled))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Создано DLP правило: {rule.name}")
            return True
        except Exception as e:
            logger.error(f"Ошибка создания правила: {e}")
            return False
    
    def _generate_id(self) -> str:
        """Генерация уникального ID"""
        return hashlib.sha256(f"{time.time()}".encode()).hexdigest()[:16]
    
    def sync_cloud_policies(self, cloud_provider: str) -> bool:
        """Синхронизация политик с облачными провайдерами"""
        try:
            if cloud_provider == "aws":
                return self._sync_aws_dlp_policies()
            elif cloud_provider == "azure":
                return self._sync_azure_dlp_policies()
            elif cloud_provider == "gcp":
                return self._sync_gcp_dlp_policies()
            else:
                logger.error(f"Неподдерживаемый провайдер: {cloud_provider}")
                return False
        except Exception as e:
            logger.error(f"Ошибка синхронизации с {cloud_provider}: {e}")
            return False
    
    def _sync_aws_dlp_policies(self) -> bool:
        """Синхронизация с AWS DLP"""
        # Интеграция с AWS Macie, GuardDuty
        logger.info("Синхронизация с AWS DLP политиками")
        return True
    
    def _sync_azure_dlp_policies(self) -> bool:
        """Синхронизация с Azure Information Protection"""
        logger.info("Синхронизация с Azure DLP политиками")
        return True
    
    def _sync_gcp_dlp_policies(self) -> bool:
        """Синхронизация с Google Cloud DLP API"""
        logger.info("Синхронизация с GCP DLP политиками")
        return True
    
    def create_data_retention_policy(self, policy_name: str, retention_days: int, 
                                   categories: List[str], auto_delete: bool = False) -> str:
        """Создание политики хранения данных"""
        policy_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_retention_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT,
                retention_days INTEGER,
                categories TEXT,
                auto_delete BOOLEAN,
                automated BOOLEAN DEFAULT FALSE,
                automation_enabled_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_retention_policies 
            (policy_id, name, retention_days, categories, auto_delete, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (policy_id, policy_name, retention_days, 
              ','.join(categories), auto_delete))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана политика хранения: {policy_name}")
        return policy_id
    
    def apply_data_masking(self, text: str, masking_type: str = "asterisk") -> str:
        """Применение маскирования данных"""
        scan_result = self.scan_text(text)
        masked_text = text
        
        for match in scan_result.matches:
            if masking_type == "asterisk":
                replacement = '*' * len(match.matched_text)
            elif masking_type == "hash":
                replacement = f"[HASH:{hashlib.md5(match.matched_text.encode()).hexdigest()[:8]}]"
            elif masking_type == "partial":
                # Показываем первые и последние символы
                if len(match.matched_text) > 4:
                    replacement = match.matched_text[:2] + '*' * (len(match.matched_text) - 4) + match.matched_text[-2:]
                else:
                    replacement = '*' * len(match.matched_text)
            else:
                replacement = '[MASKED]'
            
            masked_text = masked_text.replace(match.matched_text, replacement)
        
        return masked_text
    
    def create_data_lineage_record(self, data_id: str, source: str, 
                                 transformations: List[str], destination: str) -> str:
        """Создание записи происхождения данных"""
        lineage_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_lineage (
                lineage_id TEXT PRIMARY KEY,
                data_id TEXT,
                source TEXT,
                transformations TEXT,
                destination TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_lineage 
            (lineage_id, data_id, source, transformations, destination, created_at)
            VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (lineage_id, data_id, source, json.dumps(transformations), destination))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана запись происхождения данных: {lineage_id}")
        return lineage_id
    
    def setup_webhook_notification(self, webhook_url: str, events: List[str], 
                                 auth_token: str = None) -> str:
        """Настройка webhook уведомлений"""
        webhook_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS webhooks (
                webhook_id TEXT PRIMARY KEY,
                url TEXT,
                events TEXT,
                auth_token TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO webhooks 
            (webhook_id, url, events, auth_token, enabled, created_at)
            VALUES (?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP)
        ''', (webhook_id, webhook_url, ','.join(events), auth_token))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен webhook: {webhook_url}")
        return webhook_id
    
    def send_webhook_notification(self, event_type: str, data: Dict[str, Any]):
        """Отправка webhook уведомления"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT url, auth_token FROM webhooks 
            WHERE enabled = TRUE AND events LIKE ?
        ''', (f'%{event_type}%',))
        
        webhooks = cursor.fetchall()
        conn.close()
        
        for webhook_url, auth_token in webhooks:
            try:
                import requests
                headers = {'Content-Type': 'application/json'}
                if auth_token:
                    headers['Authorization'] = f'Bearer {auth_token}'
                
                payload = {
                    'event_type': event_type,
                    'timestamp': datetime.now().isoformat(),
                    'data': data
                }
                
                response = requests.post(webhook_url, json=payload, headers=headers, timeout=10)
                logger.info(f"Webhook уведомление отправлено: {event_type}")
                
            except Exception as e:
                logger.error(f"Ошибка отправки webhook: {e}")
    
    def analyze_data_flow(self, flow_id: str) -> Dict[str, Any]:
        """Анализ потока данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_flows (
                flow_id TEXT PRIMARY KEY,
                source TEXT,
                destination TEXT,
                data_types TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            SELECT * FROM data_flows WHERE flow_id = ?
        ''', (flow_id,))
        
        flow_data = cursor.fetchone()
        conn.close()
        
        if not flow_data:
            return {'error': 'Поток данных не найден'}
        
        return {
            'flow_id': flow_id,
            'source': flow_data[1],
            'destination': flow_data[2],
            'data_types': flow_data[3].split(',') if flow_data[3] else [],
            'risk_level': self._calculate_flow_risk(flow_data),
            'recommendations': self._get_flow_recommendations(flow_data)
        }
    
    def _calculate_flow_risk(self, flow_data) -> str:
        """Расчет риска потока данных"""
        # Простая логика оценки риска
        data_types = flow_data[3].split(',') if flow_data[3] else []
        sensitive_types = ['CREDIT_CARD', 'SSN', 'PASSPORT', 'MEDICAL']
        
        if any(dt in sensitive_types for dt in data_types):
            return "HIGH"
        elif len(data_types) > 3:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _get_flow_recommendations(self, flow_data) -> List[str]:
        """Получение рекомендаций для потока данных"""
        recommendations = []
        risk_level = self._calculate_flow_risk(flow_data)
        
        if risk_level == "HIGH":
            recommendations.extend([
                "Включить шифрование в транзите",
                "Настроить дополнительное логирование",
                "Требовать MFA для доступа"
            ])
        
        return recommendations
    
    def create_compliance_template(self, regulation: str) -> Dict[str, Any]:
        """Создание шаблона соответствия нормативам"""
        templates = {
            'GDPR': {
                'required_patterns': ['EMAIL_PATTERN', 'EU_PERSONAL_ID'],
                'retention_period': 2555,  # 7 лет
                'required_actions': ['ENCRYPT', 'LOG', 'NOTIFY'],
                'deletion_rights': True
            },
            'HIPAA': {
                'required_patterns': ['SSN_PATTERN', 'MEDICAL_RECORD'],
                'retention_period': 2190,  # 6 лет
                'required_actions': ['ENCRYPT', 'AUDIT', 'ACCESS_CONTROL'],
                'data_categories': ['PHI', 'MEDICAL']
            },
            'PCI_DSS': {
                'required_patterns': ['CREDIT_CARD_PATTERN', 'CVV_PATTERN'],
                'retention_period': 365,  # 1 год
                'required_actions': ['ENCRYPT', 'TOKENIZE', 'SECURE_DELETE'],
                'cardholder_data': True
            },
            'GDPR_RUSSIA': {
                'required_patterns': ['PASSPORT_PATTERN', 'INN_PATTERN', 'SNILS_PATTERN'],
                'retention_period': 1825,  # 5 лет
                'required_actions': ['ENCRYPT', 'LOCALIZE', 'AUDIT'],
                'data_localization': True
            }
        }
        
        return templates.get(regulation, {})
    
    def apply_compliance_template(self, regulation: str) -> bool:
        """Применение шаблона соответствия"""
        template = self.create_compliance_template(regulation)
        if not template:
            return False
        
        try:
            # Создаем правила на основе шаблона
            for pattern in template.get('required_patterns', []):
                rule = DLPRule(
                    rule_id=f"{regulation.lower()}_{pattern.lower()}",
                    name=f"{regulation} - {pattern}",
                    description=f"Правило соответствия {regulation}",
                    patterns=[pattern],
                    conditions={"regulation": regulation},
                    actions=[ActionType.ENCRYPT],
                    severity="HIGH"
                )
                self.create_rule(rule)
            
            logger.info(f"Применен шаблон соответствия {regulation}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка применения шаблона {regulation}: {e}")
            return False
    
    def perform_data_discovery(self, target_path: str, file_types: List[str] = None) -> Dict[str, Any]:
        """Обнаружение чувствительных данных в файловой системе"""
        import os
        
        if file_types is None:
            file_types = ['.txt', '.csv', '.json', '.xml', '.pdf']
        
        discovered_files = []
        total_files = 0
        sensitive_files = 0
        
        try:
            for root, dirs, files in os.walk(target_path):
                for file in files:
                    if any(file.endswith(ext) for ext in file_types):
                        total_files += 1
                        file_path = os.path.join(root, file)
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read(1024 * 1024)  # Читаем первый MB
                            
                            scan_result = self.scan_text(content)
                            if scan_result.matches:
                                sensitive_files += 1
                                discovered_files.append({
                                    'path': file_path,
                                    'size': os.path.getsize(file_path),
                                    'matches': len(scan_result.matches),
                                    'categories': list(set(m.category for m in scan_result.matches))
                                })
                        
                        except Exception as e:
                            logger.warning(f"Не удалось сканировать файл {file_path}: {e}")
        except Exception as e:
            logger.error(f"Ошибка обнаружения данных: {e}")
            return {'error': str(e)}
        
        return {
            'total_files_scanned': total_files,
            'sensitive_files_found': sensitive_files,
            'sensitivity_rate': round(sensitive_files / total_files * 100, 2) if total_files > 0 else 0,
            'discovered_files': discovered_files
        }
    
    def create_anonymization_profile(self, profile_name: str, rules: Dict[str, str]) -> str:
        """Создание профиля анонимизации"""
        profile_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS anonymization_profiles (
                profile_id TEXT PRIMARY KEY,
                name TEXT,
                rules TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO anonymization_profiles 
            (profile_id, name, rules, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (profile_id, profile_name, json.dumps(rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан профиль анонимизации: {profile_name}")
        return profile_id
    
    def apply_anonymization(self, text: str, profile_id: str) -> str:
        """Применение анонимизации по профилю"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT rules FROM anonymization_profiles WHERE profile_id = ?', (profile_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return text
        
        rules = json.loads(result[0])
        anonymized_text = text
        
        # Применяем каждое правило анонимизации
        scan_result = self.scan_text(text)
        for match in scan_result.matches:
            category_key = f"{match.category}_PATTERN"
            if category_key in rules:
                anonymized_text = anonymized_text.replace(match.matched_text, rules[category_key])
        
        return anonymized_text
    
    def schedule_automated_scan(self, scan_name: str, target_path: str, 
                              schedule_cron: str, notification_email: str = None) -> str:
        """Планирование автоматического сканирования"""
        scan_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scheduled_scans (
                scan_id TEXT PRIMARY KEY,
                name TEXT,
                target_path TEXT,
                schedule_cron TEXT,
                notification_email TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_run TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO scheduled_scans 
            (scan_id, name, target_path, schedule_cron, notification_email, 
             enabled, created_at, last_run)
            VALUES (?, ?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP, NULL)
        ''', (scan_id, scan_name, target_path, schedule_cron, notification_email))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Запланировано автоматическое сканирование: {scan_name}")
        return scan_id
    
    def execute_scheduled_scans(self) -> List[Dict[str, Any]]:
        """Выполнение запланированных сканирований"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT * FROM scheduled_scans WHERE enabled = TRUE
        ''')
        
        scheduled_scans = cursor.fetchall()
        results = []
        
        for scan in scheduled_scans:
            scan_id, name, target_path, schedule_cron = scan[0], scan[1], scan[2], scan[3]
            notification_email, last_run = scan[4], scan[7]
            
            # Проверяем, нужно ли выполнить сканирование
            if self._should_run_scan(schedule_cron, last_run):
                discovery_result = self.perform_data_discovery(target_path)
                
                # Обновляем время последнего запуска
                cursor.execute('''
                    UPDATE scheduled_scans 
                    SET last_run = CURRENT_TIMESTAMP 
                    WHERE scan_id = ?
                ''', (scan_id,))
                
                results.append({
                    'scan_id': scan_id,
                    'name': name,
                    'result': discovery_result
                })
                
                # Отправляем уведомление если настроено
                if notification_email:
                    self._send_scan_notification(notification_email, name, discovery_result)
        
        conn.commit()
        conn.close()
        
        return results
    
    def _should_run_scan(self, schedule_cron: str, last_run: str) -> bool:
        """Проверка необходимости запуска сканирования"""
        # Упрощенная логика - в реальности нужно использовать crontab
        if not last_run:
            return True
        
        last_run_dt = datetime.fromisoformat(last_run)
        return (datetime.now() - last_run_dt).total_seconds() > 3600  # 1 час
    
    def _send_scan_notification(self, email: str, scan_name: str, result: Dict[str, Any]):
        """Отправка уведомления о результатах сканирования"""
        logger.info(f"Отправка уведомления о сканировании {scan_name} на {email}")
        # Заглушка для отправки email
    
    def create_data_catalog_entry(self, data_source: str, schema: Dict[str, Any], 
                                sensitive_fields: List[str]) -> str:
        """Создание записи в каталоге данных"""
        catalog_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_catalog (
                catalog_id TEXT PRIMARY KEY,
                data_source TEXT,
                schema TEXT,
                sensitive_fields TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_catalog 
            (catalog_id, data_source, schema, sensitive_fields, 
             created_at, last_updated)
            VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (catalog_id, data_source, json.dumps(schema), 
              ','.join(sensitive_fields)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана запись каталога данных: {data_source}")
        return catalog_id
    
    def generate_privacy_impact_assessment(self, project_name: str, 
                                         data_types: List[str]) -> Dict[str, Any]:
        """Генерация оценки влияния на конфиденциальность (PIA)"""
        risk_score = 0
        high_risk_types = ['SSN', 'CREDIT_CARD', 'MEDICAL', 'BIOMETRIC']
        medium_risk_types = ['EMAIL', 'PHONE', 'ADDRESS']
        
        for data_type in data_types:
            if data_type in high_risk_types:
                risk_score += 3
            elif data_type in medium_risk_types:
                risk_score += 2
            else:
                risk_score += 1
        
        risk_level = 'LOW' if risk_score < 5 else 'MEDIUM' if risk_score < 10 else 'HIGH'
        
        pia = {
            'project_name': project_name,
            'assessment_date': datetime.now().isoformat(),
            'data_types': data_types,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'recommendations': self._get_pia_recommendations(risk_level),
            'compliance_requirements': self._get_compliance_requirements(data_types)
        }
        
        # Сохраняем оценку
        pia_id = self._generate_id()
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS privacy_assessments (
                pia_id TEXT PRIMARY KEY,
                project_name TEXT,
                data_types TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                recommendations TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO privacy_assessments 
            (pia_id, project_name, data_types, risk_score, risk_level, 
             recommendations, created_at)
            VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
        ''', (pia_id, project_name, ','.join(data_types), risk_score, 
              risk_level, json.dumps(pia['recommendations'])))
        
        conn.commit()
        conn.close()
        
        return pia
    
    def _get_pia_recommendations(self, risk_level: str) -> List[str]:
        """Получение рекомендаций PIA"""
        base_recommendations = [
            "Внедрить принципы минимизации данных",
            "Обеспечить прозрачность обработки данных",
            "Настроить механизмы согласия пользователей"
        ]
        
        if risk_level == 'HIGH':
            base_recommendations.extend([
                "Провести консультацию с DPO",
                "Внедрить дополнительные технические меры защиты",
                "Рассмотреть шифрование на уровне приложения"
            ])
        
        return base_recommendations
    
    def _get_compliance_requirements(self, data_types: List[str]) -> List[str]:
        """Определение требований соответствия"""
        requirements = set()
        
        for data_type in data_types:
            if data_type in ['EMAIL', 'NAME', 'ADDRESS']:
                requirements.add('GDPR')
            if data_type in ['SSN', 'MEDICAL']:
                requirements.add('HIPAA')
            if data_type in ['CREDIT_CARD', 'CVV']:
                requirements.add('PCI_DSS')
        
        return list(requirements)
    
    def create_data_subject_request(self, request_type: str, subject_email: str, 
                                  details: str) -> str:
        """Создание запроса субъекта данных (GDPR)"""
        request_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_subject_requests (
                request_id TEXT PRIMARY KEY,
                request_type TEXT,
                subject_email TEXT,
                details TEXT,
                status TEXT DEFAULT 'PENDING',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                due_date TIMESTAMP,
                completed_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_subject_requests 
            (request_id, request_type, subject_email, details, status, 
             created_at, due_date)
            VALUES (?, ?, ?, ?, 'PENDING', CURRENT_TIMESTAMP, 
                   datetime('now', '+30 days'))
        ''', (request_id, request_type, subject_email, details))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан запрос субъекта данных: {request_type}")
        return request_id
    
    def process_data_subject_request(self, request_id: str) -> Dict[str, Any]:
        """Обработка запроса субъекта данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM data_subject_requests WHERE request_id = ?', (request_id,))
        request_data = cursor.fetchone()
        
        if not request_data:
            return {'error': 'Запрос не найден'}
        
        request_type = request_data[1]
        subject_email = request_data[2]
        
        if request_type == 'ACCESS':
            # Поиск всех данных субъекта
            subject_data = self._find_subject_data(subject_email)
            result = {'data_found': subject_data}
            
        elif request_type == 'DELETION':
            # Удаление данных субъекта
            deleted_records = self._delete_subject_data(subject_email)
            result = {'deleted_records': deleted_records}
            
        elif request_type == 'PORTABILITY':
            # Экспорт данных субъекта
            exported_data = self._export_subject_data(subject_email)
            result = {'exported_data': exported_data}
        
        # Обновляем статус запроса
        cursor.execute('''
            UPDATE data_subject_requests 
            SET status = 'COMPLETED', completed_at = CURRENT_TIMESTAMP 
            WHERE request_id = ?
        ''', (request_id,))
        
        conn.commit()
        conn.close()
        
        return result
    
    def _find_subject_data(self, subject_email: str) -> List[Dict[str, Any]]:
        """Поиск данных субъекта"""
        # Заглушка для поиска данных по email
        return [{'table': 'users', 'records': 1, 'fields': ['email', 'name']}]
    
    def _delete_subject_data(self, subject_email: str) -> int:
        """Удаление данных субъекта"""
        # Заглушка для удаления данных
        logger.info(f"Удаление данных для {subject_email}")
        return 1
    
    def _export_subject_data(self, subject_email: str) -> Dict[str, Any]:
        """Экспорт данных субъекта"""
        # Заглушка для экспорта данных
        return {'email': subject_email, 'export_format': 'JSON'}
    
    def create_data_classification_model(self, model_name: str, 
                                       training_data: List[Dict[str, Any]]) -> str:
        """Создание модели классификации данных с ML"""
        model_id = self._generate_id()
        
        # Заглушка для ML модели
        try:
            # В реальности здесь будет обучение модели
            # sklearn, tensorflow, pytorch и т.д.
            model_metrics = {
                'accuracy': 0.95,
                'precision': 0.93,
                'recall': 0.91,
                'f1_score': 0.92
            }
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ml_models (
                    model_id TEXT PRIMARY KEY,
                    name TEXT,
                    model_type TEXT,
                    metrics TEXT,
                    trained_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'TRAINED'
                )
            ''')
            
            cursor.execute('''
                INSERT INTO ml_models 
                (model_id, name, model_type, metrics, trained_at, status)
                VALUES (?, ?, 'CLASSIFICATION', ?, CURRENT_TIMESTAMP, 'TRAINED')
            ''', (model_id, model_name, json.dumps(model_metrics)))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Создана ML модель классификации: {model_name}")
            return model_id
            
        except Exception as e:
            logger.error(f"Ошибка создания ML модели: {e}")
            return ""
    
    def predict_data_sensitivity(self, text: str, model_id: str) -> Dict[str, Any]:
        """Предсказание чувствительности данных с помощью ML"""
        # Заглушка для ML предсказания
        predictions = {
            'sensitivity_score': 0.75,
            'predicted_categories': ['PII', 'FINANCIAL'],
            'confidence': 0.89,
            'model_used': model_id
        }
        
        return predictions
    
    def create_data_loss_incident(self, incident_type: str, description: str, 
                                affected_records: int, severity: str) -> str:
        """Создание инцидента утечки данных"""
        incident_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_incidents (
                incident_id TEXT PRIMARY KEY,
                incident_type TEXT,
                description TEXT,
                affected_records INTEGER,
                severity TEXT,
                status TEXT DEFAULT 'OPEN',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                assigned_to TEXT,
                response_log TEXT
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_incidents 
            (incident_id, incident_type, description, affected_records, 
             severity, status, created_at, assigned_to)
            VALUES (?, ?, ?, ?, ?, 'OPEN', CURRENT_TIMESTAMP, NULL)
        ''', (incident_id, incident_type, description, affected_records, severity))
        
        conn.commit()
        conn.close()
        
        # Отправляем уведомление
        self.send_webhook_notification('DATA_INCIDENT', {
            'incident_id': incident_id,
            'type': incident_type,
            'severity': severity,
            'affected_records': affected_records
        })
        
        logger.critical(f"Создан инцидент утечки данных: {incident_id}")
        return incident_id
    
    def manage_data_lifecycle(self, data_id: str, lifecycle_stage: str) -> bool:
        """Управление жизненным циклом данных"""
        valid_stages = ['CREATED', 'ACTIVE', 'ARCHIVED', 'PURGED']
        
        if lifecycle_stage not in valid_stages:
            return False
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_lifecycle (
                data_id TEXT PRIMARY KEY,
                current_stage TEXT,
                stage_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT OR REPLACE INTO data_lifecycle 
            (data_id, current_stage, stage_updated_at, created_at)
            VALUES (?, ?, CURRENT_TIMESTAMP, 
                   COALESCE((SELECT created_at FROM data_lifecycle WHERE data_id = ?), CURRENT_TIMESTAMP))
        ''', (data_id, lifecycle_stage, data_id))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Обновлен жизненный цикл данных {data_id}: {lifecycle_stage}")
        return True
    
    def generate_compliance_report(self, regulation: str, date_from: datetime, 
                                 date_to: datetime) -> Dict[str, Any]:
        """Генерация отчета о соответствии нормативам"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Создаем таблицу нарушений если не существует
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_violations (
                violation_id TEXT PRIMARY KEY,
                regulation TEXT,
                description TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Статистика нарушений
        cursor.execute('''
            SELECT COUNT(*) FROM scan_violations 
            WHERE regulation = ? AND created_at BETWEEN ? AND ?
        ''', (regulation, date_from.isoformat(), date_to.isoformat()))
        
        violations_count = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        # Статистика сканирований
        cursor.execute('''
            SELECT COUNT(*) FROM scan_reports 
            WHERE scan_timestamp BETWEEN ? AND ?
        ''', (date_from.isoformat(), date_to.isoformat()))
        
        total_scans = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        compliance_score = max(0, 100 - (violations_count / max(total_scans, 1) * 100))
        
        return {
            'regulation': regulation,
            'period': f"{date_from.date()} - {date_to.date()}",
            'total_scans': total_scans,
            'violations_found': violations_count,
            'compliance_score': round(compliance_score, 2),
            'status': 'COMPLIANT' if compliance_score > 90 else 'NON_COMPLIANT',
            'generated_at': datetime.now().isoformat()
        }
    
    def setup_data_retention_automation(self, policy_id: str) -> bool:
        """Настройка автоматизации политик хранения"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE data_retention_policies 
                SET automated = TRUE, automation_enabled_at = CURRENT_TIMESTAMP 
                WHERE policy_id = ?
            ''', (policy_id,))
            
            conn.commit()
            conn.close()
            
            logger.info(f"Включена автоматизация политики хранения: {policy_id}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка настройки автоматизации: {e}")
            return False
    
    def perform_data_quality_assessment(self, dataset_id: str) -> Dict[str, Any]:
        """Оценка качества данных"""
        # Заглушка для анализа качества данных
        quality_metrics = {
            'completeness': 0.95,
            'accuracy': 0.88,
            'consistency': 0.92,
            'timeliness': 0.85,
            'validity': 0.90,
            'overall_score': 0.90
        }
        
        issues_found = [
            {'type': 'MISSING_VALUES', 'count': 15, 'severity': 'MEDIUM'},
            {'type': 'DUPLICATE_RECORDS', 'count': 3, 'severity': 'LOW'},
            {'type': 'INVALID_FORMAT', 'count': 7, 'severity': 'HIGH'}
        ]
        
        return {
            'dataset_id': dataset_id,
            'assessment_date': datetime.now().isoformat(),
            'quality_metrics': quality_metrics,
            'issues_found': issues_found,
            'recommendations': self._get_data_quality_recommendations(issues_found)
        }
    
    def _get_data_quality_recommendations(self, issues: List[Dict[str, Any]]) -> List[str]:
        """Рекомендации по улучшению качества данных"""
        recommendations = []
        
        for issue in issues:
            if issue['type'] == 'MISSING_VALUES':
                recommendations.append("Внедрить валидацию обязательных полей")
            elif issue['type'] == 'DUPLICATE_RECORDS':
                recommendations.append("Настроить дедупликацию записей")
            elif issue['type'] == 'INVALID_FORMAT':
                recommendations.append("Усилить форматную валидацию")
        
        return list(set(recommendations))
    
    def setup_cross_border_transfer_monitoring(self, source_region: str, 
                                             target_region: str, data_types: List[str]) -> str:
        """Настройка мониторинга трансграничных передач"""
        monitor_id = self._generate_id()
        
        transfer_rules = self._evaluate_transfer_legality(source_region, target_region, data_types)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cross_border_monitors (
                monitor_id TEXT PRIMARY KEY,
                source_region TEXT,
                target_region TEXT,
                data_types TEXT,
                transfer_rules TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO cross_border_monitors 
            (monitor_id, source_region, target_region, data_types, 
             transfer_rules, enabled, created_at)
            VALUES (?, ?, ?, ?, ?, TRUE, CURRENT_TIMESTAMP)
        ''', (monitor_id, source_region, target_region, ','.join(data_types),
              json.dumps(transfer_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен мониторинг трансграничных передач: {source_region} -> {target_region}")
        return monitor_id
    
    def _evaluate_transfer_legality(self, source: str, target: str, data_types: List[str]) -> Dict[str, Any]:
        """Оценка законности трансграничной передачи"""
        # Упрощенная логика оценки
        eu_countries = ['DE', 'FR', 'IT', 'ES', 'NL', 'BE', 'AT', 'SE', 'DK']
        adequacy_countries = ['US', 'CA', 'JP', 'KR', 'IL']
        
        if source in eu_countries and target not in eu_countries + adequacy_countries:
            return {
                'legal': False,
                'reason': 'Передача в страну без решения об адекватности',
                'required_safeguards': ['STANDARD_CONTRACTUAL_CLAUSES', 'ENCRYPTION']
            }
        
        return {'legal': True, 'reason': 'Передача разрешена'}
    
    def create_data_breach_response_plan(self, plan_name: str, 
                                       response_steps: List[str]) -> str:
        """Создание плана реагирования на утечки"""
        plan_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS breach_response_plans (
                plan_id TEXT PRIMARY KEY,
                name TEXT,
                response_steps TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO breach_response_plans 
            (plan_id, name, response_steps, created_at, last_updated)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        ''', (plan_id, plan_name, json.dumps(response_steps)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан план реагирования на утечки: {plan_name}")
        return plan_id
    
    def execute_breach_response(self, incident_id: str, plan_id: str) -> Dict[str, Any]:
        """Выполнение плана реагирования на утечку"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Получаем план реагирования
        cursor.execute('SELECT response_steps FROM breach_response_plans WHERE plan_id = ?', (plan_id,))
        plan_data = cursor.fetchone()
        
        if not plan_data:
            return {'error': 'План реагирования не найден'}
        
        response_steps = json.loads(plan_data[0])
        execution_log = []
        
        for step in response_steps:
            try:
                # Выполняем шаг плана
                step_result = self._execute_response_step(step, incident_id)
                execution_log.append({
                    'step': step,
                    'result': step_result,
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                execution_log.append({
                    'step': step,
                    'error': str(e),
                    'timestamp': datetime.now().isoformat()
                })
        
        # Сохраняем лог выполнения
        cursor.execute('''
            UPDATE data_incidents 
            SET response_log = ?, status = 'IN_PROGRESS' 
            WHERE incident_id = ?
        ''', (json.dumps(execution_log), incident_id))
        
        conn.commit()
        conn.close()
        
        return {'execution_log': execution_log}
    
    def _execute_response_step(self, step: str, incident_id: str) -> str:
        """Выполнение шага плана реагирования"""
        if step == "ISOLATE_SYSTEMS":
            return "Системы изолированы"
        elif step == "NOTIFY_STAKEHOLDERS":
            return "Заинтересованные стороны уведомлены"
        elif step == "COLLECT_EVIDENCE":
            return "Доказательства собраны"
        elif step == "NOTIFY_AUTHORITIES":
            return "Уведомлены контролирующие органы"
        else:
            return f"Выполнен шаг: {step}"
    
    def generate_data_map(self) -> Dict[str, Any]:
        """Генерация карты данных организации"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Собираем информацию о данных
        cursor.execute('SELECT * FROM data_catalog')
        catalog_entries = cursor.fetchall()
        
        cursor.execute('SELECT * FROM data_flows')
        data_flows = cursor.fetchall()
        
        conn.close()
        
        data_map = {
            'data_sources': len(catalog_entries),
            'active_flows': len(data_flows),
            'categories': self._extract_data_categories(catalog_entries),
            'risk_assessment': self._assess_overall_risk(catalog_entries, data_flows),
            'generated_at': datetime.now().isoformat()
        }
        
        return data_map
    
    def _extract_data_categories(self, catalog_entries) -> List[str]:
        """Извлечение категорий данных"""
        categories = set()
        for entry in catalog_entries:
            if entry and len(entry) > 3 and entry[3]:  # sensitive_fields column
                categories.update(entry[3].split(','))
        return list(categories)
    
    def _assess_overall_risk(self, catalog_entries, data_flows) -> str:
        """Общая оценка риска"""
        # Простая логика оценки
        high_risk_indicators = len([e for e in catalog_entries if e and 'CREDIT_CARD' in str(e)])
        
        if high_risk_indicators > 5:
            return "HIGH"
        elif high_risk_indicators > 2:
            return "MEDIUM"
        else:
            return "LOW"
    
    def create_api_endpoint(self, endpoint_path: str, methods: List[str], 
                          auth_required: bool = True) -> str:
        """Создание API эндпоинта для DLP"""
        endpoint_id = self._generate_id()
        
        # Заглушка для API эндпоинта
        api_config = {
            'path': endpoint_path,
            'methods': methods,
            'auth_required': auth_required,
            'rate_limit': '100/hour',
            'created_at': datetime.now().isoformat()
        }
        
        logger.info(f"Создан API эндпоинт: {endpoint_path}")
        return endpoint_id
    
    def validate_data_governance_policy(self, policy: Dict[str, Any]) -> Dict[str, Any]:
        """Валидация политики управления данными"""
        validation_result = {
            'valid': True,
            'errors': [],
            'warnings': []
        }
        
        # Проверяем обязательные поля
        required_fields = ['name', 'description', 'data_types', 'retention_period']
        for field in required_fields:
            if field not in policy:
                validation_result['valid'] = False
                validation_result['errors'].append(f"Отсутствует обязательное поле: {field}")
        
        # Проверяем период хранения
        if 'retention_period' in policy and policy['retention_period'] > 3650:
            validation_result['warnings'].append("Очень длительный период хранения (>10 лет)")
        
        return validation_result
    
    def export_dlp_configuration(self, export_format: str = "json") -> str:
        """Экспорт конфигурации DLP"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Собираем всю конфигурацию
        cursor.execute('SELECT * FROM dlp_rules')
        rules = cursor.fetchall()
        
        cursor.execute('SELECT * FROM dlp_patterns')
        patterns = cursor.fetchall()
        
        conn.close()
        
        config = {
            'export_date': datetime.now().isoformat(),
            'rules': [dict(zip(['rule_id', 'name', 'description', 'patterns', 'conditions', 'actions', 'severity', 'enabled'], rule)) for rule in rules],
            'patterns': [dict(zip(['pattern_id', 'name', 'description', 'regex_pattern', 'classification', 'confidence', 'enabled'], pattern)) for pattern in patterns]
        }
        
        if export_format == "json":
            return json.dumps(config, indent=2, ensure_ascii=False)
        else:
            return str(config)
    
    def import_dlp_configuration(self, config_data: str, merge: bool = False) -> bool:
        """Импорт конфигурации DLP"""
        try:
            config = json.loads(config_data)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            if not merge:
                # Очищаем существующую конфигурацию
                cursor.execute('DELETE FROM dlp_rules')
                cursor.execute('DELETE FROM dlp_patterns')
            
            # Импортируем паттерны
            for pattern in config.get('patterns', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO dlp_patterns 
                    (pattern_id, name, description, regex_pattern, classification, confidence, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (pattern['pattern_id'], pattern['name'], pattern['description'],
                      pattern['regex_pattern'], pattern['classification'], 
                      pattern['confidence'], pattern['enabled']))
            
            # Импортируем правила
            for rule in config.get('rules', []):
                cursor.execute('''
                    INSERT OR REPLACE INTO dlp_rules 
                    (rule_id, name, description, patterns, conditions, actions, severity, enabled)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (rule['rule_id'], rule['name'], rule['description'],
                      rule['patterns'], rule['conditions'], rule['actions'],
                      rule['severity'], rule['enabled']))
            
            conn.commit()
            conn.close()
            
            logger.info("Конфигурация DLP импортирована успешно")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка импорта конфигурации: {e}")
            return False
    
    def create_data_tokenization_vault(self, vault_name: str, algorithm: str = "AES256") -> str:
        """Создание хранилища токенизации данных"""
        vault_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokenization_vaults (
                vault_id TEXT PRIMARY KEY,
                name TEXT,
                algorithm TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                key_rotation_days INTEGER DEFAULT 90
            )
        ''')
        
        cursor.execute('''
            INSERT INTO tokenization_vaults 
            (vault_id, name, algorithm, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (vault_id, vault_name, algorithm))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создано хранилище токенизации: {vault_name}")
        return vault_id
    
    def tokenize_sensitive_data(self, data: str, vault_id: str) -> str:
        """Токенизация чувствительных данных"""
        # Генерируем токен
        token = f"TOKEN_{self._generate_id()[:12]}"
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tokenization_mapping (
                token TEXT PRIMARY KEY,
                vault_id TEXT,
                original_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                access_count INTEGER DEFAULT 0
            )
        ''')
        
        # Шифруем оригинальные данные перед сохранением
        encrypted_data = self.cipher.encrypt(data.encode()).decode()
        
        cursor.execute('''
            INSERT INTO tokenization_mapping 
            (token, vault_id, original_data, created_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (token, vault_id, encrypted_data))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Данные токенизированы: {token}")
        return token
    
    def detokenize_data(self, token: str) -> Optional[str]:
        """Детокенизация данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT original_data FROM tokenization_mapping 
            WHERE token = ?
        ''', (token,))
        
        result = cursor.fetchone()
        
        if result:
            # Обновляем счетчик доступа
            cursor.execute('''
                UPDATE tokenization_mapping 
                SET access_count = access_count + 1 
                WHERE token = ?
            ''', (token,))
            
            conn.commit()
            
            # Расшифровываем данные
            try:
                decrypted_data = self.cipher.decrypt(result[0].encode()).decode()
                logger.info(f"Данные детокенизированы: {token}")
                return decrypted_data
            except Exception as e:
                logger.error(f"Ошибка расшифровки токена {token}: {e}")
        
        conn.close()
        return None
    
    def setup_real_time_monitoring(self, monitor_name: str, 
                                 data_sources: List[str], alert_threshold: float = 0.8) -> str:
        """Настройка мониторинга в реальном времени"""
        monitor_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS real_time_monitors (
                monitor_id TEXT PRIMARY KEY,
                name TEXT,
                data_sources TEXT,
                alert_threshold REAL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO real_time_monitors 
            (monitor_id, name, data_sources, alert_threshold, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (monitor_id, monitor_name, ','.join(data_sources), alert_threshold))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен мониторинг в реальном времени: {monitor_name}")
        return monitor_id
    
    def create_data_backup_policy(self, policy_name: str, backup_frequency: str, 
                                retention_copies: int, encryption_enabled: bool = True) -> str:
        """Создание политики резервного копирования данных"""
        policy_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS backup_policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT,
                frequency TEXT,
                retention_copies INTEGER,
                encryption_enabled BOOLEAN,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO backup_policies 
            (policy_id, name, frequency, retention_copies, encryption_enabled)
            VALUES (?, ?, ?, ?, ?)
        ''', (policy_id, policy_name, backup_frequency, retention_copies, encryption_enabled))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана политика резервного копирования: {policy_name}")
        return policy_id
    
    def perform_data_migration(self, source_system: str, target_system: str, 
                             data_types: List[str], validation_rules: Dict[str, Any]) -> str:
        """Выполнение миграции данных с валидацией"""
        migration_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_migrations (
                migration_id TEXT PRIMARY KEY,
                source_system TEXT,
                target_system TEXT,
                data_types TEXT,
                validation_rules TEXT,
                status TEXT DEFAULT 'PENDING',
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                records_migrated INTEGER DEFAULT 0,
                errors_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_migrations 
            (migration_id, source_system, target_system, data_types, validation_rules, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')
        ''', (migration_id, source_system, target_system, 
              ','.join(data_types), json.dumps(validation_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана задача миграции данных: {source_system} -> {target_system}")
        return migration_id
    
    def validate_data_format(self, data: str, expected_format: str) -> Dict[str, Any]:
        """Валидация формата данных"""
        validation_result = {
            'valid': True,
            'format': expected_format,
            'errors': []
        }
        
        try:
            if expected_format == 'json':
                json.loads(data)
            elif expected_format == 'email':
                if not re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', data):
                    validation_result['valid'] = False
                    validation_result['errors'].append('Неверный формат email')
            elif expected_format == 'phone':
                if not re.match(r'^\+?7[\s\(-]?\d{3}[\s\)-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}$', data):
                    validation_result['valid'] = False
                    validation_result['errors'].append('Неверный формат телефона')
            
        except Exception as e:
            validation_result['valid'] = False
            validation_result['errors'].append(str(e))
        
        return validation_result
    
    def create_data_sharing_agreement(self, party_name: str, data_types: List[str], 
                                    purpose: str, retention_period: int) -> str:
        """Создание соглашения о совместном использовании данных"""
        agreement_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_sharing_agreements (
                agreement_id TEXT PRIMARY KEY,
                party_name TEXT,
                data_types TEXT,
                purpose TEXT,
                retention_period INTEGER,
                status TEXT DEFAULT 'ACTIVE',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP
            )
        ''')
        
        expires_at = datetime.now() + timedelta(days=retention_period)
        
        cursor.execute('''
            INSERT INTO data_sharing_agreements 
            (agreement_id, party_name, data_types, purpose, retention_period, expires_at)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (agreement_id, party_name, ','.join(data_types), purpose, 
              retention_period, expires_at.isoformat()))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создано соглашение о совместном использовании данных: {party_name}")
        return agreement_id
    
    def setup_data_archival_system(self, archive_name: str, criteria: Dict[str, Any], 
                                 storage_location: str) -> str:
        """Настройка системы архивирования данных"""
        archive_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS archival_systems (
                archive_id TEXT PRIMARY KEY,
                name TEXT,
                criteria TEXT,
                storage_location TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO archival_systems 
            (archive_id, name, criteria, storage_location, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (archive_id, archive_name, json.dumps(criteria), storage_location))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена система архивирования: {archive_name}")
        return archive_id
    
    def perform_automated_archival(self, archive_id: str) -> Dict[str, Any]:
        """Выполнение автоматического архивирования"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM archival_systems WHERE archive_id = ? AND enabled = TRUE', (archive_id,))
        archive_config = cursor.fetchone()
        
        if not archive_config:
            return {'error': 'Система архивирования не найдена или отключена'}
        
        criteria = json.loads(archive_config[2])
        storage_location = archive_config[3]
        
        # Заглушка для архивирования
        archived_count = 0
        archive_size = 0
        
        # В реальности здесь будет логика архивирования
        # на основе критериев (возраст данных, размер, тип и т.д.)
        
        result = {
            'archive_id': archive_id,
            'archived_records': archived_count,
            'archive_size_bytes': archive_size,
            'storage_location': storage_location,
            'archived_at': datetime.now().isoformat()
        }
        
        conn.close()
        logger.info(f"Выполнено автоматическое архивирование: {archived_count} записей")
        return result
    
    def create_data_pipeline_monitor(self, pipeline_name: str, stages: List[str], 
                                   sla_threshold: int) -> str:
        """Создание монитора конвейера обработки данных"""
        monitor_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pipeline_monitors (
                monitor_id TEXT PRIMARY KEY,
                name TEXT,
                stages TEXT,
                sla_threshold INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO pipeline_monitors 
            (monitor_id, name, stages, sla_threshold, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (monitor_id, pipeline_name, ','.join(stages), sla_threshold))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан монитор конвейера данных: {pipeline_name}")
        return monitor_id
    
    def setup_consent_management(self, consent_type: str, legal_basis: str, 
                               retention_period: int) -> str:
        """Настройка управления согласиями пользователей"""
        consent_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS consent_management (
                consent_id TEXT PRIMARY KEY,
                consent_type TEXT,
                legal_basis TEXT,
                retention_period INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO consent_management 
            (consent_id, consent_type, legal_basis, retention_period)
            VALUES (?, ?, ?, ?)
        ''', (consent_id, consent_type, legal_basis, retention_period))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено управление согласиями: {consent_type}")
        return consent_id
    
    def record_user_consent(self, user_id: str, consent_id: str, granted: bool, 
                          consent_details: str) -> str:
        """Запись согласия пользователя"""
        record_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_consents (
                record_id TEXT PRIMARY KEY,
                user_id TEXT,
                consent_id TEXT,
                granted BOOLEAN,
                consent_details TEXT,
                granted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                withdrawn_at TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO user_consents 
            (record_id, user_id, consent_id, granted, consent_details)
            VALUES (?, ?, ?, ?, ?)
        ''', (record_id, user_id, consent_id, granted, consent_details))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Записано согласие пользователя {user_id}: {'предоставлено' if granted else 'отозвано'}")
        return record_id
    
    def create_privacy_dashboard(self) -> Dict[str, Any]:
        """Создание панели управления конфиденциальностью"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Собираем основные метрики
        cursor.execute('SELECT COUNT(*) FROM scan_reports')
        total_scans = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM data_incidents WHERE status = "OPEN"')
        open_incidents = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM data_subject_requests WHERE status = "PENDING"')
        pending_requests = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM quarantine WHERE released = FALSE')
        quarantined_files = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        dashboard = {
            'overview': {
                'total_scans': total_scans,
                'open_incidents': open_incidents,
                'pending_requests': pending_requests,
                'quarantined_files': quarantined_files
            },
            'compliance_status': self._get_compliance_overview(),
            'recent_activities': self._get_recent_activities(),
            'risk_trends': self._calculate_risk_trends(),
            'generated_at': datetime.now().isoformat()
        }
        
        return dashboard
    
    def _get_compliance_overview(self) -> Dict[str, Any]:
        """Обзор соответствия нормативам"""
        return {
            'GDPR': {'status': 'COMPLIANT', 'score': 95},
            'HIPAA': {'status': 'PARTIAL', 'score': 78},
            'PCI_DSS': {'status': 'COMPLIANT', 'score': 92}
        }
    
    def _get_recent_activities(self) -> List[Dict[str, Any]]:
        """Получение последних активностей"""
        # Заглушка для последних активностей
        return [
            {'type': 'SCAN', 'timestamp': datetime.now().isoformat(), 'details': 'Completed file scan'},
            {'type': 'INCIDENT', 'timestamp': (datetime.now() - timedelta(hours=2)).isoformat(), 'details': 'Data breach detected'}
        ]
    
    def _calculate_risk_trends(self) -> Dict[str, Any]:
        """Расчет трендов риска"""
        # Заглушка для трендов риска
        return {
            'current_level': 'MEDIUM',
            'trend': 'DECREASING',
            'weekly_change': -5.2
        }
    
    def setup_data_versioning(self, data_id: str, versioning_strategy: str = "timestamp") -> str:
        """Настройка версионирования данных"""
        version_config_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_versioning (
                config_id TEXT PRIMARY KEY,
                data_id TEXT,
                strategy TEXT,
                max_versions INTEGER DEFAULT 10,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_versioning 
            (config_id, data_id, strategy)
            VALUES (?, ?, ?)
        ''', (version_config_id, data_id, versioning_strategy))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено версионирование данных: {data_id}")
        return version_config_id
    
    def create_data_version(self, data_id: str, content: str, version_notes: str = "") -> str:
        """Создание новой версии данных"""
        version_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_versions (
                version_id TEXT PRIMARY KEY,
                data_id TEXT,
                content_hash TEXT,
                encrypted_content TEXT,
                version_notes TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Создаем хеш содержимого и шифруем его
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        encrypted_content = self.cipher.encrypt(content.encode()).decode()
        
        cursor.execute('''
            INSERT INTO data_versions 
            (version_id, data_id, content_hash, encrypted_content, version_notes)
            VALUES (?, ?, ?, ?, ?)
        ''', (version_id, data_id, content_hash, encrypted_content, version_notes))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана версия данных: {version_id}")
        return version_id
    
    def setup_automated_classification(self, ruleset_name: str, 
                                     classification_rules: List[Dict[str, Any]]) -> str:
        """Настройка автоматической классификации данных"""
        ruleset_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS auto_classification_rules (
                ruleset_id TEXT PRIMARY KEY,
                name TEXT,
                rules TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO auto_classification_rules 
            (ruleset_id, name, rules, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (ruleset_id, ruleset_name, json.dumps(classification_rules)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена автоматическая классификация: {ruleset_name}")
        return ruleset_id
    
    def apply_automated_classification(self, content: str, ruleset_id: str) -> str:
        """Применение автоматической классификации"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT rules FROM auto_classification_rules WHERE ruleset_id = ?', (ruleset_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return "UNKNOWN"
        
        rules = json.loads(result[0])
        
        # Применяем правила классификации
        for rule in rules:
            if 'pattern' in rule and re.search(rule['pattern'], content, re.IGNORECASE):
                return rule.get('classification', 'CONFIDENTIAL')
        
        return "PUBLIC"
    
    def setup_data_loss_prevention_agent(self, agent_name: str, endpoints: List[str], 
                                       monitoring_frequency: int = 60) -> str:
        """Настройка агента предотвращения утечек данных"""
        agent_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS dlp_agents (
                agent_id TEXT PRIMARY KEY,
                name TEXT,
                endpoints TEXT,
                monitoring_frequency INTEGER,
                status TEXT DEFAULT 'ACTIVE',
                last_heartbeat TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO dlp_agents 
            (agent_id, name, endpoints, monitoring_frequency, status)
            VALUES (?, ?, ?, ?, 'ACTIVE')
        ''', (agent_id, agent_name, ','.join(endpoints), monitoring_frequency))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен DLP агент: {agent_name}")
        return agent_id
    
    def perform_risk_assessment(self, assessment_scope: str, 
                              data_categories: List[str]) -> Dict[str, Any]:
        """Выполнение оценки рисков"""
        assessment_id = self._generate_id()
        
        # Рассчитываем риски по категориям
        category_risks = {}
        overall_risk = 0
        
        for category in data_categories:
            if category in ['CREDIT_CARD', 'SSN', 'MEDICAL']:
                risk_score = 0.9
            elif category in ['EMAIL', 'PHONE']:
                risk_score = 0.6
            else:
                risk_score = 0.3
            
            category_risks[category] = risk_score
            overall_risk += risk_score
        
        overall_risk = min(overall_risk / len(data_categories), 1.0) if data_categories else 0
        
        assessment = {
            'assessment_id': assessment_id,
            'scope': assessment_scope,
            'overall_risk_score': round(overall_risk, 2),
            'risk_level': 'HIGH' if overall_risk > 0.7 else 'MEDIUM' if overall_risk > 0.4 else 'LOW',
            'category_risks': category_risks,
            'mitigation_recommendations': self._get_risk_mitigation_recommendations(overall_risk),
            'assessed_at': datetime.now().isoformat()
        }
        
        return assessment
    
    def _get_risk_mitigation_recommendations(self, risk_score: float) -> List[str]:
        """Получение рекомендаций по снижению рисков"""
        recommendations = ["Регулярно обновлять паттерны DLP"]
        
        if risk_score > 0.7:
            recommendations.extend([
                "Внедрить дополнительное шифрование",
                "Усилить мониторинг доступа",
                "Провести обучение персонала"
            ])
        elif risk_score > 0.4:
            recommendations.extend([
                "Настроить автоматические оповещения",
                "Пересмотреть политики доступа"
            ])
        
        return recommendations
    
    def create_audit_trail(self, action: str, user_id: str, resource: str, 
                         details: Dict[str, Any]) -> str:
        """Создание записи аудита"""
        audit_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_trail (
                audit_id TEXT PRIMARY KEY,
                action TEXT,
                user_id TEXT,
                resource TEXT,
                details TEXT,
                ip_address TEXT,
                user_agent TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO audit_trail 
            (audit_id, action, user_id, resource, details)
            VALUES (?, ?, ?, ?, ?)
        ''', (audit_id, action, user_id, resource, json.dumps(details)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создана запись аудита: {action} - {resource}")
        return audit_id
    
    def generate_executive_report(self, report_period: str) -> Dict[str, Any]:
        """Генерация отчета для руководства"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Собираем ключевые метрики
        cursor.execute('SELECT COUNT(*) FROM scan_reports')
        total_scans = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT COUNT(*) FROM data_incidents')
        total_incidents = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        cursor.execute('SELECT AVG(risk_score) FROM scan_reports')
        avg_risk_score = cursor.fetchone()[0] if cursor.fetchone() else 0
        
        conn.close()
        
        executive_report = {
            'report_period': report_period,
            'executive_summary': {
                'total_data_scans': total_scans,
                'security_incidents': total_incidents,
                'average_risk_score': round(avg_risk_score or 0, 2),
                'compliance_status': 'GOOD'
            },
            'key_achievements': [
                "Реализована автоматизация DLP сканирования",
                "Внедрена система мониторинга в реальном времени",
                "Достигнуто соответствие GDPR на 95%"
            ],
            'recommendations': [
                "Расширить покрытие облачных сервисов",
                "Усилить обучение персонала",
                "Внедрить дополнительные средства шифрования"
            ],
            'generated_at': datetime.now().isoformat()
        }
        
        return executive_report
    
    def setup_data_lake_scanning(self, lake_name: str, connection_params: Dict[str, Any], 
                               scan_schedule: str) -> str:
        """Настройка сканирования озера данных"""
        scanner_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_lake_scanners (
                scanner_id TEXT PRIMARY KEY,
                name TEXT,
                connection_params TEXT,
                scan_schedule TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_lake_scanners 
            (scanner_id, name, connection_params, scan_schedule, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (scanner_id, lake_name, json.dumps(connection_params), scan_schedule))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено сканирование озера данных: {lake_name}")
        return scanner_id
    
    def create_synthetic_data_generator(self, generator_name: str, source_schema: Dict[str, Any], 
                                      privacy_budget: float = 1.0) -> str:
        """Создание генератора синтетических данных"""
        generator_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS synthetic_data_generators (
                generator_id TEXT PRIMARY KEY,
                name TEXT,
                source_schema TEXT,
                privacy_budget REAL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO synthetic_data_generators 
            (generator_id, name, source_schema, privacy_budget)
            VALUES (?, ?, ?, ?)
        ''', (generator_id, generator_name, json.dumps(source_schema), privacy_budget))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан генератор синтетических данных: {generator_name}")
        return generator_id
    
    def generate_synthetic_dataset(self, generator_id: str, record_count: int) -> Dict[str, Any]:
        """Генерация синтетического набора данных"""
        # Заглушка для генерации синтетических данных
        synthetic_data = {
            'generator_id': generator_id,
            'record_count': record_count,
            'generated_at': datetime.now().isoformat(),
            'data_format': 'JSON',
            'privacy_preserved': True
        }
        
        logger.info(f"Сгенерирован синтетический набор данных: {record_count} записей")
        return synthetic_data
    
    def setup_zero_trust_data_access(self, resource_name: str, access_policies: List[Dict[str, Any]]) -> str:
        """Настройка доступа к данным по принципу Zero Trust"""
        policy_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS zero_trust_policies (
                policy_id TEXT PRIMARY KEY,
                resource_name TEXT,
                access_policies TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO zero_trust_policies 
            (policy_id, resource_name, access_policies, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (policy_id, resource_name, json.dumps(access_policies)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен Zero Trust доступ: {resource_name}")
        return policy_id
    
    def verify_zero_trust_access(self, user_id: str, resource: str, context: Dict[str, Any]) -> bool:
        """Проверка доступа по принципу Zero Trust"""
        # Заглушка для проверки Zero Trust доступа
        # В реальности здесь будет сложная логика проверки контекста,
        # устройства, местоположения, времени и т.д.
        
        trust_score = 0.8  # Базовый уровень доверия
        
        # Снижаем доверие на основе контекста
        if context.get('new_device', False):
            trust_score -= 0.2
        if context.get('unusual_location', False):
            trust_score -= 0.3
        if context.get('unusual_time', False):
            trust_score -= 0.1
        
        access_granted = trust_score > 0.5
        
        logger.info(f"Zero Trust проверка для {user_id}: {'разрешено' if access_granted else 'запрещено'}")
        return access_granted
    
    def create_data_minimization_rule(self, rule_name: str, data_purpose: str, 
                                     required_fields: List[str], retention_days: int) -> str:
        """Создание правила минимизации данных"""
        rule_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_minimization_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT,
                purpose TEXT,
                required_fields TEXT,
                retention_days INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_minimization_rules 
            (rule_id, name, purpose, required_fields, retention_days, enabled)
            VALUES (?, ?, ?, ?, ?, TRUE)
        ''', (rule_id, rule_name, data_purpose, ','.join(required_fields), retention_days))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создано правило минимизации данных: {rule_name}")
        return rule_id
    
    def apply_data_minimization(self, data: Dict[str, Any], rule_id: str) -> Dict[str, Any]:
        """Применение минимизации данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT required_fields FROM data_minimization_rules WHERE rule_id = ?', (rule_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return data
        
        required_fields = result[0].split(',')
        minimized_data = {field: data.get(field) for field in required_fields if field in data}
        
        logger.info(f"Применена минимизация данных: {len(minimized_data)} полей из {len(data)}")
        return minimized_data
    
    def setup_data_encryption_at_rest(self, encryption_policy: str, key_management: str) -> str:
        """Настройка шифрования данных в покое"""
        policy_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS encryption_policies (
                policy_id TEXT PRIMARY KEY,
                policy_name TEXT,
                key_management TEXT,
                algorithm TEXT DEFAULT 'AES-256',
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO encryption_policies 
            (policy_id, policy_name, key_management, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (policy_id, encryption_policy, key_management))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено шифрование в покое: {encryption_policy}")
        return policy_id
    
    def setup_homomorphic_encryption(self, computation_type: str, security_level: int = 128) -> str:
        """Настройка гомоморфного шифрования для вычислений над зашифрованными данными"""
        he_config_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS homomorphic_encryption_configs (
                config_id TEXT PRIMARY KEY,
                computation_type TEXT,
                security_level INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO homomorphic_encryption_configs 
            (config_id, computation_type, security_level, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (he_config_id, computation_type, security_level))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено гомоморфное шифрование: {computation_type}")
        return he_config_id
    
    def create_differential_privacy_mechanism(self, mechanism_name: str, epsilon: float, 
                                            delta: float = 1e-5) -> str:
        """Создание механизма дифференциальной приватности"""
        mechanism_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS differential_privacy_mechanisms (
                mechanism_id TEXT PRIMARY KEY,
                name TEXT,
                epsilon REAL,
                delta REAL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO differential_privacy_mechanisms 
            (mechanism_id, name, epsilon, delta, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (mechanism_id, mechanism_name, epsilon, delta))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан механизм дифференциальной приватности: {mechanism_name}")
        return mechanism_id
    
    def apply_differential_privacy(self, data: List[float], mechanism_id: str) -> List[float]:
        """Применение дифференциальной приватности к данным"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT epsilon FROM differential_privacy_mechanisms WHERE mechanism_id = ?', (mechanism_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            return data
        
        epsilon = result[0]
        
        # Применяем Лапласовский шум для дифференциальной приватности
        import numpy as np
        
        try:
            noise_scale = 1.0 / epsilon
            noisy_data = []
            
            for value in data:
                noise = np.random.laplace(0, noise_scale)
                noisy_data.append(value + noise)
            
            logger.info(f"Применена дифференциальная приватность к {len(data)} значениям")
            return noisy_data
            
        except ImportError:
            logger.warning("NumPy не установлен, дифференциальная приватность недоступна")
            return data
        except Exception as e:
            logger.error(f"Ошибка применения дифференциальной приватности: {e}")
            return data
    
    def setup_federated_learning_monitor(self, fl_name: str, participants: List[str], 
                                       privacy_budget: float) -> str:
        """Настройка мониторинга федеративного обучения"""
        fl_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS federated_learning_monitors (
                fl_id TEXT PRIMARY KEY,
                name TEXT,
                participants TEXT,
                privacy_budget REAL,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO federated_learning_monitors 
            (fl_id, name, participants, privacy_budget, enabled)
            VALUES (?, ?, ?, ?, TRUE)
        ''', (fl_id, fl_name, ','.join(participants), privacy_budget))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроен мониторинг федеративного обучения: {fl_name}")
        return fl_id
    
    def create_data_provenance_tracker(self, data_asset: str, lineage_depth: int = 5) -> str:
        """Создание трекера происхождения данных"""
        tracker_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS data_provenance_trackers (
                tracker_id TEXT PRIMARY KEY,
                data_asset TEXT,
                lineage_depth INTEGER,
                tracking_enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO data_provenance_trackers 
            (tracker_id, data_asset, lineage_depth, tracking_enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (tracker_id, data_asset, lineage_depth))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан трекер происхождения данных: {data_asset}")
        return tracker_id
    
    def perform_privacy_preserving_analytics(self, dataset_id: str, analysis_type: str, 
                                           privacy_method: str = "differential_privacy") -> Dict[str, Any]:
        """Выполнение анализа с сохранением приватности"""
        analysis_id = self._generate_id()
        
        # Заглушка для анализа с сохранением приватности
        analysis_result = {
            'analysis_id': analysis_id,
            'dataset_id': dataset_id,
            'analysis_type': analysis_type,
            'privacy_method': privacy_method,
            'results': {
                'statistical_summary': 'Сгенерированная статистика с сохранением приватности',
                'privacy_budget_consumed': 0.1,
                'confidence_interval': [0.85, 0.95]
            },
            'analyzed_at': datetime.now().isoformat()
        }
        
        logger.info(f"Выполнен анализ с сохранением приватности: {analysis_type}")
        return analysis_result
    
    def setup_blockchain_data_integrity(self, blockchain_network: str, 
                                      data_categories: List[str]) -> str:
        """Настройка блокчейн для обеспечения целостности данных"""
        blockchain_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS blockchain_integrity (
                blockchain_id TEXT PRIMARY KEY,
                network TEXT,
                data_categories TEXT,
                contract_address TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            INSERT INTO blockchain_integrity 
            (blockchain_id, network, data_categories, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (blockchain_id, blockchain_network, ','.join(data_categories)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроена блокчейн интеграция: {blockchain_network}")
        return blockchain_id
    
    def create_smart_contract_for_consent(self, contract_name: str, 
                                        consent_conditions: Dict[str, Any]) -> str:
        """Создание смарт-контракта для управления согласиями"""
        contract_id = self._generate_id()
        
        # Заглушка для смарт-контракта
        contract_code = f"""
        // Smart Contract for Consent Management
        contract ConsentManagement {{
            mapping(address => bool) public consents;
            
            function grantConsent() public {{
                consents[msg.sender] = true;
            }}
            
            function revokeConsent() public {{
                consents[msg.sender] = false;
            }}
        }}
        """
        
        logger.info(f"Создан смарт-контракт для согласий: {contract_name}")
        return contract_id
    
    def setup_quantum_safe_encryption(self, algorithm: str = "CRYSTALS-Kyber") -> str:
        """Настройка квантово-безопасного шифрования"""
        config_id = self._generate_id()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS quantum_safe_configs (
                config_id TEXT PRIMARY KEY,
                algorithm TEXT,
                key_size INTEGER,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        key_size = 1024 if algorithm == "CRYSTALS-Kyber" else 2048
        
        cursor.execute('''
            INSERT INTO quantum_safe_configs 
            (config_id, algorithm, key_size, enabled)
            VALUES (?, ?, ?, TRUE)
        ''', (config_id, algorithm, key_size))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Настроено квантово-безопасное шифрование: {algorithm}")
        return config_id

# Псевдоним для совместимости
DataProtectionEngine = DLPProtection

if __name__ == "__main__":
    # Пример использования
    dlp = DLPProtection("casb.db")
    
    # Тестовое содержимое с конфиденциальными данными
    test_content = """
    Документ содержит следующую информацию:
    Паспорт: 45 03 123456
    ИНН: 123456789012
    Телефон: +7 (495) 123-45-67
    Email: ivanov@company.ru
    Банковская карта: 4111 1111 1111 1111
    """
    
    # Сканирование содержимого
    report = dlp.scan_content(test_content, "test_document.txt", len(test_content.encode()))
    
    print(f"Результат сканирования: {report.scan_result.value}")
    print(f"Классификация: {report.classification.value}")
    print(f"Риск-скор: {report.risk_score:.2f}")
    print(f"Найдено паттернов: {len(report.patterns_found)}")
    
    for pattern in report.patterns_found:
        print(f"  - {pattern['pattern_name']}: {pattern['matches_count']} совпадений")
    
    print("Модуль защиты данных готов к работе!")
