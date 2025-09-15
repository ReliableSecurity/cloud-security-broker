"""
Модуль мониторинга облачных активностей для CASB
Отслеживает и анализирует активность в облачных сервисах

Автор: AI Assistant
"""

import asyncio
import aiohttp
import json
import logging
import time
import threading
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import hashlib
from collections import defaultdict, deque
import re

logger = logging.getLogger(__name__)

class EventType(Enum):
    """Типы событий в облаке"""
    LOGIN = "login"
    LOGOUT = "logout"
    FILE_ACCESS = "file_access"
    FILE_UPLOAD = "file_upload"
    FILE_DOWNLOAD = "file_download"
    FILE_DELETE = "file_delete"
    PERMISSION_CHANGE = "permission_change"
    CONFIG_CHANGE = "config_change"
    API_CALL = "api_call"
    RESOURCE_CREATE = "resource_create"
    RESOURCE_DELETE = "resource_delete"
    UNKNOWN = "unknown"

class Severity(Enum):
    """Уровни серьезности событий"""
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

@dataclass
class CloudEvent:
    """Событие в облачном сервисе"""
    event_id: str
    service_id: str
    user_id: str
    event_type: EventType
    timestamp: datetime
    source_ip: str
    user_agent: str
    resource: str
    action: str
    result: str
    severity: Severity
    raw_data: Dict[str, Any]
    processed: bool = False
    
@dataclass
class AlertRule:
    """Правило для генерации оповещений"""
    rule_id: str
    name: str
    description: str
    conditions: Dict[str, Any]
    severity: Severity
    enabled: bool = True
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()

@dataclass
class SecurityAlert:
    """Оповещение о безопасности"""
    alert_id: str
    rule_id: str
    event_ids: List[str]
    title: str
    description: str
    severity: Severity
    timestamp: datetime
    acknowledged: bool = False
    resolved: bool = False

class CloudActivityMonitor:
    """Класс для мониторинга облачных активностей"""
    
    def __init__(self, db_path: str, config: Dict = None):
        self.db_path = db_path
        self.config = config or {}
        self.alert_rules = {}
        self.event_processors = {}
        self.active_alerts = {}
        self.event_buffer = deque(maxlen=10000)  # Буфер для быстрого доступа
        
        # Настройки мониторинга
        self.monitoring_interval = self.config.get('monitoring_interval', 60)  # секунды
        self.batch_size = self.config.get('batch_size', 100)
        self.retention_days = self.config.get('retention_days', 90)
        
        # Счетчики для аномального поведения
        self.user_activity_counters = defaultdict(lambda: defaultdict(int))
        self.ip_activity_counters = defaultdict(lambda: defaultdict(int))
        
        self._init_monitoring_tables()
        self._load_default_alert_rules()
        
        # Запуск фонового мониторинга
        self.monitoring_thread = threading.Thread(target=self._start_background_monitoring, daemon=True)
        self.monitoring_active = True
        self.monitoring_thread.start()
        
        logger.info("Модуль мониторинга облачных активностей инициализирован")
    
    def _init_monitoring_tables(self):
        """Инициализация таблиц для мониторинга"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица событий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_events (
                event_id TEXT PRIMARY KEY,
                service_id TEXT,
                user_id TEXT,
                event_type TEXT,
                timestamp TIMESTAMP,
                source_ip TEXT,
                user_agent TEXT,
                resource TEXT,
                action TEXT,
                result TEXT,
                severity TEXT,
                raw_data TEXT,
                processed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица правил оповещений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS alert_rules (
                rule_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                conditions TEXT,
                severity TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица оповещений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS security_alerts (
                alert_id TEXT PRIMARY KEY,
                rule_id TEXT,
                event_ids TEXT,
                title TEXT,
                description TEXT,
                severity TEXT,
                timestamp TIMESTAMP,
                acknowledged BOOLEAN DEFAULT FALSE,
                resolved BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Таблица метрик производительности
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                metric_id INTEGER PRIMARY KEY AUTOINCREMENT,
                service_id TEXT,
                metric_name TEXT,
                metric_value REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_default_alert_rules(self):
        """Загрузка правил оповещений по умолчанию"""
        default_rules = [
            {
                'name': 'Подозрительная активность входа',
                'description': 'Множественные неудачные попытки входа',
                'conditions': {
                    'event_type': 'login',
                    'result': 'failed',
                    'count_threshold': 5,
                    'time_window_minutes': 10
                },
                'severity': Severity.WARNING
            },
            {
                'name': 'Доступ из нового местоположения',
                'description': 'Вход с нового IP адреса',
                'conditions': {
                    'event_type': 'login',
                    'new_ip': True,
                    'geo_distance_km': 1000
                },
                'severity': Severity.INFO
            },
            {
                'name': 'Массовое удаление файлов',
                'description': 'Удаление большого количества файлов',
                'conditions': {
                    'event_type': 'file_delete',
                    'count_threshold': 10,
                    'time_window_minutes': 5
                },
                'severity': Severity.CRITICAL
            },
            {
                'name': 'Изменение критичных настроек',
                'description': 'Изменение конфигурации безопасности',
                'conditions': {
                    'event_type': 'config_change',
                    'resource_pattern': '.*security.*|.*permission.*|.*policy.*'
                },
                'severity': Severity.ERROR
            },
            {
                'name': 'Необычная активность API',
                'description': 'Превышение обычного количества API вызовов',
                'conditions': {
                    'event_type': 'api_call',
                    'count_threshold': 1000,
                    'time_window_minutes': 60
                },
                'severity': Severity.WARNING
            }
        ]
        
        for rule_data in default_rules:
            self.create_alert_rule(
                name=rule_data['name'],
                description=rule_data['description'],
                conditions=rule_data['conditions'],
                severity=rule_data['severity']
            )
    
    def create_alert_rule(self, name: str, description: str, 
                         conditions: Dict[str, Any], severity: Severity) -> AlertRule:
        """Создание правила оповещения"""
        rule_id = hashlib.sha256(f"{name}_{time.time()}".encode()).hexdigest()[:16]
        
        rule = AlertRule(
            rule_id=rule_id,
            name=name,
            description=description,
            conditions=conditions,
            severity=severity
        )
        
        # Сохраняем в базу данных
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO alert_rules (rule_id, name, description, conditions, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (rule_id, name, description, json.dumps(conditions, ensure_ascii=False), severity.value))
        
        conn.commit()
        conn.close()
        
        self.alert_rules[rule_id] = rule
        logger.info(f"Создано правило оповещения: {name}")
        
        return rule
    
    def log_cloud_event(self, service_id: str, user_id: str, event_type: EventType,
                       source_ip: str, user_agent: str, resource: str, action: str,
                       result: str, raw_data: Dict[str, Any] = None) -> CloudEvent:
        """Логирование события в облаке"""
        event_id = hashlib.sha256(f"{service_id}_{user_id}_{time.time()}".encode()).hexdigest()[:16]
        
        # Определяем серьезность события
        severity = self._determine_event_severity(event_type, result, action)
        
        event = CloudEvent(
            event_id=event_id,
            service_id=service_id,
            user_id=user_id,
            event_type=event_type,
            timestamp=datetime.now(),
            source_ip=source_ip,
            user_agent=user_agent,
            resource=resource,
            action=action,
            result=result,
            severity=severity,
            raw_data=raw_data or {}
        )
        
        # Сохраняем в базу данных
        self._save_cloud_event(event)
        
        # Добавляем в буфер для быстрого анализа
        self.event_buffer.append(event)
        
        # Обновляем счетчики активности
        self._update_activity_counters(event)
        
        # Проверяем правила оповещений
        self._check_alert_rules(event)
        
        logger.debug(f"Зарегистрировано событие: {event_type.value} от {user_id}")
        return event
    
    def _determine_event_severity(self, event_type: EventType, result: str, action: str) -> Severity:
        """Определение серьезности события"""
        # Критичные события
        if event_type in [EventType.FILE_DELETE, EventType.RESOURCE_DELETE, EventType.CONFIG_CHANGE]:
            return Severity.ERROR
        
        # Неудачные попытки
        if result.lower() in ['failed', 'error', 'denied']:
            return Severity.WARNING
        
        # Административные действия
        if 'admin' in action.lower() or 'permission' in action.lower():
            return Severity.WARNING
        
        return Severity.INFO
    
    def _save_cloud_event(self, event: CloudEvent):
        """Сохранение события в базу данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO cloud_events 
            (event_id, service_id, user_id, event_type, timestamp, source_ip, 
             user_agent, resource, action, result, severity, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (event.event_id, event.service_id, event.user_id, event.event_type.value,
              event.timestamp, event.source_ip, event.user_agent, event.resource,
              event.action, event.result, event.severity.value, 
              json.dumps(event.raw_data, ensure_ascii=False)))
        
        conn.commit()
        conn.close()
    
    def _update_activity_counters(self, event: CloudEvent):
        """Обновление счетчиков активности"""
        current_minute = event.timestamp.replace(second=0, microsecond=0)
        
        # Счетчики по пользователям
        self.user_activity_counters[event.user_id][current_minute] += 1
        
        # Счетчики по IP адресам
        self.ip_activity_counters[event.source_ip][current_minute] += 1
        
        # Очистка старых данных (старше 24 часов)
        cutoff_time = datetime.now() - timedelta(hours=24)
        
        for user_id in list(self.user_activity_counters.keys()):
            self.user_activity_counters[user_id] = {
                k: v for k, v in self.user_activity_counters[user_id].items()
                if k > cutoff_time
            }
            if not self.user_activity_counters[user_id]:
                del self.user_activity_counters[user_id]
        
        for ip in list(self.ip_activity_counters.keys()):
            self.ip_activity_counters[ip] = {
                k: v for k, v in self.ip_activity_counters[ip].items()
                if k > cutoff_time
            }
            if not self.ip_activity_counters[ip]:
                del self.ip_activity_counters[ip]
    
    def _check_alert_rules(self, event: CloudEvent):
        """Проверка правил оповещений для события"""
        for rule in self.alert_rules.values():
            if not rule.enabled:
                continue
            
            if self._evaluate_alert_rule(event, rule):
                self._trigger_alert(rule, [event])
    
    def _evaluate_alert_rule(self, event: CloudEvent, rule: AlertRule) -> bool:
        """Оценка правила оповещения"""
        conditions = rule.conditions
        
        # Проверка типа события
        if 'event_type' in conditions:
            if event.event_type.value != conditions['event_type']:
                return False
        
        # Проверка результата
        if 'result' in conditions:
            if event.result.lower() != conditions['result'].lower():
                return False
        
        # Проверка паттерна ресурса
        if 'resource_pattern' in conditions:
            pattern = conditions['resource_pattern']
            if not re.search(pattern, event.resource, re.IGNORECASE):
                return False
        
        # Проверка порогов количества
        if 'count_threshold' in conditions and 'time_window_minutes' in conditions:
            threshold = conditions['count_threshold']
            window_minutes = conditions['time_window_minutes']
            
            # Подсчитываем события за временное окно
            cutoff_time = datetime.now() - timedelta(minutes=window_minutes)
            recent_events = self._get_recent_events(
                user_id=event.user_id,
                event_type=event.event_type,
                since=cutoff_time
            )
            
            if len(recent_events) < threshold:
                return False
        
        # Проверка нового IP адреса
        if conditions.get('new_ip', False):
            if self._is_known_ip_for_user(event.user_id, event.source_ip):
                return False
        
        return True
    
    def _trigger_alert(self, rule: AlertRule, events: List[CloudEvent]):
        """Генерация оповещения"""
        alert_id = hashlib.sha256(f"{rule.rule_id}_{time.time()}".encode()).hexdigest()[:16]
        
        alert = SecurityAlert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            event_ids=[e.event_id for e in events],
            title=f"Оповещение: {rule.name}",
            description=rule.description,
            severity=rule.severity,
            timestamp=datetime.now()
        )
        
        # Сохраняем оповещение
        self._save_alert(alert)
        
        # Добавляем в активные оповещения
        self.active_alerts[alert_id] = alert
        
        logger.warning(f"Создано оповещение: {rule.name} (ID: {alert_id})")
        
        # Отправка уведомлений
        self._send_alert_notification(alert)
    
    def _save_alert(self, alert: SecurityAlert):
        """Сохранение оповещения в базу данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO security_alerts 
            (alert_id, rule_id, event_ids, title, description, severity, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (alert.alert_id, alert.rule_id, json.dumps(alert.event_ids),
              alert.title, alert.description, alert.severity.value, alert.timestamp))
        
        conn.commit()
        conn.close()
    
    def _send_alert_notification(self, alert: SecurityAlert):
        """Отправка уведомления об оповещении"""
        # Здесь можно добавить интеграцию с различными системами уведомлений
        # Telegram, Email, Slack, webhook и т.д.
        
        notification_data = {
            'alert_id': alert.alert_id,
            'title': alert.title,
            'description': alert.description,
            'severity': alert.severity.value,
            'timestamp': alert.timestamp.isoformat()
        }
        
        # Пример отправки webhook
        webhook_url = self.config.get('webhook_url')
        if webhook_url:
            try:
                import requests
                response = requests.post(webhook_url, json=notification_data, timeout=10)
                logger.info(f"Уведомление отправлено на webhook: {response.status_code}")
            except ImportError:
                logger.warning("Модуль requests не найден, webhook не отправлен")
            except Exception as e:
                logger.error(f"Ошибка отправки webhook: {e}")
    
    def _get_recent_events(self, user_id: str = None, event_type: EventType = None,
                          since: datetime = None, service_id: str = None) -> List[CloudEvent]:
        """Получение недавних событий"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = "SELECT * FROM cloud_events WHERE 1=1"
        params = []
        
        if user_id:
            query += " AND user_id = ?"
            params.append(user_id)
        
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type.value)
        
        if since:
            query += " AND timestamp > ?"
            params.append(since)
        
        if service_id:
            query += " AND service_id = ?"
            params.append(service_id)
        
        query += " ORDER BY timestamp DESC"
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        events = []
        for result in results:
            event = CloudEvent(
                event_id=result[0],
                service_id=result[1],
                user_id=result[2],
                event_type=EventType(result[3]),
                timestamp=datetime.fromisoformat(result[4]),
                source_ip=result[5],
                user_agent=result[6],
                resource=result[7],
                action=result[8],
                result=result[9],
                severity=Severity(result[10]),
                raw_data=json.loads(result[11]) if result[11] else {},
                processed=bool(result[12])
            )
            events.append(event)
        
        return events
    
    def _is_known_ip_for_user(self, user_id: str, ip_address: str) -> bool:
        """Проверка, является ли IP адрес известным для пользователя"""
        # Проверяем последние 30 дней
        since = datetime.now() - timedelta(days=30)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) FROM cloud_events 
            WHERE user_id = ? AND source_ip = ? AND timestamp > ?
        ''', (user_id, ip_address, since))
        
        count = cursor.fetchone()[0]
        conn.close()
        
        return count > 0
    
    def _start_background_monitoring(self):
        """Запуск фонового мониторинга"""
        logger.info("Запуск фонового мониторинга")
        
        while self.monitoring_active:
            try:
                # Анализ аномалий
                self._analyze_anomalies()
                
                # Очистка старых данных
                self._cleanup_old_data()
                
                # Обновление метрик
                self._update_performance_metrics()
                
                time.sleep(self.monitoring_interval)
                
            except Exception as e:
                logger.error(f"Ошибка в фоновом мониторинге: {e}")
                time.sleep(60)  # Пауза при ошибке
    
    def _analyze_anomalies(self):
        """Анализ аномалий в поведении"""
        current_time = datetime.now()
        
        # Анализ пользовательской активности
        for user_id, activity in self.user_activity_counters.items():
            recent_activity = sum(
                count for timestamp, count in activity.items()
                if current_time - timestamp < timedelta(hours=1)
            )
            
            # Определяем базовую активность пользователя
            baseline = self._get_user_baseline_activity(user_id)
            
            # Если активность превышает базовую в 3 раза
            if recent_activity > baseline * 3 and baseline > 0:
                self._create_anomaly_alert(
                    f"Аномальная активность пользователя {user_id}",
                    f"Активность: {recent_activity}, базовая: {baseline}",
                    Severity.WARNING
                )
        
        # Анализ активности по IP
        for ip, activity in self.ip_activity_counters.items():
            recent_activity = sum(
                count for timestamp, count in activity.items()
                if current_time - timestamp < timedelta(hours=1)
            )
            
            # Подозрительная активность с одного IP
            if recent_activity > 500:  # Более 500 запросов в час
                self._create_anomaly_alert(
                    f"Подозрительная активность с IP {ip}",
                    f"Количество запросов: {recent_activity}",
                    Severity.ERROR
                )
    
    def _get_user_baseline_activity(self, user_id: str) -> float:
        """Получение базовой активности пользователя"""
        # Анализируем активность за последние 30 дней (исключая последние 24 часа)
        end_time = datetime.now() - timedelta(hours=24)
        start_time = end_time - timedelta(days=30)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT COUNT(*) as daily_count, DATE(timestamp) as date
            FROM cloud_events 
            WHERE user_id = ? AND timestamp BETWEEN ? AND ?
            GROUP BY DATE(timestamp)
        ''', (user_id, start_time, end_time))
        
        results = cursor.fetchall()
        conn.close()
        
        if not results:
            return 10.0  # Значение по умолчанию
        
        # Вычисляем среднее количество событий в день
        total_events = sum(row[0] for row in results)
        days_count = len(results)
        
        return total_events / days_count if days_count > 0 else 10.0
    
    def _create_anomaly_alert(self, title: str, description: str, severity: Severity):
        """Создание оповещения об аномалии"""
        alert_id = hashlib.sha256(f"anomaly_{title}_{time.time()}".encode()).hexdigest()[:16]
        
        alert = SecurityAlert(
            alert_id=alert_id,
            rule_id="anomaly_detection",
            event_ids=[],
            title=title,
            description=description,
            severity=severity,
            timestamp=datetime.now()
        )
        
        self._save_alert(alert)
        self.active_alerts[alert_id] = alert
        
        logger.warning(f"Обнаружена аномалия: {title}")
    
    def _cleanup_old_data(self):
        """Очистка старых данных"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Удаляем старые события
        cursor.execute('DELETE FROM cloud_events WHERE timestamp < ?', (cutoff_date,))
        events_deleted = cursor.rowcount
        
        # Удаляем старые метрики
        cursor.execute('DELETE FROM performance_metrics WHERE timestamp < ?', (cutoff_date,))
        metrics_deleted = cursor.rowcount
        
        conn.commit()
        conn.close()
        
        if events_deleted > 0 or metrics_deleted > 0:
            logger.info(f"Очищены старые данные: {events_deleted} событий, {metrics_deleted} метрик")
    
    def _update_performance_metrics(self):
        """Обновление метрик производительности"""
        # Метрики за последний час
        last_hour = datetime.now() - timedelta(hours=1)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Количество событий по сервисам
        cursor.execute('''
            SELECT service_id, COUNT(*) as event_count
            FROM cloud_events 
            WHERE timestamp > ?
            GROUP BY service_id
        ''', (last_hour,))
        
        service_metrics = cursor.fetchall()
        
        # Сохраняем метрики
        for service_id, count in service_metrics:
            cursor.execute('''
                INSERT INTO performance_metrics (service_id, metric_name, metric_value)
                VALUES (?, ?, ?)
            ''', (service_id, 'events_per_hour', count))
        
        # Средний риск-скор
        cursor.execute('''
            SELECT AVG(
                CASE 
                    WHEN severity = 'critical' THEN 1.0
                    WHEN severity = 'error' THEN 0.8
                    WHEN severity = 'warning' THEN 0.6
                    WHEN severity = 'info' THEN 0.2
                    ELSE 0.0
                END
            ) as avg_risk
            FROM cloud_events 
            WHERE timestamp > ?
        ''', (last_hour,))
        
        avg_risk = cursor.fetchone()[0] or 0.0
        
        cursor.execute('''
            INSERT INTO performance_metrics (service_id, metric_name, metric_value)
            VALUES (?, ?, ?)
        ''', ('system', 'average_risk_score', avg_risk))
        
        conn.commit()
        conn.close()
    
    def get_activity_dashboard(self, hours: int = 24) -> Dict[str, Any]:
        """Получение данных для дашборда активности"""
        since = datetime.now() - timedelta(hours=hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общая статистика
        cursor.execute('''
            SELECT COUNT(*) FROM cloud_events WHERE timestamp > ?
        ''', (since,))
        total_events = cursor.fetchone()[0]
        
        # События по типам
        cursor.execute('''
            SELECT event_type, COUNT(*) as count
            FROM cloud_events 
            WHERE timestamp > ?
            GROUP BY event_type
            ORDER BY count DESC
        ''', (since,))
        events_by_type = cursor.fetchall()
        
        # События по серьезности
        cursor.execute('''
            SELECT severity, COUNT(*) as count
            FROM cloud_events 
            WHERE timestamp > ?
            GROUP BY severity
        ''', (since,))
        events_by_severity = cursor.fetchall()
        
        # Топ активных пользователей
        cursor.execute('''
            SELECT user_id, COUNT(*) as activity_count
            FROM cloud_events 
            WHERE timestamp > ?
            GROUP BY user_id
            ORDER BY activity_count DESC
            LIMIT 10
        ''', (since,))
        top_users = cursor.fetchall()
        
        # Топ сервисов по активности
        cursor.execute('''
            SELECT service_id, COUNT(*) as event_count
            FROM cloud_events 
            WHERE timestamp > ?
            GROUP BY service_id
            ORDER BY event_count DESC
            LIMIT 10
        ''', (since,))
        top_services = cursor.fetchall()
        
        # Активные оповещения
        cursor.execute('''
            SELECT COUNT(*) FROM security_alerts 
            WHERE timestamp > ? AND resolved = FALSE
        ''', (since,))
        active_alerts_count = cursor.fetchone()[0]
        
        conn.close()
        
        return {
            'period_hours': hours,
            'summary': {
                'total_events': total_events,
                'active_alerts': active_alerts_count,
                'events_per_hour': round(total_events / hours, 2)
            },
            'events_by_type': [
                {'type': event_type, 'count': count}
                for event_type, count in events_by_type
            ],
            'events_by_severity': [
                {'severity': severity, 'count': count}
                for severity, count in events_by_severity
            ],
            'top_users': [
                {'user_id': user_id, 'activity': count}
                for user_id, count in top_users
            ],
            'top_services': [
                {'service_id': service_id, 'events': count}
                for service_id, count in top_services
            ]
        }
    
    def get_threat_timeline(self, hours: int = 24) -> List[Dict[str, Any]]:
        """Получение временной линии угроз"""
        since = datetime.now() - timedelta(hours=hours)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT event_id, user_id, event_type, timestamp, source_ip, 
                   resource, action, severity
            FROM cloud_events 
            WHERE timestamp > ? AND severity IN ('warning', 'error', 'critical')
            ORDER BY timestamp DESC
            LIMIT 100
        ''', (since,))
        
        results = cursor.fetchall()
        conn.close()
        
        timeline = []
        for result in results:
            timeline.append({
                'event_id': result[0],
                'user_id': result[1],
                'event_type': result[2],
                'timestamp': result[3],
                'source_ip': result[4],
                'resource': result[5],
                'action': result[6],
                'severity': result[7]
            })
        
        return timeline
    
    def acknowledge_alert(self, alert_id: str, user_id: str) -> bool:
        """Подтверждение оповещения"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE security_alerts 
            SET acknowledged = TRUE, acknowledged_by = ?, acknowledged_at = CURRENT_TIMESTAMP
            WHERE alert_id = ?
        ''', (user_id, alert_id))
        
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if rows_affected > 0 and alert_id in self.active_alerts:
            self.active_alerts[alert_id].acknowledged = True
            logger.info(f"Оповещение {alert_id} подтверждено пользователем {user_id}")
            return True
        
        return False
    
    def resolve_alert(self, alert_id: str, user_id: str, resolution_notes: str = "") -> bool:
        """Решение оповещения"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE security_alerts 
            SET resolved = TRUE, resolved_by = ?, resolved_at = CURRENT_TIMESTAMP,
                resolution_notes = ?
            WHERE alert_id = ?
        ''', (user_id, resolution_notes, alert_id))
        
        rows_affected = cursor.rowcount
        conn.commit()
        conn.close()
        
        if rows_affected > 0:
            if alert_id in self.active_alerts:
                self.active_alerts[alert_id].resolved = True
                del self.active_alerts[alert_id]
            
            logger.info(f"Оповещение {alert_id} решено пользователем {user_id}")
            return True
        
        return False
    
    def get_user_activity_profile(self, user_id: str, days: int = 30) -> Dict[str, Any]:
        """Получение профиля активности пользователя"""
        since = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общая активность
        cursor.execute('''
            SELECT COUNT(*) FROM cloud_events 
            WHERE user_id = ? AND timestamp > ?
        ''', (user_id, since))
        total_events = cursor.fetchone()[0]
        
        # Активность по типам событий
        cursor.execute('''
            SELECT event_type, COUNT(*) as count
            FROM cloud_events 
            WHERE user_id = ? AND timestamp > ?
            GROUP BY event_type
            ORDER BY count DESC
        ''', (user_id, since))
        events_by_type = cursor.fetchall()
        
        # Активность по часам дня
        cursor.execute('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM cloud_events 
            WHERE user_id = ? AND timestamp > ?
            GROUP BY hour
            ORDER BY hour
        ''', (user_id, since))
        hourly_activity = cursor.fetchall()
        
        # Используемые IP адреса
        cursor.execute('''
            SELECT source_ip, COUNT(*) as count
            FROM cloud_events 
            WHERE user_id = ? AND timestamp > ?
            GROUP BY source_ip
            ORDER BY count DESC
        ''', (user_id, since))
        ip_usage = cursor.fetchall()
        
        conn.close()
        
        return {
            'user_id': user_id,
            'period_days': days,
            'total_events': total_events,
            'events_by_type': [
                {'type': event_type, 'count': count}
                for event_type, count in events_by_type
            ],
            'hourly_activity': [
                {'hour': int(hour), 'count': count}
                for hour, count in hourly_activity
            ],
            'ip_addresses': [
                {'ip': ip, 'usage_count': count}
                for ip, count in ip_usage
            ]
        }
    
    def export_events_report(self, start_date: datetime, end_date: datetime, 
                            format: str = "json") -> str:
        """Экспорт отчета о событиях"""
        events = self._get_recent_events(since=start_date)
        events = [e for e in events if e.timestamp <= end_date]
        
        if format.lower() == "json":
            return json.dumps([asdict(event) for event in events], 
                            default=str, ensure_ascii=False, indent=2)
        elif format.lower() == "csv":
            # Простой CSV экспорт
            lines = ["event_id,user_id,event_type,timestamp,source_ip,resource,action,result,severity"]
            for event in events:
                lines.append(f"{event.event_id},{event.user_id},{event.event_type.value},"
                           f"{event.timestamp},{event.source_ip},{event.resource},"
                           f"{event.action},{event.result},{event.severity.value}")
            return "\\n".join(lines)
        
        return json.dumps([asdict(event) for event in events], default=str, ensure_ascii=False)
    
    def stop_monitoring(self):
        """Остановка мониторинга"""
        self.monitoring_active = False
        if self.monitoring_thread.is_alive():
            self.monitoring_thread.join()
        logger.info("Мониторинг остановлен")

# Функции для интеграции с облачными провайдерами
class CloudProviderIntegration:
    """Интеграция с облачными провайдерами"""
    
    @staticmethod
    async def fetch_aws_events(access_key: str, secret_key: str, region: str = "us-east-1") -> List[Dict]:
        """Получение событий из AWS CloudTrail"""
        # Заглушка для демонстрации
        # В реальной реализации здесь будет интеграция с AWS SDK
        return []
    
    @staticmethod
    async def fetch_azure_events(client_id: str, client_secret: str, tenant_id: str) -> List[Dict]:
        """Получение событий из Azure Activity Log"""
        # Заглушка для демонстрации
        # В реальной реализации здесь будет интеграция с Azure SDK
        return []
    
    @staticmethod
    async def fetch_yandex_events(oauth_token: str, cloud_id: str) -> List[Dict]:
        """Получение событий из Yandex Cloud Audit Trails"""
        # Заглушка для демонстрации
        # В реальной реализации здесь будет интеграция с Yandex Cloud SDK
        return []

if __name__ == "__main__":
    # Пример использования
    monitor = CloudActivityMonitor("casb.db")
    
    # Логирование тестового события
    event = monitor.log_cloud_event(
        service_id="yandex_storage_01",
        user_id="test_user",
        event_type=EventType.FILE_UPLOAD,
        source_ip="192.168.1.100",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        resource="/documents/important.pdf",
        action="upload_file",
        result="success"
    )
    
    print(f"Зарегистрировано событие: {event.event_id}")
    
    # Получение дашборда
    dashboard = monitor.get_activity_dashboard(hours=24)
    print(f"Всего событий за 24 часа: {dashboard['summary']['total_events']}")
    
    print("Модуль мониторинга готов к работе!")
