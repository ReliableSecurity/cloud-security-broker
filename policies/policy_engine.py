"""
Модуль управления политиками безопасности для CASB
Система конфигурации и применения политик безопасности

Автор: AI Assistant
"""

import json
import logging
import time
import re
from typing import Dict, List, Optional, Any, Union
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from enum import Enum
import sqlite3
import hashlib
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)

class PolicyType(Enum):
    """Типы политик"""
    ACCESS_CONTROL = "access_control"
    DATA_PROTECTION = "data_protection"
    AUTHENTICATION = "authentication"
    NETWORK_SECURITY = "network_security"
    COMPLIANCE = "compliance"
    INCIDENT_RESPONSE = "incident_response"

class PolicyScope(Enum):
    """Область применения политики"""
    GLOBAL = "global"
    SERVICE = "service"
    USER = "user"
    DEPARTMENT = "department"
    ROLE = "role"

class PolicyStatus(Enum):
    """Статус политики"""
    DRAFT = "draft"
    ACTIVE = "active"
    SUSPENDED = "suspended"
    ARCHIVED = "archived"

class ConditionOperator(Enum):
    """Операторы для условий"""
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    GREATER_THAN = "greater_than"
    LESS_THAN = "less_than"
    IN_LIST = "in_list"
    NOT_IN_LIST = "not_in_list"
    REGEX_MATCH = "regex_match"
    TIME_RANGE = "time_range"

@dataclass
class PolicyCondition:
    """Условие политики"""
    field: str
    operator: ConditionOperator
    value: Union[str, int, float, List, Dict]
    case_sensitive: bool = False

@dataclass
class PolicyAction:
    """Действие политики"""
    action_type: str
    parameters: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.parameters is None:
            self.parameters = {}

@dataclass
class Policy:
    """Политика безопасности"""
    policy_id: str
    name: str
    description: str
    policy_type: PolicyType
    scope: PolicyScope
    target: str  # ID цели (service_id, user_id, department, etc.)
    conditions: List[PolicyCondition]
    actions: List[PolicyAction]
    priority: int = 100  # Чем меньше число, тем выше приоритет
    status: PolicyStatus = PolicyStatus.DRAFT
    created_at: datetime = None
    updated_at: datetime = None
    created_by: str = ""
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.now()
        if self.updated_at is None:
            self.updated_at = datetime.now()

@dataclass
class PolicyEvaluation:
    """Результат оценки политики"""
    policy_id: str
    matched: bool
    conditions_met: List[bool]
    actions_to_execute: List[PolicyAction]
    evaluation_time: datetime
    context: Dict[str, Any]

class PolicyEvaluator(ABC):
    """Абстрактный класс для оценки политик"""
    
    @abstractmethod
    def evaluate_condition(self, condition: PolicyCondition, context: Dict[str, Any]) -> bool:
        """Оценка условия политики"""
        pass

class DefaultPolicyEvaluator(PolicyEvaluator):
    """Стандартный оценщик политик"""
    
    def evaluate_condition(self, condition: PolicyCondition, context: Dict[str, Any]) -> bool:
        """Оценка условия политики"""
        field_value = self._get_field_value(condition.field, context)
        target_value = condition.value
        
        if field_value is None:
            return False
        
        # Приведение к строке для сравнения
        if not condition.case_sensitive and isinstance(field_value, str):
            field_value = field_value.lower()
            if isinstance(target_value, str):
                target_value = target_value.lower()
        
        # Оценка в зависимости от оператора
        if condition.operator == ConditionOperator.EQUALS:
            return field_value == target_value
        
        elif condition.operator == ConditionOperator.NOT_EQUALS:
            return field_value != target_value
        
        elif condition.operator == ConditionOperator.CONTAINS:
            return str(target_value) in str(field_value)
        
        elif condition.operator == ConditionOperator.NOT_CONTAINS:
            return str(target_value) not in str(field_value)
        
        elif condition.operator == ConditionOperator.GREATER_THAN:
            try:
                return float(field_value) > float(target_value)
            except (ValueError, TypeError):
                return False
        
        elif condition.operator == ConditionOperator.LESS_THAN:
            try:
                return float(field_value) < float(target_value)
            except (ValueError, TypeError):
                return False
        
        elif condition.operator == ConditionOperator.IN_LIST:
            return field_value in target_value if isinstance(target_value, list) else False
        
        elif condition.operator == ConditionOperator.NOT_IN_LIST:
            return field_value not in target_value if isinstance(target_value, list) else True
        
        elif condition.operator == ConditionOperator.REGEX_MATCH:
            try:
                return bool(re.search(str(target_value), str(field_value), 
                                    re.IGNORECASE if not condition.case_sensitive else 0))
            except re.error:
                logger.error(f"Некорректное регулярное выражение: {target_value}")
                return False
        
        elif condition.operator == ConditionOperator.TIME_RANGE:
            return self._check_time_range(field_value, target_value)
        
        return False
    
    def _get_field_value(self, field_path: str, context: Dict[str, Any]) -> Any:
        """Получение значения поля из контекста"""
        keys = field_path.split('.')
        value = context
        
        try:
            for key in keys:
                if isinstance(value, dict):
                    value = value.get(key)
                elif hasattr(value, key):
                    value = getattr(value, key)
                else:
                    return None
                
                if value is None:
                    return None
            
            return value
        except (KeyError, AttributeError, TypeError):
            return None
    
    def _check_time_range(self, timestamp: Any, time_range: Dict[str, Any]) -> bool:
        """Проверка временного диапазона"""
        try:
            if isinstance(timestamp, str):
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            elif isinstance(timestamp, datetime):
                dt = timestamp
            else:
                return False
            
            current_time = datetime.now()
            
            # Проверка диапазона часов в день
            if 'hours' in time_range:
                start_hour, end_hour = time_range['hours']
                current_hour = dt.hour
                
                if start_hour <= end_hour:
                    return start_hour <= current_hour <= end_hour
                else:  # Переход через полночь
                    return current_hour >= start_hour or current_hour <= end_hour
            
            # Проверка дней недели
            if 'weekdays' in time_range:
                allowed_weekdays = time_range['weekdays']  # 0=Monday, 6=Sunday
                return dt.weekday() in allowed_weekdays
            
            # Проверка абсолютного времени
            if 'start' in time_range and 'end' in time_range:
                start_time = datetime.fromisoformat(time_range['start'])
                end_time = datetime.fromisoformat(time_range['end'])
                return start_time <= dt <= end_time
            
            return True
            
        except Exception as e:
            logger.error(f"Ошибка проверки временного диапазона: {e}")
            return False

class PolicyEngine:
    """Движок политик безопасности"""
    
    def __init__(self, db_path: str, evaluator: PolicyEvaluator = None):
        self.db_path = db_path
        self.evaluator = evaluator or DefaultPolicyEvaluator()
        self.policies = {}
        self.policy_cache = {}
        
        # Статистика применения политик
        self.policy_stats = {
            'evaluations': 0,
            'policy_violations': 0,
            'actions_executed': 0
        }
        
        self._init_policy_tables()
        self._load_policies_from_db()
        
        logger.info("Движок политик безопасности инициализирован")
    
    def _init_policy_tables(self):
        """Инициализация таблиц политик"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица политик
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policies (
                policy_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                policy_type TEXT,
                scope TEXT,
                target TEXT,
                conditions TEXT,
                actions TEXT,
                priority INTEGER DEFAULT 100,
                status TEXT DEFAULT 'draft',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by TEXT
            )
        ''')
        
        # Таблица истории применения политик
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policy_evaluations (
                evaluation_id TEXT PRIMARY KEY,
                policy_id TEXT,
                context_hash TEXT,
                matched BOOLEAN,
                actions_executed TEXT,
                evaluation_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                execution_time_ms REAL,
                FOREIGN KEY (policy_id) REFERENCES policies (policy_id)
            )
        ''')
        
        # Таблица шаблонов политик
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS policy_templates (
                template_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                category TEXT,
                template_data TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _load_policies_from_db(self):
        """Загрузка политик из базы данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM policies WHERE status = "active"')
        results = cursor.fetchall()
        conn.close()
        
        for result in results:
            policy = self._row_to_policy(result)
            self.policies[policy.policy_id] = policy
        
        logger.info(f"Загружено {len(self.policies)} активных политик")
    
    def _row_to_policy(self, row: tuple) -> Policy:
        """Преобразование строки БД в объект Policy"""
        conditions_data = json.loads(row[6]) if row[6] else []
        actions_data = json.loads(row[7]) if row[7] else []
        
        conditions = [
            PolicyCondition(
                field=cond['field'],
                operator=ConditionOperator(cond['operator']),
                value=cond['value'],
                case_sensitive=cond.get('case_sensitive', False)
            )
            for cond in conditions_data
        ]
        
        actions = [
            PolicyAction(
                action_type=action['action_type'],
                parameters=action.get('parameters', {})
            )
            for action in actions_data
        ]
        
        return Policy(
            policy_id=row[0],
            name=row[1],
            description=row[2],
            policy_type=PolicyType(row[3]),
            scope=PolicyScope(row[4]),
            target=row[5],
            conditions=conditions,
            actions=actions,
            priority=row[8],
            status=PolicyStatus(row[9]),
            created_at=datetime.fromisoformat(row[10]),
            updated_at=datetime.fromisoformat(row[11]),
            created_by=row[12]
        )
    
    def create_policy(self, name: str, description: str, policy_type: PolicyType,
                     scope: PolicyScope, target: str, conditions: List[PolicyCondition],
                     actions: List[PolicyAction], priority: int = 100, 
                     created_by: str = "") -> Policy:
        """Создание новой политики"""
        policy_id = hashlib.sha256(f"{name}_{time.time()}".encode()).hexdigest()[:16]
        
        policy = Policy(
            policy_id=policy_id,
            name=name,
            description=description,
            policy_type=policy_type,
            scope=scope,
            target=target,
            conditions=conditions,
            actions=actions,
            priority=priority,
            created_by=created_by
        )
        
        # Сохраняем в базу данных
        self._save_policy(policy)
        
        logger.info(f"Создана политика: {name}")
        return policy
    
    def _save_policy(self, policy: Policy):
        """Сохранение политики в базу данных"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Сериализация условий и действий
        conditions_json = json.dumps([
            {
                'field': cond.field,
                'operator': cond.operator.value,
                'value': cond.value,
                'case_sensitive': cond.case_sensitive
            }
            for cond in policy.conditions
        ], ensure_ascii=False)
        
        actions_json = json.dumps([
            {
                'action_type': action.action_type,
                'parameters': action.parameters
            }
            for action in policy.actions
        ], ensure_ascii=False)
        
        cursor.execute('''
            INSERT OR REPLACE INTO policies 
            (policy_id, name, description, policy_type, scope, target, 
             conditions, actions, priority, status, created_at, updated_at, created_by)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (policy.policy_id, policy.name, policy.description, 
              policy.policy_type.value, policy.scope.value, policy.target,
              conditions_json, actions_json, policy.priority, policy.status.value,
              policy.created_at, policy.updated_at, policy.created_by))
        
        conn.commit()
        conn.close()
    
    def activate_policy(self, policy_id: str) -> bool:
        """Активация политики"""
        if policy_id not in self.policies:
            # Загружаем из базы данных
            policy = self._load_policy_by_id(policy_id)
            if not policy:
                return False
        else:
            policy = self.policies[policy_id]
        
        policy.status = PolicyStatus.ACTIVE
        policy.updated_at = datetime.now()
        
        self._save_policy(policy)
        self.policies[policy_id] = policy
        
        logger.info(f"Политика активирована: {policy.name}")
        return True
    
    def suspend_policy(self, policy_id: str) -> bool:
        """Приостановка политики"""
        if policy_id in self.policies:
            policy = self.policies[policy_id]
            policy.status = PolicyStatus.SUSPENDED
            policy.updated_at = datetime.now()
            
            self._save_policy(policy)
            del self.policies[policy_id]  # Удаляем из активных
            
            logger.info(f"Политика приостановлена: {policy.name}")
            return True
        
        return False
    
    def _load_policy_by_id(self, policy_id: str) -> Optional[Policy]:
        """Загрузка политики по ID"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM policies WHERE policy_id = ?', (policy_id,))
        result = cursor.fetchone()
        conn.close()
        
        if result:
            return self._row_to_policy(result)
        
        return None
    
    def evaluate_policies(self, context: Dict[str, Any]) -> List[PolicyEvaluation]:
        """Оценка всех применимых политик для данного контекста"""
        start_time = time.time()
        evaluations = []
        
        # Сортируем политики по приоритету
        sorted_policies = sorted(self.policies.values(), key=lambda p: p.priority)
        
        for policy in sorted_policies:
            if not self._is_policy_applicable(policy, context):
                continue
            
            evaluation = self._evaluate_single_policy(policy, context)
            evaluations.append(evaluation)
            
            # Записываем результат оценки
            self._log_policy_evaluation(evaluation, time.time() - start_time)
        
        self.policy_stats['evaluations'] += 1
        
        logger.debug(f"Оценено {len(evaluations)} политик за {(time.time() - start_time)*1000:.2f}мс")
        return evaluations
    
    def _is_policy_applicable(self, policy: Policy, context: Dict[str, Any]) -> bool:
        """Проверка применимости политики к контексту"""
        # Проверка области применения
        if policy.scope == PolicyScope.GLOBAL:
            return True
        
        elif policy.scope == PolicyScope.SERVICE:
            return context.get('service_id') == policy.target
        
        elif policy.scope == PolicyScope.USER:
            return context.get('user_id') == policy.target
        
        elif policy.scope == PolicyScope.DEPARTMENT:
            return context.get('user_department') == policy.target
        
        elif policy.scope == PolicyScope.ROLE:
            user_roles = context.get('user_roles', [])
            return policy.target in user_roles
        
        return False
    
    def _evaluate_single_policy(self, policy: Policy, context: Dict[str, Any]) -> PolicyEvaluation:
        """Оценка одной политики"""
        conditions_met = []
        
        # Оценка всех условий
        for condition in policy.conditions:
            result = self.evaluator.evaluate_condition(condition, context)
            conditions_met.append(result)
        
        # Политика срабатывает если все условия выполнены (логическое И)
        matched = all(conditions_met) if conditions_met else False
        
        # Определяем действия к выполнению
        actions_to_execute = policy.actions if matched else []
        
        return PolicyEvaluation(
            policy_id=policy.policy_id,
            matched=matched,
            conditions_met=conditions_met,
            actions_to_execute=actions_to_execute,
            evaluation_time=datetime.now(),
            context=context
        )
    
    def _log_policy_evaluation(self, evaluation: PolicyEvaluation, execution_time: float):
        """Логирование результата оценки политики"""
        evaluation_id = hashlib.sha256(f"{evaluation.policy_id}_{time.time()}".encode()).hexdigest()[:16]
        context_hash = hashlib.sha256(json.dumps(evaluation.context, sort_keys=True).encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO policy_evaluations 
            (evaluation_id, policy_id, context_hash, matched, actions_executed, execution_time_ms)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (evaluation_id, evaluation.policy_id, context_hash, evaluation.matched,
              json.dumps([action.action_type for action in evaluation.actions_to_execute]),
              execution_time * 1000))
        
        conn.commit()
        conn.close()
    
    def execute_policy_actions(self, evaluations: List[PolicyEvaluation], 
                              action_handlers: Dict[str, callable] = None) -> Dict[str, Any]:
        """Выполнение действий политик"""
        action_handlers = action_handlers or {}
        execution_results = {
            'executed_actions': [],
            'failed_actions': [],
            'execution_summary': {}
        }
        
        for evaluation in evaluations:
            if not evaluation.matched:
                continue
            
            for action in evaluation.actions_to_execute:
                try:
                    # Выполняем действие
                    if action.action_type in action_handlers:
                        result = action_handlers[action.action_type](action.parameters, evaluation.context)
                        execution_results['executed_actions'].append({
                            'policy_id': evaluation.policy_id,
                            'action_type': action.action_type,
                            'result': result
                        })
                    else:
                        # Стандартные действия
                        result = self._execute_standard_action(action, evaluation.context)
                        execution_results['executed_actions'].append({
                            'policy_id': evaluation.policy_id,
                            'action_type': action.action_type,
                            'result': result
                        })
                    
                    self.policy_stats['actions_executed'] += 1
                    
                except Exception as e:
                    logger.error(f"Ошибка выполнения действия {action.action_type}: {e}")
                    execution_results['failed_actions'].append({
                        'policy_id': evaluation.policy_id,
                        'action_type': action.action_type,
                        'error': str(e)
                    })
        
        # Подсчет статистики
        action_counts = {}
        for action in execution_results['executed_actions']:
            action_type = action['action_type']
            action_counts[action_type] = action_counts.get(action_type, 0) + 1
        
        execution_results['execution_summary'] = action_counts
        
        if execution_results['executed_actions']:
            self.policy_stats['policy_violations'] += 1
        
        return execution_results
    
    def _execute_standard_action(self, action: PolicyAction, context: Dict[str, Any]) -> str:
        """Выполнение стандартных действий"""
        if action.action_type == "block":
            logger.warning(f"Доступ заблокирован политикой для пользователя {context.get('user_id')}")
            return "blocked"
        
        elif action.action_type == "log":
            logger.info(f"Логирование события: {json.dumps(context, ensure_ascii=False)}")
            return "logged"
        
        elif action.action_type == "alert":
            alert_message = action.parameters.get('message', 'Сработала политика безопасности')
            logger.warning(f"ALERT: {alert_message}")
            return "alert_sent"
        
        elif action.action_type == "quarantine":
            logger.warning(f"Ресурс помещен в карантин: {context.get('resource')}")
            return "quarantined"
        
        elif action.action_type == "require_mfa":
            logger.info(f"Требуется дополнительная аутентификация для {context.get('user_id')}")
            return "mfa_required"
        
        return "unknown_action"
    
    def create_policy_template(self, name: str, description: str, category: str,
                              template_data: Dict[str, Any]) -> str:
        """Создание шаблона политики"""
        template_id = hashlib.sha256(f"{name}_{category}_{time.time()}".encode()).hexdigest()[:16]
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO policy_templates (template_id, name, description, category, template_data)
            VALUES (?, ?, ?, ?, ?)
        ''', (template_id, name, description, category, json.dumps(template_data, ensure_ascii=False)))
        
        conn.commit()
        conn.close()
        
        logger.info(f"Создан шаблон политики: {name}")
        return template_id
    
    def create_policy_from_template(self, template_id: str, name: str, target: str,
                                   created_by: str = "", **kwargs) -> Optional[Policy]:
        """Создание политики из шаблона"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT template_data FROM policy_templates WHERE template_id = ?', (template_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            logger.error(f"Шаблон политики не найден: {template_id}")
            return None
        
        template_data = json.loads(result[0])
        
        # Замещаем параметры шаблона
        for key, value in kwargs.items():
            if key in template_data:
                template_data[key] = value
        
        # Создаем условия и действия
        conditions = [
            PolicyCondition(
                field=cond['field'],
                operator=ConditionOperator(cond['operator']),
                value=cond['value'],
                case_sensitive=cond.get('case_sensitive', False)
            )
            for cond in template_data.get('conditions', [])
        ]
        
        actions = [
            PolicyAction(
                action_type=action['action_type'],
                parameters=action.get('parameters', {})
            )
            for action in template_data.get('actions', [])
        ]
        
        return self.create_policy(
            name=name,
            description=template_data.get('description', ''),
            policy_type=PolicyType(template_data['policy_type']),
            scope=PolicyScope(template_data['scope']),
            target=target,
            conditions=conditions,
            actions=actions,
            priority=template_data.get('priority', 100),
            created_by=created_by
        )
    
    def get_policy_statistics(self, days: int = 30) -> Dict[str, Any]:
        """Получение статистики политик"""
        since = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Общая статистика оценок
        cursor.execute('''
            SELECT COUNT(*) FROM policy_evaluations WHERE evaluation_timestamp > ?
        ''', (since,))
        total_evaluations = cursor.fetchone()[0]
        
        cursor.execute('''
            SELECT COUNT(*) FROM policy_evaluations 
            WHERE evaluation_timestamp > ? AND matched = TRUE
        ''', (since,))
        matched_evaluations = cursor.fetchone()[0]
        
        # Статистика по политикам
        cursor.execute('''
            SELECT p.name, COUNT(*) as evaluations, 
                   SUM(CASE WHEN pe.matched THEN 1 ELSE 0 END) as matches
            FROM policy_evaluations pe
            JOIN policies p ON pe.policy_id = p.policy_id
            WHERE pe.evaluation_timestamp > ?
            GROUP BY p.policy_id, p.name
            ORDER BY matches DESC
        ''', (since,))
        
        policy_stats = cursor.fetchall()
        
        # Средне время выполнения
        cursor.execute('''
            SELECT AVG(execution_time_ms) FROM policy_evaluations 
            WHERE evaluation_timestamp > ?
        ''', (since,))
        avg_execution_time = cursor.fetchone()[0] or 0
        
        conn.close()
        
        return {
            'period_days': days,
            'summary': {
                'total_evaluations': total_evaluations,
                'matched_evaluations': matched_evaluations,
                'match_rate': round(matched_evaluations / total_evaluations * 100, 2) if total_evaluations > 0 else 0,
                'avg_execution_time_ms': round(avg_execution_time, 2),
                'active_policies': len(self.policies)
            },
            'policy_performance': [
                {
                    'policy_name': name,
                    'evaluations': evaluations,
                    'matches': matches,
                    'match_rate': round(matches / evaluations * 100, 2) if evaluations > 0 else 0
                }
                for name, evaluations, matches in policy_stats
            ],
            'current_stats': self.policy_stats
        }
    
    def validate_policy(self, policy: Policy) -> List[str]:
        """Валидация политики"""
        errors = []
        
        # Проверка обязательных полей
        if not policy.name.strip():
            errors.append("Имя политики не может быть пустым")
        
        if not policy.conditions:
            errors.append("Политика должна содержать хотя бы одно условие")
        
        if not policy.actions:
            errors.append("Политика должна содержать хотя бы одно действие")
        
        # Проверка условий
        for i, condition in enumerate(policy.conditions):
            if not condition.field.strip():
                errors.append(f"Условие {i+1}: поле не может быть пустым")
            
            # Проверка регулярных выражений
            if condition.operator == ConditionOperator.REGEX_MATCH:
                try:
                    re.compile(str(condition.value))
                except re.error as e:
                    errors.append(f"Условие {i+1}: некорректное регулярное выражение - {e}")
        
        # Проверка действий
        known_actions = ["block", "log", "alert", "quarantine", "require_mfa", "encrypt", "notify"]
        for i, action in enumerate(policy.actions):
            if action.action_type not in known_actions:
                errors.append(f"Действие {i+1}: неизвестный тип действия '{action.action_type}'")
        
        return errors
    
    def get_applicable_policies(self, context: Dict[str, Any]) -> List[Policy]:
        """Получение применимых политик для контекста"""
        applicable_policies = []
        
        for policy in self.policies.values():
            if self._is_policy_applicable(policy, context):
                applicable_policies.append(policy)
        
        # Сортируем по приоритету
        applicable_policies.sort(key=lambda p: p.priority)
        
        return applicable_policies
    
    def import_policies_from_file(self, file_path: str, created_by: str = "") -> int:
        """Импорт политик из файла"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                policies_data = json.load(f)
            
            imported_count = 0
            
            for policy_data in policies_data:
                try:
                    # Создаем условия
                    conditions = [
                        PolicyCondition(
                            field=cond['field'],
                            operator=ConditionOperator(cond['operator']),
                            value=cond['value'],
                            case_sensitive=cond.get('case_sensitive', False)
                        )
                        for cond in policy_data.get('conditions', [])
                    ]
                    
                    # Создаем действия
                    actions = [
                        PolicyAction(
                            action_type=action['action_type'],
                            parameters=action.get('parameters', {})
                        )
                        for action in policy_data.get('actions', [])
                    ]
                    
                    # Создаем политику
                    policy = self.create_policy(
                        name=policy_data['name'],
                        description=policy_data.get('description', ''),
                        policy_type=PolicyType(policy_data['policy_type']),
                        scope=PolicyScope(policy_data['scope']),
                        target=policy_data['target'],
                        conditions=conditions,
                        actions=actions,
                        priority=policy_data.get('priority', 100),
                        created_by=created_by
                    )
                    
                    imported_count += 1
                    logger.info(f"Импортирована политика: {policy.name}")
                    
                except Exception as e:
                    logger.error(f"Ошибка импорта политики {policy_data.get('name', 'Unknown')}: {e}")
            
            logger.info(f"Импортировано {imported_count} политик из {file_path}")
            return imported_count
            
        except Exception as e:
            logger.error(f"Ошибка импорта политик из файла {file_path}: {e}")
            return 0
    
    def export_policies_to_file(self, file_path: str, policy_ids: List[str] = None) -> bool:
        """Экспорт политик в файл"""
        try:
            policies_to_export = []
            
            if policy_ids:
                # Экспорт конкретных политик
                for policy_id in policy_ids:
                    policy = self.policies.get(policy_id) or self._load_policy_by_id(policy_id)
                    if policy:
                        policies_to_export.append(policy)
            else:
                # Экспорт всех активных политик
                policies_to_export = list(self.policies.values())
            
            # Сериализация политик
            export_data = []
            for policy in policies_to_export:
                policy_dict = {
                    'name': policy.name,
                    'description': policy.description,
                    'policy_type': policy.policy_type.value,
                    'scope': policy.scope.value,
                    'target': policy.target,
                    'priority': policy.priority,
                    'conditions': [
                        {
                            'field': cond.field,
                            'operator': cond.operator.value,
                            'value': cond.value,
                            'case_sensitive': cond.case_sensitive
                        }
                        for cond in policy.conditions
                    ],
                    'actions': [
                        {
                            'action_type': action.action_type,
                            'parameters': action.parameters
                        }
                        for action in policy.actions
                    ]
                }
                export_data.append(policy_dict)
            
            # Сохранение в файл
            with open(file_path, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, ensure_ascii=False, indent=2)
            
            logger.info(f"Экспортировано {len(export_data)} политик в {file_path}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка экспорта политик в файл {file_path}: {e}")
            return False
    
    def get_policy_conflicts(self) -> List[Dict[str, Any]]:
        """Поиск конфликтующих политик"""
        conflicts = []
        policies_list = list(self.policies.values())
        
        for i, policy1 in enumerate(policies_list):
            for policy2 in policies_list[i+1:]:
                # Проверяем конфликты только для политик с одинаковой областью применения
                if (policy1.scope == policy2.scope and 
                    policy1.target == policy2.target and
                    policy1.policy_type == policy2.policy_type):
                    
                    # Проверяем противоречивые действия
                    actions1 = {action.action_type for action in policy1.actions}
                    actions2 = {action.action_type for action in policy2.actions}
                    
                    # Конфликтующие пары действий
                    conflicting_pairs = [
                        ("block", "allow"),
                        ("quarantine", "allow"),
                        ("encrypt", "block")
                    ]
                    
                    for action_a, action_b in conflicting_pairs:
                        if action_a in actions1 and action_b in actions2:
                            conflicts.append({
                                'policy1_id': policy1.policy_id,
                                'policy1_name': policy1.name,
                                'policy2_id': policy2.policy_id,
                                'policy2_name': policy2.name,
                                'conflict_type': f"Конфликт действий: {action_a} vs {action_b}",
                                'priority_diff': abs(policy1.priority - policy2.priority)
                            })
        
        return conflicts
    
    def optimize_policies(self) -> Dict[str, Any]:
        """Оптимизация политик"""
        optimization_results = {
            'redundant_policies': [],
            'unused_policies': [],
            'recommendations': []
        }
        
        # Поиск неиспользуемых политик
        since = datetime.now() - timedelta(days=30)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        for policy_id, policy in self.policies.items():
            cursor.execute('''
                SELECT COUNT(*) FROM policy_evaluations 
                WHERE policy_id = ? AND evaluation_timestamp > ?
            ''', (policy_id, since))
            
            evaluation_count = cursor.fetchone()[0]
            
            if evaluation_count == 0:
                optimization_results['unused_policies'].append({
                    'policy_id': policy_id,
                    'name': policy.name,
                    'created_at': policy.created_at.isoformat()
                })
        
        conn.close()
        
        # Поиск избыточных политик (упрощенная логика)
        policies_by_scope = {}
        for policy in self.policies.values():
            key = f"{policy.scope.value}:{policy.target}:{policy.policy_type.value}"
            if key not in policies_by_scope:
                policies_by_scope[key] = []
            policies_by_scope[key].append(policy)
        
        for scope_key, scope_policies in policies_by_scope.items():
            if len(scope_policies) > 3:  # Много политик для одной области
                optimization_results['recommendations'].append({
                    'type': 'consolidation',
                    'message': f"Рекомендуется консолидировать {len(scope_policies)} политик для области {scope_key}"
                })
        
        return optimization_results

# Предустановленные шаблоны политик
def load_default_policy_templates(policy_engine: PolicyEngine):
    """Загрузка шаблонов политик по умолчанию"""
    
    templates = [
        {
            'name': 'Блокировка доступа в нерабочее время',
            'description': 'Запрет доступа к критичным ресурсам вне рабочих часов',
            'category': 'access_control',
            'template_data': {
                'policy_type': 'access_control',
                'scope': 'service',
                'priority': 50,
                'conditions': [
                    {
                        'field': 'request.timestamp',
                        'operator': 'time_range',
                        'value': {'hours': [18, 8]},  # После 18:00 и до 8:00
                        'case_sensitive': False
                    },
                    {
                        'field': 'service.risk_level',
                        'operator': 'in_list',
                        'value': ['high', 'critical'],
                        'case_sensitive': False
                    }
                ],
                'actions': [
                    {
                        'action_type': 'block',
                        'parameters': {'reason': 'Доступ запрещен в нерабочее время'}
                    },
                    {
                        'action_type': 'log',
                        'parameters': {'level': 'warning'}
                    }
                ]
            }
        },
        {
            'name': 'Требование MFA для административных действий',
            'description': 'Обязательная многофакторная аутентификация для админов',
            'category': 'authentication',
            'template_data': {
                'policy_type': 'authentication',
                'scope': 'role',
                'priority': 10,
                'conditions': [
                    {
                        'field': 'user.access_level',
                        'operator': 'equals',
                        'value': 'admin',
                        'case_sensitive': False
                    },
                    {
                        'field': 'request.action',
                        'operator': 'regex_match',
                        'value': '.*(delete|modify|config|admin).*',
                        'case_sensitive': False
                    }
                ],
                'actions': [
                    {
                        'action_type': 'require_mfa',
                        'parameters': {'methods': ['totp', 'sms']}
                    }
                ]
            }
        },
        {
            'name': 'Блокировка подозрительных IP',
            'description': 'Блокировка доступа с подозрительных IP адресов',
            'category': 'network_security',
            'template_data': {
                'policy_type': 'network_security',
                'scope': 'global',
                'priority': 20,
                'conditions': [
                    {
                        'field': 'request.ip_address',
                        'operator': 'in_list',
                        'value': [],  # Будет заполнено при создании
                        'case_sensitive': False
                    }
                ],
                'actions': [
                    {
                        'action_type': 'block',
                        'parameters': {'reason': 'IP адрес в черном списке'}
                    },
                    {
                        'action_type': 'alert',
                        'parameters': {'severity': 'high', 'message': 'Доступ с заблокированного IP'}
                    }
                ]
            }
        },
        {
            'name': 'Шифрование конфиденциальных файлов',
            'description': 'Автоматическое шифрование файлов с конфиденциальными данными',
            'category': 'data_protection',
            'template_data': {
                'policy_type': 'data_protection',
                'scope': 'global',
                'priority': 30,
                'conditions': [
                    {
                        'field': 'file.classification',
                        'operator': 'in_list',
                        'value': ['confidential', 'restricted'],
                        'case_sensitive': False
                    }
                ],
                'actions': [
                    {
                        'action_type': 'encrypt',
                        'parameters': {'algorithm': 'AES-256'}
                    },
                    {
                        'action_type': 'log',
                        'parameters': {'level': 'info'}
                    }
                ]
            }
        },
        {
            'name': 'Контроль доступа по отделам',
            'description': 'Ограничение доступа к ресурсам по отделам',
            'category': 'access_control',
            'template_data': {
                'policy_type': 'access_control',
                'scope': 'department',
                'priority': 40,
                'conditions': [
                    {
                        'field': 'user.department',
                        'operator': 'not_equals',
                        'value': '',  # Будет заполнено при создании
                        'case_sensitive': False
                    },
                    {
                        'field': 'resource.department_restriction',
                        'operator': 'equals',
                        'value': True,
                        'case_sensitive': False
                    }
                ],
                'actions': [
                    {
                        'action_type': 'block',
                        'parameters': {'reason': 'Нет доступа для данного отдела'}
                    }
                ]
            }
        }
    ]
    
    for template in templates:
        policy_engine.create_policy_template(
            name=template['name'],
            description=template['description'],
            category=template['category'],
            template_data=template['template_data']
        )
    
    logger.info(f"Загружено {len(templates)} шаблонов политик")

if __name__ == "__main__":
    # Пример использования
    policy_engine = PolicyEngine("casb.db")
    
    # Загрузка шаблонов по умолчанию
    load_default_policy_templates(policy_engine)
    
    # Создание политики из шаблона
    policy = policy_engine.create_policy_from_template(
        template_id="template_id_here",  # В реальном использовании будет настоящий ID
        name="Блокировка доступа к финансовым данным в выходные",
        target="finance_service",
        created_by="admin"
    )
    
    # Тестовый контекст для оценки политик
    test_context = {
        'user_id': 'test_user',
        'user_department': 'IT',
        'user_access_level': 'admin',
        'service_id': 'finance_service',
        'service_risk_level': 'high',
        'request': {
            'timestamp': datetime.now(),
            'ip_address': '192.168.1.100',
            'action': 'view_reports'
        }
    }
    
    # Оценка политик
    evaluations = policy_engine.evaluate_policies(test_context)
    
    print(f"Оценено {len(evaluations)} политик")
    for eval_result in evaluations:
        if eval_result.matched:
            print(f"Сработала политика: {eval_result.policy_id}")
            print(f"Действия к выполнению: {[a.action_type for a in eval_result.actions_to_execute]}")
    
    print("Модуль управления политиками готов к работе!")
