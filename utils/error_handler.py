#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Comprehensive Error Handling and Logging System for CASB
Система комплексной обработки ошибок и логирования для CASB

Автор: AI Assistant
Версия: 2.0
"""

import logging
import logging.handlers
import json
import traceback
import sys
import time
from datetime import datetime
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, asdict
from enum import Enum
import functools
import inspect
from pathlib import Path


class ErrorSeverity(Enum):
    """Уровни серьезности ошибок"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ErrorCategory(Enum):
    """Категории ошибок"""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    VALIDATION = "validation"
    DATABASE = "database"
    NETWORK = "network"
    CONFIGURATION = "configuration"
    SECURITY = "security"
    SYSTEM = "system"
    INTEGRATION = "integration"
    USER_INPUT = "user_input"


@dataclass
class ErrorDetail:
    """Детальная информация об ошибке"""
    error_id: str
    timestamp: datetime
    severity: ErrorSeverity
    category: ErrorCategory
    message: str
    description: str
    module: str
    function: str
    line_number: int
    user_id: Optional[str] = None
    request_id: Optional[str] = None
    stack_trace: Optional[str] = None
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.context is None:
            self.context = {}


class SecurityError(Exception):
    """Базовый класс для ошибок безопасности"""
    def __init__(self, message: str, error_code: str = None, context: Dict = None):
        self.message = message
        self.error_code = error_code or "SECURITY_ERROR"
        self.context = context or {}
        super().__init__(self.message)


class AuthenticationError(SecurityError):
    """Ошибки аутентификации"""
    def __init__(self, message: str = "Ошибка аутентификации", **kwargs):
        super().__init__(message, error_code="AUTH_ERROR", **kwargs)


class AuthorizationError(SecurityError):
    """Ошибки авторизации"""
    def __init__(self, message: str = "Недостаточно прав доступа", **kwargs):
        super().__init__(message, error_code="AUTHZ_ERROR", **kwargs)


class ValidationError(Exception):
    """Ошибки валидации данных"""
    def __init__(self, message: str, field: str = None, value: Any = None):
        self.message = message
        self.field = field
        self.value = value
        super().__init__(self.message)


class DatabaseError(Exception):
    """Ошибки базы данных"""
    def __init__(self, message: str, query: str = None, error_code: str = None):
        self.message = message
        self.query = query
        self.error_code = error_code
        super().__init__(self.message)


class IntegrationError(Exception):
    """Ошибки интеграции с внешними сервисами"""
    def __init__(self, message: str, service: str = None, endpoint: str = None, status_code: int = None):
        self.message = message
        self.service = service
        self.endpoint = endpoint
        self.status_code = status_code
        super().__init__(self.message)


class RateLimitError(Exception):
    """Ошибки превышения лимитов запросов"""
    def __init__(self, message: str = "Превышен лимит запросов", retry_after: int = None):
        self.message = message
        self.retry_after = retry_after
        super().__init__(self.message)


class ConfigurationError(Exception):
    """Ошибки конфигурации"""
    def __init__(self, message: str, config_key: str = None):
        self.message = message
        self.config_key = config_key
        super().__init__(self.message)


class CASBLogger:
    """Расширенная система логирования для CASB"""
    
    def __init__(self, name: str = "CASB", config: Dict = None):
        self.name = name
        self.config = config or {}
        self.logger = logging.getLogger(name)
        self.error_count = {}
        self.setup_logging()
    
    def setup_logging(self):
        """Настройка логирования"""
        log_level = self.config.get('log_level', 'INFO')
        log_format = self.config.get('log_format', 'json')
        
        # Создаем директорию для логов
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        # Настройка форматтера
        if log_format.lower() == 'json':
            formatter = JsonFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        # Очищаем существующие хендлеры
        self.logger.handlers.clear()
        
        # Консольный хендлер
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setFormatter(formatter)
        self.logger.addHandler(console_handler)
        
        # Файловый хендлер для всех логов
        file_handler = logging.handlers.RotatingFileHandler(
            log_dir / f'{self.name.lower()}.log',
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5,
            encoding='utf-8'
        )
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Отдельный файл для ошибок
        error_handler = logging.handlers.RotatingFileHandler(
            log_dir / f'{self.name.lower()}_errors.log',
            maxBytes=10*1024*1024,
            backupCount=10,
            encoding='utf-8'
        )
        error_handler.setLevel(logging.ERROR)
        error_handler.setFormatter(formatter)
        self.logger.addHandler(error_handler)
        
        # Установка уровня логирования
        level = getattr(logging, log_level.upper(), logging.INFO)
        self.logger.setLevel(level)
        
        # Отключаем пропагацию для избежания дублирования
        self.logger.propagate = False
    
    def log_error(self, error_detail: ErrorDetail):
        """Логирование детальной информации об ошибке"""
        extra_data = {
            'error_id': error_detail.error_id,
            'severity': error_detail.severity.value,
            'category': error_detail.category.value,
            'error_module': error_detail.module,  # Renamed to avoid conflict
            'error_function': error_detail.function,
            'line_number': error_detail.line_number,
            'user_id': error_detail.user_id,
            'request_id': error_detail.request_id,
            'context': error_detail.context
        }
        
        if error_detail.severity in [ErrorSeverity.HIGH, ErrorSeverity.CRITICAL]:
            self.logger.error(
                f"[{error_detail.category.value.upper()}] {error_detail.message}",
                extra=extra_data
            )
            # Отправляем критичные ошибки в систему мониторинга
            self._send_alert(error_detail)
        else:
            self.logger.warning(
                f"[{error_detail.category.value.upper()}] {error_detail.message}",
                extra=extra_data
            )
        
        # Обновляем счетчики ошибок
        key = f"{error_detail.category.value}:{error_detail.severity.value}"
        self.error_count[key] = self.error_count.get(key, 0) + 1
    
    def _send_alert(self, error_detail: ErrorDetail):
        """Отправка алертов для критичных ошибок"""
        try:
            alert_data = {
                'timestamp': error_detail.timestamp.isoformat(),
                'severity': error_detail.severity.value,
                'category': error_detail.category.value,
                'message': error_detail.message,
                'module': error_detail.module,
                'context': error_detail.context
            }
            
            # Здесь можно добавить отправку в Slack, Telegram, email и т.д.
            # Пока просто логируем
            self.logger.critical(f"ALERT: {json.dumps(alert_data, ensure_ascii=False)}")
            
        except Exception as e:
            self.logger.error(f"Ошибка отправки алерта: {e}")
    
    def get_error_statistics(self) -> Dict[str, Any]:
        """Получение статистики ошибок"""
        return {
            'error_counts': self.error_count,
            'total_errors': sum(self.error_count.values()),
            'timestamp': datetime.now().isoformat()
        }


class JsonFormatter(logging.Formatter):
    """JSON форматтер для логов"""
    
    def format(self, record):
        log_data = {
            'timestamp': datetime.fromtimestamp(record.created).isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Добавляем дополнительные данные если есть
        if hasattr(record, 'error_id'):
            log_data.update({
                'error_id': record.error_id,
                'severity': record.severity,
                'category': record.category,
                'error_module': getattr(record, 'error_module', None),
                'error_function': getattr(record, 'error_function', None),
                'user_id': record.user_id,
                'request_id': record.request_id,
                'context': record.context
            })
        
        # Добавляем информацию об исключении
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)
        
        return json.dumps(log_data, ensure_ascii=False)


class ErrorHandler:
    """Центральная система обработки ошибок"""
    
    def __init__(self, logger: CASBLogger = None):
        self.logger = logger or CASBLogger()
        self.error_handlers = {}
        self.setup_default_handlers()
    
    def setup_default_handlers(self):
        """Настройка обработчиков по умолчанию"""
        self.register_handler(AuthenticationError, self._handle_auth_error)
        self.register_handler(AuthorizationError, self._handle_authz_error)
        self.register_handler(ValidationError, self._handle_validation_error)
        self.register_handler(DatabaseError, self._handle_database_error)
        self.register_handler(IntegrationError, self._handle_integration_error)
        self.register_handler(RateLimitError, self._handle_rate_limit_error)
        self.register_handler(ConfigurationError, self._handle_config_error)
    
    def register_handler(self, error_type: type, handler_func):
        """Регистрация обработчика для типа ошибки"""
        self.error_handlers[error_type] = handler_func
    
    def handle_error(self, error: Exception, context: Dict[str, Any] = None) -> ErrorDetail:
        """Центральная обработка ошибок"""
        error_id = self._generate_error_id()
        context = context or {}
        
        # Получаем информацию о месте возникновения ошибки
        frame = inspect.currentframe().f_back
        module = frame.f_globals.get('__name__', 'unknown')
        function = frame.f_code.co_name
        line_number = frame.f_lineno
        
        # Определяем тип ошибки и создаем ErrorDetail
        error_detail = self._create_error_detail(
            error, error_id, module, function, line_number, context
        )
        
        # Логируем ошибку
        self.logger.log_error(error_detail)
        
        # Вызываем специфичный обработчик если есть
        handler = self.error_handlers.get(type(error))
        if handler:
            try:
                handler(error, error_detail)
            except Exception as handler_error:
                self.logger.logger.error(f"Ошибка в обработчике: {handler_error}")
        
        return error_detail
    
    def _create_error_detail(self, error: Exception, error_id: str, 
                           module: str, function: str, line_number: int,
                           context: Dict[str, Any]) -> ErrorDetail:
        """Создание детальной информации об ошибке"""
        
        # Определяем категорию и серьезность
        if isinstance(error, (AuthenticationError, AuthorizationError)):
            category = ErrorCategory.SECURITY
            severity = ErrorSeverity.HIGH
        elif isinstance(error, ValidationError):
            category = ErrorCategory.VALIDATION
            severity = ErrorSeverity.MEDIUM
        elif isinstance(error, DatabaseError):
            category = ErrorCategory.DATABASE
            severity = ErrorSeverity.HIGH
        elif isinstance(error, IntegrationError):
            category = ErrorCategory.INTEGRATION
            severity = ErrorSeverity.MEDIUM
        elif isinstance(error, RateLimitError):
            category = ErrorCategory.SYSTEM
            severity = ErrorSeverity.MEDIUM
        elif isinstance(error, ConfigurationError):
            category = ErrorCategory.CONFIGURATION
            severity = ErrorSeverity.HIGH
        else:
            category = ErrorCategory.SYSTEM
            severity = ErrorSeverity.MEDIUM
        
        return ErrorDetail(
            error_id=error_id,
            timestamp=datetime.now(),
            severity=severity,
            category=category,
            message=str(error),
            description=getattr(error, 'description', ''),
            module=module,
            function=function,
            line_number=line_number,
            user_id=context.get('user_id'),
            request_id=context.get('request_id'),
            stack_trace=traceback.format_exc(),
            context=context
        )
    
    def _generate_error_id(self) -> str:
        """Генерация уникального ID ошибки"""
        import hashlib
        timestamp = str(time.time())
        return hashlib.sha256(timestamp.encode()).hexdigest()[:16]
    
    # Специфичные обработчики ошибок
    def _handle_auth_error(self, error: AuthenticationError, detail: ErrorDetail):
        """Обработка ошибок аутентификации"""
        # Логируем попытки атак
        if detail.context.get('failed_attempts', 0) > 5:
            detail.severity = ErrorSeverity.CRITICAL
            detail.message = f"Возможная атака брутфорс: {detail.message}"
    
    def _handle_authz_error(self, error: AuthorizationError, detail: ErrorDetail):
        """Обработка ошибок авторизации"""
        # Логируем попытки эскалации привилегий
        if 'admin' in detail.context.get('requested_resource', '').lower():
            detail.severity = ErrorSeverity.HIGH
            detail.message = f"Попытка эскалации привилегий: {detail.message}"
    
    def _handle_validation_error(self, error: ValidationError, detail: ErrorDetail):
        """Обработка ошибок валидации"""
        detail.context.update({
            'field': getattr(error, 'field', None),
            'value': str(getattr(error, 'value', None))
        })
    
    def _handle_database_error(self, error: DatabaseError, detail: ErrorDetail):
        """Обработка ошибок базы данных"""
        detail.context.update({
            'query': getattr(error, 'query', None),
            'error_code': getattr(error, 'error_code', None)
        })
        
        # Проверяем на SQL инъекции
        query = getattr(error, 'query', '')
        if any(keyword in query.upper() for keyword in ['DROP', 'DELETE', 'UPDATE', 'INSERT']):
            detail.severity = ErrorSeverity.CRITICAL
            detail.category = ErrorCategory.SECURITY
    
    def _handle_integration_error(self, error: IntegrationError, detail: ErrorDetail):
        """Обработка ошибок интеграции"""
        detail.context.update({
            'service': getattr(error, 'service', None),
            'endpoint': getattr(error, 'endpoint', None),
            'status_code': getattr(error, 'status_code', None)
        })
    
    def _handle_rate_limit_error(self, error: RateLimitError, detail: ErrorDetail):
        """Обработка ошибок превышения лимитов"""
        detail.context.update({
            'retry_after': getattr(error, 'retry_after', None)
        })
    
    def _handle_config_error(self, error: ConfigurationError, detail: ErrorDetail):
        """Обработка ошибок конфигурации"""
        detail.context.update({
            'config_key': getattr(error, 'config_key', None)
        })


def error_handler(severity: ErrorSeverity = ErrorSeverity.MEDIUM, 
                 category: ErrorCategory = ErrorCategory.SYSTEM):
    """Декоратор для автоматической обработки ошибок"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                # Получаем или создаем обработчик ошибок
                error_handler_instance = getattr(wrapper, '_error_handler', None)
                if error_handler_instance is None:
                    error_handler_instance = ErrorHandler()
                    wrapper._error_handler = error_handler_instance
                
                # Обрабатываем ошибку
                context = {
                    'function': func.__name__,
                    'args': str(args)[:100],  # Ограничиваем размер
                    'kwargs': str(kwargs)[:100]
                }
                
                error_detail = error_handler_instance.handle_error(e, context)
                
                # Перебрасываем исключение дальше
                raise
        
        return wrapper
    return decorator


def require_auth(func):
    """Декоратор для проверки аутентификации"""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Простая заглушка - в реальной реализации здесь будет проверка токена
        user_id = kwargs.get('user_id') or getattr(args[0], 'user_id', None) if args else None
        
        if not user_id:
            raise AuthenticationError(
                "Требуется аутентификация",
                context={'function': func.__name__}
            )
        
        return func(*args, **kwargs)
    
    return wrapper


def require_permission(permission: str):
    """Декоратор для проверки прав доступа"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Заглушка для проверки прав
            user_permissions = kwargs.get('user_permissions', [])
            
            if permission not in user_permissions:
                raise AuthorizationError(
                    f"Недостаточно прав для выполнения действия: {permission}",
                    context={
                        'function': func.__name__,
                        'required_permission': permission,
                        'user_permissions': user_permissions
                    }
                )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


def validate_input(**validations):
    """Декоратор для валидации входных данных"""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            for param_name, validation_func in validations.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    if not validation_func(value):
                        raise ValidationError(
                            f"Неверное значение параметра {param_name}",
                            field=param_name,
                            value=value
                        )
            
            return func(*args, **kwargs)
        
        return wrapper
    return decorator


# Глобальный обработчик ошибок
global_error_handler = ErrorHandler()


def setup_global_exception_handler():
    """Настройка глобального обработчика исключений"""
    def handle_exception(exc_type, exc_value, exc_traceback):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_traceback)
            return
        
        global_error_handler.handle_error(exc_value)
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
    
    sys.excepthook = handle_exception


if __name__ == "__main__":
    # Демонстрация использования
    setup_global_exception_handler()
    
    logger = CASBLogger("DEMO")
    error_handler_instance = ErrorHandler(logger)
    
    # Тестируем различные типы ошибок
    try:
        raise AuthenticationError("Неверный пароль", context={'user_id': 'test_user'})
    except Exception as e:
        error_handler_instance.handle_error(e)
    
    try:
        raise DatabaseError("Ошибка подключения к БД", query="SELECT * FROM users")
    except Exception as e:
        error_handler_instance.handle_error(e)
    
    print("Статистика ошибок:", logger.get_error_statistics())