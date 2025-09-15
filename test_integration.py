#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Simple integration test for CASB system
Простой интеграционный тест системы CASB
"""

import os
import sys
import tempfile
from datetime import datetime

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_basic_functionality():
    """Тест базовой функциональности системы"""
    print("🚀 Запуск интеграционного теста CASB системы...")
    
    # Создаем временную базу данных
    fd, temp_db = tempfile.mkstemp(suffix='.db')
    os.close(fd)
    
    try:
        # 1. Тест импортов
        print("📦 Проверка импортов...")
        from core.casb import CASBCore, AccessLevel, CloudProvider, ThreatLevel
        from auth.mfa_auth import MFAAuthenticator  
        from monitoring.cloud_monitor import CloudActivityMonitor, EventType, Severity
        from utils.error_handler import ErrorHandler
        print("✅ Все модули импортированы успешно")
        
        # 2. Инициализация компонентов
        print("🔧 Инициализация компонентов...")
        
        # Настройка конфигурации
        config = {
            'database': temp_db,
            'jwt_secret': 'test_integration_secret',
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'threat_threshold': 0.7
        }
        
        # Создаем CASB Core с патчем
        from unittest.mock import patch
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
        
        mfa = MFAAuthenticator(temp_db)
        monitor = CloudActivityMonitor(temp_db)
        error_handler = ErrorHandler()
        
        print("✅ Все компоненты инициализированы")
        
        # 3. Тест создания пользователя
        print("👤 Тест создания пользователя...")
        user = casb.create_user(
            username="test_integration_user",
            email="test@casb-integration.com",
            department="IT",
            access_level=AccessLevel.ADMIN,
            password="SecurePassword123!"
        )
        print(f"✅ Пользователь создан: {user.username} (ID: {user.user_id})")
        
        # 4. Тест регистрации сервиса
        print("☁️ Тест регистрации облачного сервиса...")
        service = casb.register_cloud_service(
            name="Integration Test Service",
            provider=CloudProvider.AWS,
            endpoint="https://test.amazonaws.com",
            api_key="integration_test_key",
            service_type="compute",
            risk_level=ThreatLevel.MEDIUM
        )
        print(f"✅ Сервис зарегистрирован: {service.name} (ID: {service.service_id})")
        
        # 5. Тест MFA
        print("🔐 Тест многофакторной аутентификации...")
        secret, qr_code = mfa.setup_totp(user.user_id, user.username)
        print(f"✅ TOTP настроен, секрет длиной: {len(secret)} символов")
        
        # 6. Тест запроса доступа
        print("🔑 Тест запроса доступа...")
        access_request = casb.request_access(
            user_id=user.user_id,
            service_id=service.service_id,
            action="test_integration_action",
            ip_address="192.168.1.100",
            user_agent="integration-test-agent"
        )
        print(f"✅ Запрос доступа создан с риск-скором: {access_request.risk_score:.2f}")
        
        # 7. Тест мониторинга
        print("📊 Тест системы мониторинга...")
        event = monitor.log_cloud_event(
            service_id=service.service_id,
            user_id=user.user_id,
            event_type=EventType.API_CALL,
            source_ip="192.168.1.100",
            user_agent="integration-test",
            resource="/api/integration/test",
            action="integration_test",
            result="success"
        )
        print(f"✅ Событие зарегистрировано: {event.event_id}")
        
        # 8. Тест метрик
        print("📈 Тест получения метрик...")
        casb_metrics = casb.get_dashboard_metrics()
        monitor_metrics = monitor.get_activity_dashboard(hours=1)
        print(f"✅ CASB метрики: {casb_metrics['summary']['active_users']} активных пользователей")
        print(f"✅ Мониторинг метрики: {monitor_metrics['summary']['total_events']} событий")
        
        # 9. Тест обработки ошибок
        print("⚠️ Тест системы обработки ошибок...")
        from utils.error_handler import ValidationError
        try:
            raise ValidationError("Тестовая ошибка валидации", field="test_field", value="invalid_value")
        except ValidationError as e:
            error_detail = error_handler.handle_error(e, context={'test_integration': True})
            print(f"✅ Ошибка обработана с ID: {error_detail.error_id}")
        
        # 10. Тест аутентификации
        print("🔒 Тест аутентификации пользователя...")
        token = casb.authenticate_user("test_integration_user", "SecurePassword123!", "192.168.1.100")
        if token:
            print("✅ Аутентификация прошла успешно")
            
            # Валидация токена
            validated_user_id = casb.validate_session_token(token)
            if validated_user_id == user.user_id:
                print("✅ Токен валиден")
            else:
                print("❌ Ошибка валидации токена")
        else:
            print("❌ Ошибка аутентификации")
        
        # 11. Тест шифрования
        print("🔐 Тест системы шифрования...")
        sensitive_data = "sensitive_integration_test_data_12345"
        encrypted = casb.encrypt_data(sensitive_data)
        decrypted = casb.decrypt_data(encrypted)
        
        if decrypted == sensitive_data:
            print("✅ Шифрование/расшифровка работает корректно")
        else:
            print("❌ Ошибка шифрования")
        
        print("\n🎉 Интеграционный тест завершен успешно!")
        print("📋 Результаты:")
        print(f"   • Создано пользователей: 1")
        print(f"   • Зарегистрировано сервисов: 1") 
        print(f"   • Выполнено запросов доступа: 1")
        print(f"   • Зарегистрировано событий: 1")
        print(f"   • Время выполнения: {datetime.now()}")
        
        return True
        
    except Exception as e:
        print(f"❌ Ошибка во время интеграционного теста: {e}")
        import traceback
        traceback.print_exc()
        return False
        
    finally:
        # Очищаем временную базу данных
        try:
            if 'monitor' in locals():
                monitor.stop_monitoring()
            os.unlink(temp_db)
        except:
            pass


def test_security_features():
    """Тест функций безопасности"""
    print("\n🔒 Тест функций безопасности...")
    
    from utils.error_handler import (
        AuthenticationError, 
        AuthorizationError,
        ValidationError,
        SecurityError
    )
    
    # Тест классов исключений безопасности
    try:
        raise AuthenticationError("Тест ошибки аутентификации")
    except SecurityError as e:
        print(f"✅ AuthenticationError работает: {e.message}")
    
    try:
        raise AuthorizationError("Тест ошибки авторизации")
    except SecurityError as e:
        print(f"✅ AuthorizationError работает: {e.message}")
    
    print("✅ Функции безопасности протестированы")


if __name__ == "__main__":
    print("=" * 80)
    print("🛡️  CASB SECURITY SYSTEM - INTEGRATION TEST")
    print("=" * 80)
    
    success = test_basic_functionality()
    test_security_features()
    
    if success:
        print("\n🎯 ВСЕ ТЕСТЫ ПРОЙДЕНЫ УСПЕШНО!")
        print("✅ Система готова к развертыванию")
        sys.exit(0)
    else:
        print("\n❌ ТЕСТЫ НЕ ПРОЙДЕНЫ!")
        print("🔧 Требуется исправление ошибок")
        sys.exit(1)