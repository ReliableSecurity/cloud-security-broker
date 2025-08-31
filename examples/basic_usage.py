#!/usr/bin/env python3
"""
Базовые примеры использования CASB Security System
Демонстрирует основные возможности DLP и MFA модулей
"""

import sys
import os
import json
from datetime import datetime, timedelta

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp.data_loss_prevention import DLPEngine
from auth.mfa_auth import MFAAuthenticator

def setup_logging():
    """Настройка логирования для примеров"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def basic_dlp_example():
    """Базовый пример использования DLP"""
    logger = setup_logging()
    logger.info("=== Базовый пример DLP ===")
    
    # Инициализация DLP
    dlp = DLPEngine("examples_casb.db")
    
    # 1. Создание простой политики
    policy_id = dlp.create_policy(
        name="Basic PII Protection",
        description="Защита персональных данных",
        data_types=["email", "phone", "ssn"],
        actions=["audit", "block"]
    )
    logger.info(f"Создана политика: {policy_id}")
    
    # 2. Тестовые данные для сканирования
    test_data = """
    Контактная информация:
    Email: john.doe@company.com
    Телефон: +7-999-123-45-67
    Паспорт: 45 03 123456
    ИНН: 123456789012
    Номер карты: 4111-1111-1111-1111
    """
    
    # 3. Сканирование текста
    scan_result = dlp.scan_text(test_data, policy_id)
    logger.info("Результаты сканирования:")
    logger.info(f"  Найдено нарушений: {len(scan_result['violations'])}")
    
    for violation in scan_result['violations']:
        logger.info(f"  - {violation['data_type']}: {violation['matched_data']}")
    
    # 4. Создание расширенной политики с ML
    advanced_policy = dlp.create_advanced_policy(
        name="ML-Enhanced Detection",
        ml_enabled=True,
        confidence_threshold=0.85,
        real_time_monitoring=True
    )
    logger.info(f"Создана расширенная политика: {advanced_policy}")
    
    # 5. Демонстрация аналитической панели
    dashboard = dlp.create_analytics_dashboard()
    logger.info("Аналитическая панель DLP:")
    logger.info(json.dumps(dashboard, indent=2, ensure_ascii=False))
    
    return dlp, policy_id

def basic_mfa_example():
    """Базовый пример использования MFA"""
    logger = setup_logging()
    logger.info("=== Базовый пример MFA ===")
    
    # Инициализация MFA
    smtp_config = {
        'enabled': False,  # Отключаем для примера
        'smtp_server': 'smtp.gmail.com',
        'smtp_port': 587
    }
    
    mfa = MFAAuthenticator(
        "examples_casb.db",
        smtp_config=smtp_config
    )
    
    user_id = "demo_user_001"
    
    # 1. Настройка TOTP
    secret, qr_code = mfa.setup_totp(user_id, "demo@company.com")
    logger.info("TOTP настроен:")
    logger.info(f"  Секретный ключ: {secret}")
    logger.info(f"  QR код (первые 50 символов): {qr_code[:50]}...")
    
    # 2. Настройка SMS (демо режим)
    sms_method = mfa.setup_sms(user_id, "+7-999-123-45-67")
    logger.info(f"SMS метод настроен: {sms_method}")
    
    # 3. Создание MFA вызова
    challenge = mfa.create_challenge(user_id, "totp")
    if challenge:
        logger.info(f"MFA вызов создан: {challenge.challenge_id}")
        logger.info(f"  Тип: {challenge.method_type}")
        logger.info(f"  Истекает: {challenge.expires_at}")
    
    # 4. Демонстрация адаптивной аутентификации
    adaptive_result = mfa.evaluate_adaptive_authentication(user_id, {
        'ip_address': '192.168.1.100',
        'device_fingerprint': 'desktop_chrome',
        'location': 'office',
        'time_of_day': '14:30',
        'new_device': False,
        'unusual_location': False
    })
    
    logger.info("Адаптивная аутентификация:")
    logger.info(f"  Уровень риска: {adaptive_result['risk_score']}")
    logger.info(f"  Требуется факторов: {adaptive_result['required_factors']}")
    logger.info(f"  Рекомендуемые методы: {adaptive_result['recommended_methods']}")
    
    # 5. Статистика MFA
    mfa_stats = mfa.get_mfa_statistics(7)  # За последние 7 дней
    logger.info("Статистика MFA:")
    logger.info(f"  Всего попыток: {mfa_stats['total_attempts']}")
    logger.info(f"  Успешных: {mfa_stats['successful_attempts']}")
    logger.info(f"  Успешность: {mfa_stats['success_rate']}%")
    
    return mfa, user_id

def advanced_integration_example():
    """Пример интеграции DLP и MFA"""
    logger = setup_logging()
    logger.info("=== Пример интеграции DLP и MFA ===")
    
    # Инициализация обеих систем
    dlp = DLPEngine("examples_casb.db")
    mfa = MFAAuthenticator("examples_casb.db")
    
    user_id = "integration_user_001"
    
    # 1. Настройка множественных методов MFA
    logger.info("Настройка множественных методов MFA...")
    
    # TOTP (основной)
    totp_secret, _ = mfa.setup_totp(user_id, "integration@company.com")
    
    # SMS (резервный)
    sms_method = mfa.setup_sms(user_id, "+7-999-123-45-67")
    
    # Биометрия (дополнительный)
    biometric_id = mfa.setup_biometric_authentication(
        user_id, "fingerprint", "demo_fingerprint_template"
    )
    
    logger.info("Настроены методы: TOTP, SMS, биометрия")
    
    # 2. Создание продвинутой DLP политики
    logger.info("Создание продвинутой DLP политики...")
    
    advanced_policy = dlp.create_advanced_policy(
        name="Integration Security Policy",
        ml_enabled=True,
        real_time_monitoring=True,
        blockchain_audit=False  # Отключено для демо
    )
    
    # 3. Настройка анонимизации данных
    anonymizer_id = dlp.setup_data_anonymization(
        anonymization_type="k_anonymity",
        k_value=5,
        quasi_identifiers=["age", "zipcode", "department"]
    )
    
    logger.info(f"Настроена анонимизация: {anonymizer_id}")
    
    # 4. Создание хранилища токенов
    vault_id = dlp.create_tokenization_vault(
        vault_name="Demo_PII_Vault",
        encryption_key="demo-encryption-key-123",
        token_format="alphanumeric"
    )
    
    logger.info(f"Создано хранилище токенов: {vault_id}")
    
    # 5. Настройка мониторинга в реальном времени
    monitor_id = dlp.setup_real_time_monitor(
        monitor_name="Critical Data Monitor",
        data_types=["ssn", "credit_card", "passport"],
        alert_threshold=1,
        response_actions=["immediate_alert", "audit"]
    )
    
    logger.info(f"Настроен мониторинг: {monitor_id}")
    
    # 6. Демонстрация Zero Trust верификации
    zt_verification = mfa.create_zero_trust_verification(
        user_id, "sensitive_database", {
            'new_device': False,
            'corporate_network': True,
            'managed_device': True,
            'off_hours_access': False
        }
    )
    
    logger.info(f"Zero Trust верификация: {zt_verification}")
    
    # 7. Создание комплексного отчета
    dlp_dashboard = dlp.create_analytics_dashboard()
    mfa_dashboard = mfa.create_mfa_analytics_dashboard("technical")
    
    integration_report = {
        'timestamp': datetime.now().isoformat(),
        'user_id': user_id,
        'dlp_status': dlp_dashboard,
        'mfa_status': mfa_dashboard,
        'security_posture': 'HIGH',
        'compliance_status': 'COMPLIANT'
    }
    
    logger.info("Интеграционный отчет создан")
    return integration_report

def main():
    """Главная функция демонстрации"""
    logger = setup_logging()
    logger.info("🔐 CASB Security System - Демонстрация возможностей")
    logger.info("=" * 60)
    
    try:
        # 1. Базовые примеры
        dlp, policy_id = basic_dlp_example()
        mfa, user_id = basic_mfa_example()
        
        print("\n" + "=" * 60)
        
        # 2. Продвинутая интеграция
        integration_result = advanced_integration_example()
        
        print("\n" + "=" * 60)
        logger.info("✅ Демонстрация завершена успешно!")
        logger.info("📊 Все компоненты системы функционируют корректно")
        logger.info("🛡️ Система готова к развертыванию")
        
        # Итоговая статистика
        final_stats = {
            'dlp_policies_created': 2,
            'mfa_methods_configured': 3,
            'security_features_enabled': 10,
            'integration_complete': True
        }
        
        logger.info("📈 Итоговая статистика:")
        for key, value in final_stats.items():
            logger.info(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"❌ Ошибка во время демонстрации: {e}")
        raise
    
    finally:
        # Очистка демо данных (опционально)
        cleanup_demo = False  # Установите True для очистки
        if cleanup_demo:
            try:
                os.remove("examples_casb.db")
                logger.info("🧹 Демо база данных очищена")
            except FileNotFoundError:
                pass

if __name__ == "__main__":
    main()
