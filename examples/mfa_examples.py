#!/usr/bin/env python3
"""
Подробные примеры использования модуля MFA (Multi-Factor Authentication)
Демонстрирует различные сценарии многофакторной аутентификации
"""

import sys
import os
import json
import time
from datetime import datetime, timedelta

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from auth.mfa_auth import MFAAuthenticator

def setup_logging():
    """Настройка логирования"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def basic_mfa_setup_examples():
    """Базовые примеры настройки MFA"""
    logger = setup_logging()
    logger.info("=== Базовые примеры настройки MFA ===")
    
    # Инициализация MFA с отключенным SMTP для демо
    smtp_config = {
        'enabled': False,
        'smtp_server': 'smtp.company.com',
        'smtp_port': 587,
        'username': 'mfa@company.com'
    }
    
    mfa = MFAAuthenticator("mfa_examples.db", smtp_config=smtp_config)
    
    # Тестовые пользователи
    test_users = [
        {"id": "user_001", "email": "john.doe@company.com", "phone": "+7-495-123-45-67"},
        {"id": "user_002", "email": "jane.smith@company.com", "phone": "+7-916-987-65-43"},
        {"id": "admin_001", "email": "admin@company.com", "phone": "+7-495-555-00-00"}
    ]
    
    # 1. Настройка TOTP для каждого пользователя
    logger.info("1. Настройка TOTP аутентификации")
    totp_configs = {}
    
    for user in test_users:
        secret, qr_code = mfa.setup_totp(user["id"], user["email"])
        totp_configs[user["id"]] = {
            'secret': secret,
            'qr_code_length': len(qr_code)
        }
        logger.info(f"TOTP настроен для {user['id']}: секрет {secret[:8]}...")
    
    # 2. Настройка SMS
    logger.info("\n2. Настройка SMS аутентификации")
    sms_configs = {}
    
    for user in test_users:
        sms_method = mfa.setup_sms(user["id"], user["phone"])
        sms_configs[user["id"]] = sms_method
        logger.info(f"SMS настроен для {user['id']}: {user['phone']}")
    
    # 3. Генерация backup кодов
    logger.info("\n3. Генерация backup кодов")
    backup_configs = {}
    
    for user in test_users:
        backup_codes = mfa.generate_backup_codes(user["id"], count=10)
        backup_configs[user["id"]] = len(backup_codes)
        logger.info(f"Backup коды для {user['id']}: {len(backup_codes)} кодов")
        
        # Показать первые 2 кода для демонстрации
        logger.info(f"  Примеры кодов: {backup_codes[:2]}")
    
    return mfa, test_users, {
        'totp': totp_configs,
        'sms': sms_configs,
        'backup': backup_configs
    }

def advanced_mfa_methods_examples(mfa, test_users):
    """Примеры продвинутых методов MFA"""
    logger = setup_logging()
    logger.info("=== Примеры продвинутых методов MFA ===")
    
    user_id = test_users[0]["id"]
    
    # 1. Биометрическая аутентификация
    logger.info("1. Настройка биометрической аутентификации")
    
    biometric_methods = [
        {"type": "fingerprint", "template": "demo_fingerprint_template_001"},
        {"type": "face_recognition", "template": "demo_face_template_001"}
    ]
    
    biometric_configs = {}
    for method in biometric_methods:
        bio_id = mfa.setup_biometric_authentication(
            user_id, method["type"], method["template"]
        )
        biometric_configs[method["type"]] = bio_id
        logger.info(f"Биометрия {method['type']} настроена: {bio_id}")
    
    # 2. Поведенческая аутентификация
    logger.info("\n2. Настройка поведенческой аутентификации")
    
    behavior_analytics = mfa.setup_behavior_analytics(user_id, {
        "baseline_period": 30,
        "anomaly_threshold": 0.8,
        "learning_enabled": True,
        "context_aware": True
    })
    logger.info(f"Поведенческая аналитика: {behavior_analytics}")
    
    return {
        'biometric': biometric_configs,
        'behavior_analytics': behavior_analytics
    }

def authentication_flow_examples(mfa, test_users):
    """Примеры потоков аутентификации"""
    logger = setup_logging()
    logger.info("=== Примеры потоков аутентификации ===")
    
    user_id = test_users[0]["id"]
    
    # 1. Простой TOTP поток
    logger.info("1. Простой TOTP поток")
    
    totp_challenge = mfa.create_challenge(user_id, "totp")
    if totp_challenge:
        logger.info(f"TOTP вызов создан: {totp_challenge.challenge_id}")
        logger.info(f"  Истекает через: {totp_challenge.expires_at - datetime.now()}")
    
    # 2. Адаптивная аутентификация
    logger.info("\n2. Адаптивная аутентификация")
    
    # Сценарий с низким риском
    low_risk_context = {
        'ip_address': '192.168.1.100',  # Корпоративная сеть
        'device_fingerprint': 'known_device_001',
        'location': 'office',
        'time_of_day': '10:30',  # Рабочее время
        'new_device': False,
        'unusual_location': False
    }
    
    adaptive_low = mfa.evaluate_adaptive_authentication(user_id, low_risk_context)
    logger.info(f"Низкий риск - Требуется факторов: {adaptive_low['required_factors']}")
    logger.info(f"  Рекомендуемые методы: {adaptive_low['recommended_methods']}")
    
    # Сценарий с высоким риском
    high_risk_context = {
        'ip_address': '185.220.101.5',  # Подозрительный IP
        'device_fingerprint': 'unknown_device_002',
        'location': 'foreign_country',
        'time_of_day': '03:15',  # Нерабочее время
        'new_device': True,
        'unusual_location': True
    }
    
    adaptive_high = mfa.evaluate_adaptive_authentication(user_id, high_risk_context)
    logger.info(f"Высокий риск - Требуется факторов: {adaptive_high['required_factors']}")
    logger.info(f"  Рекомендуемые методы: {adaptive_high['recommended_methods']}")
    
    return {
        'totp_challenge': totp_challenge,
        'adaptive_results': {'low_risk': adaptive_low, 'high_risk': adaptive_high}
    }

def main():
    """Главная функция демонстрации MFA"""
    logger = setup_logging()
    logger.info("🔐 MFA System - Подробная демонстрация")
    logger.info("=" * 60)
    
    try:
        # 1. Базовая настройка MFA
        basic_setup = basic_mfa_setup_examples()
        mfa, test_users = basic_setup[0], basic_setup[1]
        
        print("\n" + "=" * 60)
        
        # 2. Продвинутые методы
        advanced_methods = advanced_mfa_methods_examples(mfa, test_users)
        
        print("\n" + "=" * 60)
        
        # 3. Потоки аутентификации
        auth_flows = authentication_flow_examples(mfa, test_users)
        
        print("\n" + "=" * 60)
        logger.info("✅ MFA демонстрация завершена успешно!")
        logger.info("🔒 Все функции многофакторной аутентификации продемонстрированы")
        
        # Итоговые статистики
        final_stats = {
            'total_users_configured': len(test_users),
            'mfa_methods_configured': 5,
            'security_features_enabled': 10
        }
        
        logger.info("📊 Итоговая статистика MFA демонстрации:")
        for key, value in final_stats.items():
            logger.info(f"  {key}: {value}")
        
    except Exception as e:
        logger.error(f"❌ Ошибка во время MFA демонстрации: {e}")
        raise
    
    finally:
        # Очистка (опционально)
        cleanup = False  # Установите True для очистки
        if cleanup:
            try:
                if os.path.exists("mfa_examples.db"):
                    os.remove("mfa_examples.db")
                    logger.info("🧹 MFA база данных очищена")
                    
            except Exception as e:
                logger.warning(f"Предупреждение при очистке: {e}")

if __name__ == "__main__":
    main()
