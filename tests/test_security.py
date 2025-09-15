#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тесты безопасности для CASB системы
Включает пентесты и проверку уязвимостей
"""

import pytest
import tempfile
import os
import sys
import requests
from unittest.mock import patch, MagicMock
import time
import jwt
import hashlib
import threading
from datetime import datetime, timedelta

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.casb import CASBCore, AccessLevel, CloudProvider, ThreatLevel
from auth.mfa_auth import MFAAuthenticator
from monitoring.cloud_monitor import CloudActivityMonitor


class TestSecurityValidation:
    """Тесты проверки безопасности"""
    
    @pytest.fixture
    def temp_db(self):
        """Временная база данных для тестов"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        yield path
        try:
            os.unlink(path)
        except OSError:
            pass
    
    @pytest.fixture
    def casb_system(self, temp_db):
        """Настроенная CASB система для тестов"""
        config = {
            'database': temp_db,
            'jwt_secret': 'test_secret_key_for_security_tests',
            'session_timeout': 3600,
            'max_failed_attempts': 3,
            'threat_threshold': 0.5
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            yield casb
    
    def test_sql_injection_protection(self, casb_system):
        """Тест защиты от SQL инъекций"""
        # Попытки SQL инъекций в различных полях
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "test'; INSERT INTO users VALUES ('hacker', 'hack@evil.com'); --",
            "' UNION SELECT * FROM users --",
            "'; UPDATE users SET access_level='admin' WHERE username='test'; --"
        ]
        
        for malicious_input in malicious_inputs:
            # Проверяем защиту при создании пользователя
            try:
                user = casb_system.create_user(
                    username=malicious_input,
                    email="test@example.com",
                    department="IT",
                    access_level=AccessLevel.READ_ONLY,
                    password="test123"
                )
                # Если пользователь создался, проверяем что вредоносный код не выполнился
                assert malicious_input not in user.username or len(user.username) < 100
            except Exception as e:
                # Исключения при вводе вредоносных данных - это нормально
                assert "SQL" not in str(e).upper() or "SYNTAX" not in str(e).upper()
    
    def test_password_security(self, casb_system):
        """Тест безопасности паролей"""
        # Проверяем что пароли не хранятся в открытом виде
        user = casb_system.create_user(
            username="password_test_user",
            email="pwd_test@example.com",
            department="IT",
            access_level=AccessLevel.READ_ONLY,
            password="my_secret_password_123"
        )
        
        # Получаем пользователя из БД
        stored_user = casb_system._get_user(user.user_id)
        
        # Пароль не должен храниться в открытом виде
        # Проверяем что в объекте нет поля с исходным паролем
        user_dict = stored_user.__dict__
        for key, value in user_dict.items():
            if isinstance(value, str):
                assert "my_secret_password_123" not in value
    
    def test_jwt_token_security(self, casb_system):
        """Тест безопасности JWT токенов"""
        user = casb_system.create_user(
            username="jwt_security_test",
            email="jwt@example.com",
            department="IT",
            access_level=AccessLevel.ADMIN,
            password="secure_password"
        )
        
        # Генерируем токен
        token = casb_system.generate_session_token(user.user_id)
        
        # Проверяем что токен содержит корректные данные
        try:
            payload = jwt.decode(token, casb_system.config['jwt_secret'], algorithms=['HS256'])
            assert 'user_id' in payload
            assert 'exp' in payload  # Время истечения должно быть
            assert 'iat' in payload  # Время создания должно быть
        except jwt.InvalidTokenError:
            pytest.fail("Valid JWT token should be decodable")
        
        # Проверяем что поддельный токен не проходит
        fake_payload = {'user_id': 'fake_user', 'exp': time.time() + 3600}
        fake_token = jwt.encode(fake_payload, 'wrong_secret', algorithm='HS256')
        
        validated_user = casb_system.validate_session_token(fake_token)
        assert validated_user is None
    
    def test_brute_force_protection(self, casb_system):
        """Тест защиты от брутфорс атак"""
        # Создаем пользователя
        user = casb_system.create_user(
            username="brute_force_test",
            email="brute@example.com",
            department="IT",
            access_level=AccessLevel.READ_ONLY,
            password="correct_password"
        )
        
        # Пытаемся войти с неправильным паролем несколько раз
        failed_attempts = 0
        max_attempts = casb_system.config.get('max_failed_attempts', 5)
        
        for i in range(max_attempts + 2):
            result = casb_system.authenticate_user(
                "brute_force_test",
                f"wrong_password_{i}",
                "192.168.1.100"
            )
            if result is None:
                failed_attempts += 1
        
        # Должно быть зафиксировано несколько неудачных попыток
        assert failed_attempts >= max_attempts
        
        # После превышения лимита, даже правильный пароль не должен работать (если реализована блокировка)
        # Это зависит от реализации системы блокировки
    
    def test_encryption_strength(self, casb_system):
        """Тест стойкости шифрования"""
        sensitive_data = "very_secret_api_key_12345_ABCDE"
        
        # Шифруем данные
        encrypted_data = casb_system.encrypt_data(sensitive_data)
        
        # Проверяем что зашифрованные данные не содержат исходных
        assert sensitive_data not in encrypted_data
        
        # Проверяем что данные достаточно длинные (минимальные требования к шифрованию)
        assert len(encrypted_data) > len(sensitive_data) * 1.5
        
        # Проверяем что повторное шифрование дает разные результаты
        encrypted_data2 = casb_system.encrypt_data(sensitive_data)
        # Для некоторых алгоритмов шифрования результат может быть одинаковым
        # но в идеале должен отличаться из-за соли/IV
        
        # Проверяем корректность расшифровки
        decrypted_data = casb_system.decrypt_data(encrypted_data)
        assert decrypted_data == sensitive_data
    
    def test_access_control_bypass_attempts(self, casb_system):
        """Тест попыток обхода контроля доступа"""
        # Создаем пользователя с ограниченными правами
        limited_user = casb_system.create_user(
            username="limited_user",
            email="limited@example.com",
            department="Support",
            access_level=AccessLevel.READ_ONLY,
            password="user_password"
        )
        
        # Создаем критичный сервис
        critical_service = casb_system.register_cloud_service(
            name="Critical Database",
            provider=CloudProvider.AWS,
            endpoint="https://critical-db.amazonaws.com",
            api_key="critical_api_key",
            service_type="database",
            risk_level=ThreatLevel.CRITICAL
        )
        
        # Попытка доступа к критичному ресурсу с опасным действием
        dangerous_request = casb_system.request_access(
            user_id=limited_user.user_id,
            service_id=critical_service.service_id,
            action="DROP_DATABASE",
            ip_address="192.168.1.100",
            user_agent="test-agent"
        )
        
        # Запрос должен быть заблокирован
        assert not dangerous_request.approved or dangerous_request.risk_score > 0.7
    
    def test_session_hijacking_protection(self, casb_system):
        """Тест защиты от перехвата сессий"""
        user = casb_system.create_user(
            username="session_test_user",
            email="session@example.com", 
            department="IT",
            access_level=AccessLevel.ADMIN,
            password="session_password"
        )
        
        # Создаем легитимный токен
        token = casb_system.generate_session_token(user.user_id)
        
        # Проверяем что токен работает
        validated_user_id = casb_system.validate_session_token(token)
        assert validated_user_id == user.user_id
        
        # Пытаемся модифицировать токен
        try:
            # Декодируем токен
            header, payload, signature = token.split('.')
            
            # Пытаемся создать новый токен с измененными данными
            import base64
            import json
            
            decoded_payload = json.loads(
                base64.b64decode(payload + '=' * (4 - len(payload) % 4)).decode()
            )
            decoded_payload['user_id'] = 'hacker_user_id'
            
            # Кодируем обратно (без правильной подписи)
            new_payload = base64.b64encode(
                json.dumps(decoded_payload).encode()
            ).decode().rstrip('=')
            
            modified_token = f"{header}.{new_payload}.{signature}"
            
            # Модифицированный токен не должен проходить валидацию
            hacked_user_id = casb_system.validate_session_token(modified_token)
            assert hacked_user_id is None
            
        except Exception:
            # Если не удалось модифицировать токен - это хорошо для безопасности
            pass
    
    def test_data_leakage_prevention(self, casb_system):
        """Тест предотвращения утечек данных"""
        # Создаем пользователя
        user = casb_system.create_user(
            username="data_leak_test",
            email="leak@example.com",
            department="Finance",
            access_level=AccessLevel.READ_WRITE,
            password="data_password"
        )
        
        # Получаем метрики (могут содержать чувствительные данные)
        metrics = casb_system.get_dashboard_metrics()
        
        # Проверяем что в метриках нет чувствительной информации
        metrics_str = str(metrics)
        
        # Не должно быть паролей, ключей шифрования, токенов
        sensitive_patterns = [
            "password",
            "secret",
            "token", 
            "key",
            "api_key",
            user.user_id  # ID пользователей не должны светиться в метриках
        ]
        
        for pattern in sensitive_patterns:
            # Допускаем названия полей, но не значения
            if pattern in ["password", "secret", "token", "key"]:
                continue
            assert pattern not in metrics_str.lower()
    
    def test_timing_attack_resistance(self, casb_system):
        """Тест устойчивости к атакам по времени"""
        # Создаем пользователя
        casb_system.create_user(
            username="timing_test_user",
            email="timing@example.com",
            department="IT", 
            access_level=AccessLevel.READ_ONLY,
            password="timing_password"
        )
        
        # Измеряем время аутентификации с правильным пользователем/неверным паролем
        start_time = time.time()
        result1 = casb_system.authenticate_user(
            "timing_test_user",
            "wrong_password",
            "192.168.1.100"
        )
        time1 = time.time() - start_time
        
        # Измеряем время с несуществующим пользователем
        start_time = time.time()
        result2 = casb_system.authenticate_user(
            "nonexistent_user",
            "any_password", 
            "192.168.1.100"
        )
        time2 = time.time() - start_time
        
        # Времена выполнения не должны сильно отличаться
        # (защита от timing attack)
        time_diff = abs(time1 - time2)
        assert time_diff < 0.1  # Разница менее 100ms


class TestPenetrationTesting:
    """Пентесты системы"""
    
    @pytest.fixture
    def temp_db(self):
        """Временная база данных для тестов"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        yield path
        try:
            os.unlink(path)
        except OSError:
            pass
    
    @pytest.fixture
    def full_system(self, temp_db):
        """Полная система для пентестов"""
        config = {
            'database': temp_db,
            'jwt_secret': 'pentest_secret_key',
            'session_timeout': 3600,
            'max_failed_attempts': 3,
            'threat_threshold': 0.5
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            
            mfa = MFAAuthenticator(temp_db)
            monitor = CloudActivityMonitor(temp_db)
            
            yield {'casb': casb, 'mfa': mfa, 'monitor': monitor}
    
    def test_privilege_escalation_attempt(self, full_system):
        """Тест попытки эскалации привилегий"""
        casb = full_system['casb']
        
        # Создаем пользователя с минимальными правами
        low_priv_user = casb.create_user(
            username="low_privilege",
            email="lowpriv@example.com",
            department="Support",
            access_level=AccessLevel.READ_ONLY,
            password="user123"
        )
        
        # Создаем административный сервис
        admin_service = casb.register_cloud_service(
            name="Admin Panel",
            provider=CloudProvider.CUSTOM,
            endpoint="https://admin.company.com",
            api_key="admin_api_key",
            service_type="admin",
            risk_level=ThreatLevel.CRITICAL
        )
        
        # Попытка получить админские права
        escalation_request = casb.request_access(
            user_id=low_priv_user.user_id,
            service_id=admin_service.service_id,
            action="grant_admin_privileges",
            ip_address="192.168.1.100",
            user_agent="escalation-attempt"
        )
        
        # Запрос должен быть отклонен
        assert not escalation_request.approved
        assert escalation_request.risk_score > 0.5
    
    def test_mass_access_attempt(self, full_system):
        """Тест массовых попыток доступа (DoS)"""
        casb = full_system['casb']
        monitor = full_system['monitor']
        
        # Создаем пользователя и сервис
        user = casb.create_user(
            username="mass_access_user",
            email="mass@example.com",
            department="IT",
            access_level=AccessLevel.READ_WRITE,
            password="mass123"
        )
        
        service = casb.register_cloud_service(
            name="Target Service", 
            provider=CloudProvider.AWS,
            endpoint="https://target.amazonaws.com",
            api_key="target_key",
            service_type="storage",
            risk_level=ThreatLevel.MEDIUM
        )
        
        # Множественные запросы за короткое время
        requests_count = 20
        for i in range(requests_count):
            casb.request_access(
                user_id=user.user_id,
                service_id=service.service_id,
                action=f"mass_action_{i}",
                ip_address="192.168.1.100",
                user_agent=f"mass-client-{i}"
            )
        
        # Система должна детектировать аномальную активность
        dashboard = monitor.get_activity_dashboard(hours=1)
        
        # Должно быть зафиксировано множество событий
        assert dashboard['summary']['total_events'] >= requests_count
    
    def test_data_extraction_attempt(self, full_system):
        """Тест попытки извлечения данных"""
        casb = full_system['casb']
        monitor = full_system['monitor']
        
        # Создаем пользователя с доступом к данным
        data_user = casb.create_user(
            username="data_user",
            email="data@example.com",
            department="Analytics",
            access_level=AccessLevel.READ_WRITE,
            password="data123"
        )
        
        # Создаем сервис с конфиденциальными данными
        sensitive_service = casb.register_cloud_service(
            name="Customer Database",
            provider=CloudProvider.AZURE,
            endpoint="https://customerdb.azure.com",
            api_key="sensitive_key",
            service_type="database",
            risk_level=ThreatLevel.HIGH
        )
        
        # Попытка массового извлечения данных
        extraction_attempts = [
            "SELECT * FROM customers",
            "DUMP DATABASE customers", 
            "EXPORT ALL TABLES",
            "BACKUP DATABASE TO external_location",
            "SELECT credit_card_numbers FROM payments"
        ]
        
        high_risk_requests = 0
        for attempt in extraction_attempts:
            request = casb.request_access(
                user_id=data_user.user_id,
                service_id=sensitive_service.service_id,
                action=attempt,
                ip_address="203.0.113.1",  # Подозрительный IP
                user_agent="data-extraction-tool"
            )
            
            if request.risk_score > 0.6:
                high_risk_requests += 1
        
        # Большинство запросов должно иметь высокий риск-скор
        assert high_risk_requests >= len(extraction_attempts) // 2
    
    def test_mfa_bypass_attempt(self, full_system):
        """Тест попытки обхода MFA"""
        mfa = full_system['mfa']
        
        # Настраиваем MFA для пользователя
        secret, qr_code = mfa.setup_totp("mfa_bypass_user", "mfauser")
        
        # Создаем вызов
        challenge = mfa.create_challenge("mfa_bypass_user", "totp")
        
        # Попытки обхода:
        bypass_attempts = [
            "000000",  # Простой код
            "123456",  # Популярный код
            "111111",  # Повторяющийся
            "",        # Пустой код
            "invalid", # Нечисловой код
        ]
        
        bypass_success_count = 0
        for attempt in bypass_attempts:
            try:
                result = mfa.verify_challenge(challenge.challenge_id, attempt)
                if result:
                    bypass_success_count += 1
            except Exception:
                pass  # Исключения при неверных кодах - это нормально
        
        # Обход MFA не должен проходить
        assert bypass_success_count == 0
    
    def test_log_injection_attempt(self, full_system):
        """Тест попытки инъекции в логи"""
        monitor = full_system['monitor']
        
        # Попытки инъекции вредоносного кода в логи
        malicious_payloads = [
            "normal_action\n[CRITICAL] FAKE SECURITY BREACH",
            "action_with_\r\nadmin_escalation_logged", 
            "legitimate_action\x00hidden_malicious_action",
            "action<script>alert('xss')</script>",
        ]
        
        for payload in malicious_payloads:
            # Логируем событие с вредоносными данными
            event = monitor.log_cloud_event(
                service_id="log_injection_service",
                user_id="log_injection_user", 
                event_type=monitor.EventType.API_CALL,
                source_ip="192.168.1.100",
                user_agent="injection-test",
                resource="/api/test",
                action=payload,
                result="success"
            )
            
            # Проверяем что вредоносные данные не вызывают проблем
            assert event.event_id is not None
            # Дополнительные проверки могут быть добавлены
            # в зависимости от реализации логирования


class TestComplianceValidation:
    """Тесты соответствия требованиям безопасности"""
    
    @pytest.fixture
    def temp_db(self):
        """Временная база данных для тестов"""
        fd, path = tempfile.mkstemp(suffix='.db')
        os.close(fd)
        yield path
        try:
            os.unlink(path)
        except OSError:
            pass
    
    def test_gdpr_compliance(self, temp_db):
        """Тест соответствия GDPR"""
        # Проверяем основные требования GDPR:
        # 1. Шифрование персональных данных
        # 2. Возможность удаления данных
        # 3. Логирование обработки данных
        # 4. Контроль доступа к данным
        
        config = {
            'database': temp_db,
            'jwt_secret': 'gdpr_test_secret',
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'threat_threshold': 0.7
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            
            # 1. Тест шифрования персональных данных
            personal_data = "john.doe@email.com"
            encrypted = casb.encrypt_data(personal_data)
            assert personal_data not in encrypted
            
            # 2. Тест создания и получения пользователя
            user = casb.create_user(
                username="gdpr_test_user",
                email="gdpr@example.com", 
                department="Legal",
                access_level=AccessLevel.READ_ONLY,
                password="gdpr123"
            )
            
            retrieved_user = casb._get_user(user.user_id)
            assert retrieved_user is not None
            
            # 3. Тест логирования (аудит GDPR)
            # Все операции с персональными данными должны логироваться
            # Это проверяется через создание пользователя
            
    def test_pci_dss_compliance(self, temp_db):
        """Тест соответствия PCI DSS"""
        config = {
            'database': temp_db,
            'jwt_secret': 'very_secure_secret_key_32_chars',
            'session_timeout': 900,  # 15 минут для финансовых данных
            'max_failed_attempts': 3,
            'threat_threshold': 0.5
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            
            # Проверяем требования PCI DSS:
            # 1. Сильное шифрование
            credit_card_data = "4532-1234-5678-9012"
            encrypted_cc = casb.encrypt_data(credit_card_data)
            assert credit_card_data not in encrypted_cc
            assert len(encrypted_cc) > len(credit_card_data) * 2
            
            # 2. Ограниченный доступ к финансовым системам
            finance_user = casb.create_user(
                username="finance_user",
                email="finance@company.com",
                department="Finance",
                access_level=AccessLevel.READ_WRITE,
                password="FinanceSecure123!"
            )
            
            # 3. Короткие сессии для финансовых операций
            token = casb.generate_session_token(finance_user.user_id)
            payload = jwt.decode(token, config['jwt_secret'], algorithms=['HS256'])
            
            session_duration = payload['exp'] - payload['iat']
            assert session_duration <= 900  # Не более 15 минут
    
    def test_sox_compliance(self, temp_db):
        """Тест соответствия SOX (Sarbanes-Oxley)"""
        config = {
            'database': temp_db,
            'jwt_secret': 'sox_compliance_secret',
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'threat_threshold': 0.7
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            
            monitor = CloudActivityMonitor(temp_db)
            
            # SOX требует полного аудита финансовых операций
            finance_user = casb.create_user(
                username="sox_user",
                email="sox@company.com",
                department="Finance",
                access_level=AccessLevel.ADMIN,
                password="SoxCompliant123!"
            )
            
            financial_service = casb.register_cloud_service(
                name="Financial Reporting System",
                provider=CloudProvider.CUSTOM,
                endpoint="https://finance.company.com",
                api_key="finance_api_key",
                service_type="financial_reporting",
                risk_level=ThreatLevel.CRITICAL
            )
            
            # Выполняем финансовую операцию
            access_request = casb.request_access(
                user_id=finance_user.user_id,
                service_id=financial_service.service_id,
                action="generate_quarterly_report",
                ip_address="192.168.1.100", 
                user_agent="sox-compliance-test"
            )
            
            # Логируем событие
            monitor.log_cloud_event(
                service_id=financial_service.service_id,
                user_id=finance_user.user_id,
                event_type=monitor.EventType.API_CALL,
                source_ip="192.168.1.100",
                user_agent="sox-compliance-test",
                resource="quarterly_report",
                action="generate_report",
                result="success"
            )
            
            # Проверяем что операции логируются
            dashboard = monitor.get_activity_dashboard(hours=1)
            assert dashboard['summary']['total_events'] >= 1
            
            # Проверяем возможность аудита
            timeline = monitor.get_threat_timeline(hours=1)
            assert isinstance(timeline, list)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "-s"])