#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Тесты для основной функциональности CASB системы
"""

import pytest
import tempfile
import os
import sys
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.casb import CASBCore, AccessLevel, CloudProvider, ThreatLevel, User, CloudService, AccessRequest
from auth.mfa_auth import MFAAuthenticator
from monitoring.cloud_monitor import CloudActivityMonitor, EventType, Severity
from policies.policy_engine import PolicyEngine

class TestCASBCore:
    """Тесты для CASBCore"""
    
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
    def casb_core(self, temp_db):
        """CASB система для тестов"""
        # Создаем минимальную конфигурацию
        config = {
            'database': temp_db,
            'jwt_secret': 'test_secret',
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'threat_threshold': 0.7
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            yield casb
    
    def test_create_user(self, casb_core):
        """Тест создания пользователя"""
        user = casb_core.create_user(
            username="test_user",
            email="test@example.com",
            department="IT",
            access_level=AccessLevel.READ_WRITE,
            password="test_password"
        )
        
        assert user.username == "test_user"
        assert user.email == "test@example.com"
        assert user.department == "IT"
        assert user.access_level == AccessLevel.READ_WRITE
        assert user.user_id is not None
    
    def test_authenticate_user(self, casb_core):
        """Тест аутентификации пользователя"""
        # Создаем пользователя
        user = casb_core.create_user(
            username="auth_test_user",
            email="auth_test@example.com", 
            department="IT",
            access_level=AccessLevel.ADMIN,
            password="test_password"
        )
        
        # Успешная аутентификация
        token = casb_core.authenticate_user("auth_test_user", "test_password", "127.0.0.1")
        assert token is not None
        
        # Неверный пароль
        token = casb_core.authenticate_user("auth_test_user", "wrong_password", "127.0.0.1")
        assert token is None
    
    def test_register_cloud_service(self, casb_core):
        """Тест регистрации облачного сервиса"""
        service = casb_core.register_cloud_service(
            name="Test Storage",
            provider=CloudProvider.AWS,
            endpoint="https://s3.amazonaws.com",
            api_key="test_api_key",
            service_type="storage",
            risk_level=ThreatLevel.MEDIUM
        )
        
        assert service.name == "Test Storage"
        assert service.provider == CloudProvider.AWS
        assert service.service_type == "storage"
        assert service.risk_level == ThreatLevel.MEDIUM
        assert service.service_id is not None
    
    def test_access_request_evaluation(self, casb_core):
        """Тест оценки запроса доступа"""
        # Создаем пользователя и сервис
        user = casb_core.create_user(
            username="access_test_user",
            email="access_test@example.com",
            department="IT", 
            access_level=AccessLevel.READ_WRITE,
            password="test_password"
        )
        
        service = casb_core.register_cloud_service(
            name="Test Service",
            provider=CloudProvider.AWS,
            endpoint="https://test.amazonaws.com",
            api_key="test_key",
            service_type="compute",
            risk_level=ThreatLevel.LOW
        )
        
        # Запрос доступа
        request = casb_core.request_access(
            user_id=user.user_id,
            service_id=service.service_id,
            action="read_files",
            ip_address="192.168.1.100",
            user_agent="test-agent"
        )
        
        assert request.user_id == user.user_id
        assert request.service_id == service.service_id
        assert request.requested_action == "read_files"
        assert request.risk_score >= 0.0
        assert request.risk_score <= 1.0
    
    def test_risk_score_calculation(self, casb_core):
        """Тест расчета риск-скора"""
        # Создаем пользователя и критичный сервис
        user = casb_core.create_user(
            username="risk_test_user",
            email="risk_test@example.com",
            department="Finance",
            access_level=AccessLevel.READ_WRITE,
            password="test_password"
        )
        
        critical_service = casb_core.register_cloud_service(
            name="Critical Service",
            provider=CloudProvider.AWS,
            endpoint="https://critical.amazonaws.com",
            api_key="critical_key",
            service_type="database",
            risk_level=ThreatLevel.CRITICAL
        )
        
        # Опасное действие в нерабочее время
        dangerous_request = casb_core.request_access(
            user_id=user.user_id,
            service_id=critical_service.service_id,
            action="delete_database",
            ip_address="203.0.113.1",  # Неизвестный IP
            user_agent="suspicious-agent"
        )
        
        # Риск-скор должен быть высоким
        assert dangerous_request.risk_score > 0.5
    
    def test_jwt_token_validation(self, casb_core):
        """Тест валидации JWT токенов"""
        # Создаем пользователя
        user = casb_core.create_user(
            username="jwt_test_user",
            email="jwt_test@example.com",
            department="IT",
            access_level=AccessLevel.ADMIN,
            password="test_password"
        )
        
        # Генерируем токен
        token = casb_core.generate_session_token(user.user_id)
        assert token is not None
        
        # Валидация токена
        validated_user_id = casb_core.validate_session_token(token)
        assert validated_user_id == user.user_id
        
        # Проверка невалидного токена
        invalid_user_id = casb_core.validate_session_token("invalid_token")
        assert invalid_user_id is None
    
    def test_encryption_decryption(self, casb_core):
        """Тест шифрования и расшифровки данных"""
        test_data = "sensitive_api_key_12345"
        
        # Шифрование
        encrypted_data = casb_core.encrypt_data(test_data)
        assert encrypted_data != test_data
        assert len(encrypted_data) > len(test_data)
        
        # Расшифровка
        decrypted_data = casb_core.decrypt_data(encrypted_data)
        assert decrypted_data == test_data
    
    def test_dashboard_metrics(self, casb_core):
        """Тест получения метрик дашборда"""
        metrics = casb_core.get_dashboard_metrics()
        
        assert 'metrics' in metrics
        assert 'last_24h' in metrics
        assert 'summary' in metrics
        
        # Проверяем наличие ключевых метрик
        assert 'requests' in metrics['last_24h']
        assert 'blocked' in metrics['last_24h']
        assert 'threats' in metrics['last_24h']
    
    def test_threat_analysis(self, casb_core):
        """Тест анализа угроз"""
        analysis = casb_core.get_threat_analysis(days=7)
        
        assert 'period_days' in analysis
        assert 'top_threat_ips' in analysis
        assert 'top_blocked_actions' in analysis
        assert analysis['period_days'] == 7


class TestMFAAuthenticator:
    """Тесты для MFA аутентификации"""
    
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
    def mfa_auth(self, temp_db):
        """MFA аутентификатор для тестов"""
        return MFAAuthenticator(temp_db)
    
    def test_setup_totp(self, mfa_auth):
        """Тест настройки TOTP"""
        secret, qr_code = mfa_auth.setup_totp("test_user", "testuser")
        
        assert secret is not None
        assert len(secret) == 32  # Base32 secret
        assert qr_code is not None
        assert len(qr_code) > 100  # Base64 QR code
    
    def test_setup_sms(self, mfa_auth):
        """Тест настройки SMS"""
        method_id = mfa_auth.setup_sms("test_user", "+1234567890")
        
        assert method_id is not None
        assert len(method_id) == 16
    
    def test_setup_email(self, mfa_auth):
        """Тест настройки Email"""
        method_id = mfa_auth.setup_email("test_user", "test@example.com")
        
        assert method_id is not None
        assert len(method_id) == 16
    
    def test_create_challenge(self, mfa_auth):
        """Тест создания MFA вызова"""
        # Сначала настраиваем TOTP
        mfa_auth.setup_totp("challenge_user", "challengeuser")
        
        # Создаем вызов
        challenge = mfa_auth.create_challenge("challenge_user", "totp")
        
        assert challenge is not None
        assert challenge.user_id == "challenge_user"
        assert challenge.method_type == "totp"
        assert challenge.challenge_id is not None
    
    @patch('pyotp.TOTP.verify')
    def test_verify_totp_challenge(self, mock_verify, mfa_auth):
        """Тест верификации TOTP кода"""
        # Настраиваем TOTP
        mfa_auth.setup_totp("verify_user", "verifyuser")
        
        # Создаем вызов
        challenge = mfa_auth.create_challenge("verify_user", "totp")
        
        # Мокаем успешную верификацию
        mock_verify.return_value = True
        
        # Проверяем код
        result = mfa_auth.verify_challenge(challenge.challenge_id, "123456")
        
        assert result is True
        mock_verify.assert_called_once_with("123456", valid_window=1)
    
    def test_backup_codes(self, mfa_auth):
        """Тест резервных кодов"""
        codes = mfa_auth.generate_backup_codes("backup_user", count=5)
        
        assert len(codes) == 5
        assert all(len(code) == 8 for code in codes)
        assert all(code.isalnum() for code in codes)
    
    def test_mfa_statistics(self, mfa_auth):
        """Тест статистики MFA"""
        stats = mfa_auth.get_mfa_statistics(days=7)
        
        assert 'period_days' in stats
        assert 'total_attempts' in stats
        assert 'successful_attempts' in stats
        assert 'success_rate' in stats
        assert 'method_usage' in stats


class TestCloudActivityMonitor:
    """Тесты для мониторинга облачных активностей"""
    
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
    def monitor(self, temp_db):
        """Монитор активности для тестов"""
        config = {'monitoring_interval': 1, 'retention_days': 7}
        monitor = CloudActivityMonitor(temp_db, config)
        yield monitor
        monitor.stop_monitoring()
    
    def test_log_cloud_event(self, monitor):
        """Тест логирования облачного события"""
        event = monitor.log_cloud_event(
            service_id="test_service",
            user_id="test_user",
            event_type=EventType.FILE_UPLOAD,
            source_ip="192.168.1.100",
            user_agent="test-agent",
            resource="/test/file.txt",
            action="upload",
            result="success"
        )
        
        assert event.service_id == "test_service"
        assert event.user_id == "test_user"
        assert event.event_type == EventType.FILE_UPLOAD
        assert event.event_id is not None
    
    def test_alert_rule_creation(self, monitor):
        """Тест создания правил оповещений"""
        rule = monitor.create_alert_rule(
            name="Test Alert Rule",
            description="Test description",
            conditions={"event_type": "login", "result": "failed", "count_threshold": 3},
            severity=Severity.WARNING
        )
        
        assert rule.name == "Test Alert Rule"
        assert rule.severity == Severity.WARNING
        assert rule.rule_id is not None
    
    def test_activity_dashboard(self, monitor):
        """Тест получения дашборда активности"""
        # Логируем несколько событий
        for i in range(5):
            monitor.log_cloud_event(
                service_id="test_service",
                user_id=f"user_{i}",
                event_type=EventType.FILE_ACCESS,
                source_ip="192.168.1.100",
                user_agent="test-agent",
                resource=f"/test/file_{i}.txt",
                action="read",
                result="success"
            )
        
        dashboard = monitor.get_activity_dashboard(hours=24)
        
        assert 'summary' in dashboard
        assert 'events_by_type' in dashboard
        assert 'events_by_severity' in dashboard
        assert dashboard['summary']['total_events'] >= 5
    
    def test_threat_timeline(self, monitor):
        """Тест временной линии угроз"""
        # Логируем событие с высокой серьезностью
        monitor.log_cloud_event(
            service_id="critical_service",
            user_id="suspicious_user",
            event_type=EventType.FILE_DELETE,
            source_ip="203.0.113.1",
            user_agent="suspicious-agent",
            resource="/critical/data.txt",
            action="delete",
            result="success"
        )
        
        timeline = monitor.get_threat_timeline(hours=24)
        
        assert isinstance(timeline, list)
        # Должно быть хотя бы одно событие с высокой серьезностью
        threat_events = [e for e in timeline if e['severity'] in ['error', 'critical']]
        assert len(threat_events) >= 1


class TestPolicyEngine:
    """Тесты для движка политик"""
    
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
    def policy_engine(self, temp_db):
        """Движок политик для тестов"""
        return PolicyEngine(temp_db)
    
    def test_policy_statistics(self, policy_engine):
        """Тест получения статистики политик"""
        stats = policy_engine.get_policy_statistics(days=7)
        
        assert 'period_days' in stats
        assert 'total_evaluations' in stats
        assert 'action_statistics' in stats
        assert 'top_policies' in stats
        assert 'active_policies_count' in stats


class TestIntegration:
    """Интеграционные тесты"""
    
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
    
    def test_full_access_flow(self, temp_db):
        """Тест полного потока доступа"""
        # Инициализация компонентов
        config = {
            'database': temp_db,
            'jwt_secret': 'test_secret',
            'session_timeout': 3600,
            'max_failed_attempts': 5,
            'threat_threshold': 0.7
        }
        
        with patch('core.casb.CASBCore._load_config', return_value=config):
            casb = CASBCore()
            casb.db_path = temp_db
            casb.config = config
            casb._init_database()
            
            mfa = MFAAuthenticator(temp_db)
            monitor = CloudActivityMonitor(temp_db)
        
        try:
            # 1. Создание пользователя
            user = casb.create_user(
                username="integration_user",
                email="integration@example.com",
                department="IT",
                access_level=AccessLevel.ADMIN,
                password="test_password"
            )
            
            # 2. Регистрация сервиса
            service = casb.register_cloud_service(
                name="Integration Service",
                provider=CloudProvider.AWS,
                endpoint="https://integration.amazonaws.com",
                api_key="integration_key",
                service_type="compute",
                risk_level=ThreatLevel.MEDIUM
            )
            
            # 3. Настройка MFA
            secret, qr_code = mfa.setup_totp(user.user_id, user.username)
            assert secret is not None
            
            # 4. Запрос доступа
            access_request = casb.request_access(
                user_id=user.user_id,
                service_id=service.service_id,
                action="create_instance",
                ip_address="192.168.1.100",
                user_agent="integration-test"
            )
            
            # 5. Логирование события
            event = monitor.log_cloud_event(
                service_id=service.service_id,
                user_id=user.user_id,
                event_type=EventType.RESOURCE_CREATE,
                source_ip="192.168.1.100",
                user_agent="integration-test",
                resource="i-1234567890abcdef0",
                action="create_instance",
                result="success"
            )
            
            # Проверяем, что все компоненты работают вместе
            assert user.user_id is not None
            assert service.service_id is not None
            assert access_request.request_id is not None
            assert event.event_id is not None
            
        finally:
            if 'monitor' in locals():
                monitor.stop_monitoring()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])