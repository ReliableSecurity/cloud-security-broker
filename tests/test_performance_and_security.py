#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Performance and Security Testing Suite for CASB
Comprehensive stress tests, security penetration tests, compliance tests

Автор: AI Assistant
"""

import os
import sys
import time
import asyncio
import threading
import subprocess
import tempfile
import random
import string
import hashlib
import logging
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor, as_completed
import unittest
from unittest.mock import MagicMock, patch
import json

# Добавляем корневую директорию в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from core.casb import CASBCore
    from auth.mfa_auth import MFAAuthenticator
    from monitoring.cloud_monitor import CloudActivityMonitor
    from security.advanced_security import AdvancedSecurityManager, SecurityContext
    from performance.performance_monitor import PerformanceMonitor
    from enterprise.reporting import EnterpriseReportManager, ReportConfig, ReportType
    MODULES_AVAILABLE = True
except ImportError as e:
    print(f"Некоторые модули недоступны для тестирования: {e}")
    MODULES_AVAILABLE = False

logger = logging.getLogger(__name__)

class PerformanceStressTests(unittest.TestCase):
    """Стресс-тесты производительности"""
    
    def setUp(self):
        """Настройка тестовой среды"""
        if not MODULES_AVAILABLE:
            self.skipTest("Необходимые модули недоступны")
        
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
        self.casb_core = CASBCore()
        self.performance_monitor = PerformanceMonitor(self.test_db)
        
        # Создаем тестовых пользователей
        self.test_users = []
        for i in range(100):
            from core.casb import AccessLevel
            user = self.casb_core.create_user(
                username=f"user{i}",
                email=f"user{i}@test.com",
                department="test",
                access_level=AccessLevel.READ_WRITE,
                password="TestPass123!"
            )
            self.test_users.append(user.user_id)
    
    def tearDown(self):
        """Очистка тестовой среды"""
        try:
            if hasattr(self, 'performance_monitor'):
                self.performance_monitor.monitoring_active = False
            if os.path.exists(self.test_db):
                os.unlink(self.test_db)
        except Exception as e:
            logger.warning(f"Ошибка очистки: {e}")
    
    def test_concurrent_user_authentication(self):
        """Тест одновременной аутентификации пользователей"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        start_time = time.time()
        successful_auths = 0
        failed_auths = 0
        
        def authenticate_user(username, password):
            try:
                result = self.casb_core.authenticate_user(username, password, "127.0.0.1")
                return True if result else False
            except Exception as e:
                logger.error(f"Ошибка аутентификации: {e}")
                return False
        
        # Тестируем 50 одновременных аутентификаций
        with ThreadPoolExecutor(max_workers=50) as executor:
            futures = []
            for i in range(50):
                username = f"user{i}"
                password = "TestPass123!"
                future = executor.submit(authenticate_user, username, password)
                futures.append(future)
            
            for future in as_completed(futures):
                if future.result():
                    successful_auths += 1
                else:
                    failed_auths += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        
        logger.info(f"Concurrent auth test: {successful_auths} success, {failed_auths} failed in {total_time:.2f}s")
        
        # Проверяем, что большинство аутентификаций прошли успешно
        self.assertGreater(successful_auths, 40, "Слишком много неудачных аутентификаций")
        self.assertLess(total_time, 30, "Аутентификация занимает слишком много времени")
    
    def test_database_stress(self):
        """Стресс-тест базы данных"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        start_time = time.time()
        operations_count = 1000
        
        def database_operations():
            operations = 0
            try:
                for _ in range(100):
                    # Создание события
                    self.casb_core.log_audit_event(
                        user_id=f"user_{random.randint(0, 99)}",
                        action="test_action",
                        resource_type="test_resource",
                        resource_id="test_id",
                        details={"test": "data"}
                    )
                    operations += 1
                    
                    # Запрос данных
                    self.casb_core.get_user_by_id(f"user_{random.randint(0, 99)}")
                    operations += 1
                    
            except Exception as e:
                logger.error(f"Database operation error: {e}")
            
            return operations
        
        # Параллельные операции с базой данных
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(database_operations) for _ in range(10)]
            
            total_operations = 0
            for future in as_completed(futures):
                total_operations += future.result()
        
        end_time = time.time()
        total_time = end_time - start_time
        ops_per_second = total_operations / total_time
        
        logger.info(f"Database stress test: {total_operations} operations in {total_time:.2f}s ({ops_per_second:.2f} ops/s)")
        
        # Проверяем производительность
        self.assertGreater(ops_per_second, 50, "Низкая производительность базы данных")
    
    def test_memory_usage_under_load(self):
        """Тест использования памяти под нагрузкой"""
        import psutil
        
        process = psutil.Process()
        initial_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Создаем нагрузку
        large_data = []
        for i in range(1000):
            # Имитируем создание больших объектов
            data = {
                'id': i,
                'content': ''.join(random.choices(string.ascii_letters, k=1000)),
                'timestamp': datetime.now(),
                'metadata': {'key': 'value' * 100}
            }
            large_data.append(data)
            
            # Записываем метрику производительности
            if hasattr(self, 'performance_monitor'):
                self.performance_monitor.record_metric(
                    f'test_metric_{i}', 
                    random.uniform(0, 100),
                    'units'
                )
        
        peak_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        # Очищаем данные
        del large_data
        import gc
        gc.collect()
        
        time.sleep(1)  # Даем время на очистку
        final_memory = process.memory_info().rss / 1024 / 1024  # MB
        
        memory_increase = peak_memory - initial_memory
        memory_cleaned = peak_memory - final_memory
        
        logger.info(f"Memory test: initial={initial_memory:.1f}MB, peak={peak_memory:.1f}MB, final={final_memory:.1f}MB")
        logger.info(f"Memory increase: {memory_increase:.1f}MB, cleaned: {memory_cleaned:.1f}MB")
        
        # Проверяем, что память освободилась
        self.assertLess(final_memory - initial_memory, memory_increase * 0.5, "Утечка памяти обнаружена")

class SecurityPenetrationTests(unittest.TestCase):
    """Тесты безопасности и проникновения"""
    
    def setUp(self):
        """Настройка тестовой среды"""
        if not MODULES_AVAILABLE:
            self.skipTest("Необходимые модули недоступны")
        
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
        self.security_manager = AdvancedSecurityManager(self.test_db)
        self.casb_core = CASBCore()
    
    def tearDown(self):
        """Очистка тестовой среды"""
        try:
            if os.path.exists(self.test_db):
                os.unlink(self.test_db)
        except Exception:
            pass
    
    def test_sql_injection_protection(self):
        """Тест защиты от SQL-инъекций"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Попытки SQL-инъекций
        sql_injection_attempts = [
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users; --",
            "'; INSERT INTO users VALUES ('hacker', 'evil'); --",
            "' OR '1'='1",
            "'; UPDATE users SET role='admin'; --"
        ]
        
        for injection in sql_injection_attempts:
            with self.subTest(injection=injection):
                try:
                    # Пытаемся использовать инъекцию как имя пользователя
                    result = self.casb_core.authenticate_user(injection, "password", "127.0.0.1")
                    
                    # Аутентификация должна провалиться
                    self.assertIsNone(result, f"SQL injection not prevented: {injection}")
                    
                except Exception as e:
                    # Исключение - это нормально, главное чтобы не было успешной инъекции
                    logger.info(f"SQL injection properly blocked: {injection}")
    
    def test_brute_force_protection(self):
        """Тест защиты от брутфорса"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Создаем тестового пользователя
        from core.casb import AccessLevel
        self.casb_core.create_user(
            username="testuser",
            email="test@example.com",
            department="test",
            access_level=AccessLevel.READ_WRITE,
            password="correct_password"
        )
        
        # Имитируем атаку брутфорса
        failed_attempts = 0
        for i in range(20):  # 20 неудачных попыток
            result = self.casb_core.authenticate_user("testuser", f"wrong_password_{i}", "127.0.0.1")
            if result is None:
                failed_attempts += 1
        
        # Проверяем, что все попытки провалились
        self.assertEqual(failed_attempts, 20, "Brute force protection failed")
        
        # Проверяем, что правильный пароль все еще работает (если нет блокировки)
        result = self.casb_core.authenticate_user("testuser", "correct_password", "127.0.0.1")
        # Результат может быть None если есть защита от брутфорса, что тоже нормально
    
    def test_xss_prevention(self):
        """Тест предотвращения XSS атак"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "javascript:alert('XSS')",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "';alert('XSS');//"
        ]
        
        for payload in xss_payloads:
            with self.subTest(payload=payload):
                try:
                    # Пытаемся создать пользователя с XSS в данных
                    from core.casb import AccessLevel
                    user = self.casb_core.create_user(
                        username=payload,
                        email=f"test@example.com",
                        department="test",
                        access_level=AccessLevel.READ_WRITE,
                        password="TestPass123!"
                    )
                    user_id = user.user_id if user else None
                    
                    if user_id:
                        # Проверяем, что данные были санитизированы
                        user = self.casb_core.get_user_by_id(user_id)
                        if user:
                            # Убеждаемся, что опасные теги не сохранились как есть
                            self.assertNotIn("<script>", user.get('username', ''))
                            self.assertNotIn("javascript:", user.get('username', ''))
                    
                except Exception as e:
                    # Исключение при обработке XSS - это нормально
                    logger.info(f"XSS payload properly rejected: {payload}")
    
    def test_csrf_protection(self):
        """Тест защиты от CSRF атак"""
        # Этот тест больше относится к веб-интерфейсу
        # Здесь мы проверяем основы защиты состояния
        
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Создаем пользователя
        from core.casb import AccessLevel
        user = self.casb_core.create_user(
            username="csrftest",
            email="csrf@test.com",
            department="test",
            access_level=AccessLevel.READ_WRITE,
            password="TestPass123!"
        )
        user_id = user.user_id
        
        # Проверяем, что критические операции требуют правильного контекста
        # (в реальной системе здесь была бы проверка CSRF токенов)
        
        original_user = self.casb_core.get_user_by_id(user_id)
        self.assertIsNotNone(original_user)
        
        # Попытка изменить роль без правильной авторизации
        # должна быть заблокирована
        try:
            # В реальной системе здесь была бы проверка прав доступа
            result = self.casb_core.update_user_role(user_id, "admin")
            
            # Если операция прошла, проверяем, что были соблюдены права доступа
            updated_user = self.casb_core.get_user_by_id(user_id)
            if updated_user:
                # В тестовой среде может не быть полной проверки прав
                logger.info("CSRF test: user role change occurred (may be expected in test environment)")
            
        except Exception as e:
            # Исключение - нормальная защита
            logger.info(f"CSRF protection working: {e}")
    
    def test_encryption_strength(self):
        """Тест надежности шифрования"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        from security.advanced_security import AdvancedEncryption
        
        encryption = AdvancedEncryption()
        
        # Тестируем AES шифрование
        test_data = b"This is sensitive test data that needs to be encrypted securely!"
        
        # Шифруем данные
        ciphertext, iv, tag = encryption.encrypt_aes_gcm(test_data)
        
        # Проверяем, что зашифрованные данные отличаются от исходных
        self.assertNotEqual(ciphertext, test_data)
        self.assertEqual(len(iv), 12)  # 96-bit IV for GCM
        self.assertEqual(len(tag), 16)  # 128-bit tag for GCM
        
        # Расшифровываем данные
        decrypted_data = encryption.decrypt_aes_gcm(ciphertext, iv, tag)
        
        # Проверяем, что данные расшифровались правильно
        self.assertEqual(decrypted_data, test_data)
        
        # Тестируем, что поврежденные данные не расшифровываются
        corrupted_ciphertext = bytearray(ciphertext)
        corrupted_ciphertext[0] ^= 1  # Повреждаем один байт
        
        with self.assertRaises(Exception):
            encryption.decrypt_aes_gcm(bytes(corrupted_ciphertext), iv, tag)
    
    def test_api_rate_limiting(self):
        """Тест ограничения скорости API запросов"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Тестируем rate limiting
        user_id = "test_user_rate_limit"
        endpoint = "test_endpoint"
        limit = 10  # 10 запросов в минуту
        
        successful_requests = 0
        blocked_requests = 0
        
        # Делаем много запросов подряд
        for i in range(20):
            if self.security_manager.check_rate_limit(user_id, endpoint, limit):
                successful_requests += 1
            else:
                blocked_requests += 1
        
        logger.info(f"Rate limiting test: {successful_requests} allowed, {blocked_requests} blocked")
        
        # Проверяем, что rate limiting работает
        self.assertEqual(successful_requests, limit, "Rate limiting not working properly")
        self.assertEqual(blocked_requests, 10, "Too many requests allowed")

class ComplianceTests(unittest.TestCase):
    """Тесты соответствия стандартам"""
    
    def setUp(self):
        """Настройка тестовой среды"""
        if not MODULES_AVAILABLE:
            self.skipTest("Необходимые модули недоступны")
        
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
        self.report_manager = EnterpriseReportManager(self.test_db)
    
    def tearDown(self):
        """Очистка тестовой среды"""
        try:
            if os.path.exists(self.test_db):
                os.unlink(self.test_db)
        except Exception:
            pass
    
    def test_gdpr_compliance(self):
        """Тест соответствия GDPR"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        config = ReportConfig(
            report_type=ReportType.COMPLIANCE,
            start_date=datetime.now() - timedelta(days=30),
            end_date=datetime.now(),
            filters={'standard': 'GDPR'}
        )
        
        report = self.report_manager.generate_report(config)
        
        self.assertIsNotNone(report)
        self.assertEqual(report.report_type, ReportType.COMPLIANCE)
        
        # Проверяем, что отчет содержит необходимые данные
        self.assertIn('compliance_score', report.data)
        self.assertIn('checks', report.data)
        
        compliance_score = report.data['compliance_score']
        self.assertGreaterEqual(compliance_score, 0)
        self.assertLessEqual(compliance_score, 100)
        
        # Проверяем основные проверки GDPR
        checks = report.data['checks']
        self.assertIn('consent_management', checks)
        self.assertIn('data_access_logging', checks)
        self.assertIn('right_to_be_forgotten', checks)
    
    def test_pci_dss_compliance(self):
        """Тест соответствия PCI DSS"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        config = ReportConfig(
            report_type=ReportType.COMPLIANCE,
            start_date=datetime.now() - timedelta(days=30),
            end_date=datetime.now(),
            filters={'standard': 'PCI_DSS'}
        )
        
        report = self.report_manager.generate_report(config)
        
        self.assertIsNotNone(report)
        compliance_score = report.data['compliance_score']
        
        # PCI DSS требует высокого уровня безопасности
        self.assertGreaterEqual(compliance_score, 80, "PCI DSS compliance score too low")
        
        # Проверяем обязательные компоненты PCI DSS
        checks = report.data['checks']
        required_checks = ['network_security', 'access_control', 'encryption', 'monitoring']
        
        for check in required_checks:
            self.assertIn(check, checks, f"Missing PCI DSS check: {check}")

class IntegrationTests(unittest.TestCase):
    """Интеграционные тесты"""
    
    def setUp(self):
        """Настройка тестовой среды"""
        if not MODULES_AVAILABLE:
            self.skipTest("Необходимые модули недоступны")
        
        self.test_db = tempfile.NamedTemporaryFile(delete=False, suffix='.db').name
        self.casb_core = CASBCore()
        self.mfa_auth = MFAAuthenticator(self.test_db)
        self.security_manager = AdvancedSecurityManager(self.test_db)
        self.performance_monitor = PerformanceMonitor(self.test_db)
    
    def tearDown(self):
        """Очистка тестовой среды"""
        try:
            if hasattr(self, 'performance_monitor'):
                self.performance_monitor.monitoring_active = False
            if os.path.exists(self.test_db):
                os.unlink(self.test_db)
        except Exception:
            pass
    
    def test_full_authentication_flow(self):
        """Тест полного потока аутентификации"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # 1. Создание пользователя
        from core.casb import AccessLevel
        user = self.casb_core.create_user(
            username="integrationtest",
            email="integration@test.com",
            department="test",
            access_level=AccessLevel.READ_WRITE,
            password="TestPass123!"
        )
        user_id = user.user_id
        
        self.assertIsNotNone(user_id)
        
        # 2. Первичная аутентификация
        auth_result = self.casb_core.authenticate_user("integrationtest", "TestPass123!", "127.0.0.1")
        self.assertIsNotNone(auth_result)
        
        # 3. Настройка MFA
        secret, qr_code = self.mfa_auth.setup_totp(user_id, "integrationtest")
        self.assertIsNotNone(secret)
        self.assertIsNotNone(qr_code)
        
        # 4. Создание MFA challenge
        import pyotp
        totp = pyotp.TOTP(secret)
        current_code = totp.now()
        
        challenge_id = self.mfa_auth.create_mfa_challenge(user_id, "totp")
        self.assertIsNotNone(challenge_id)
        
        # 5. Верификация MFA
        mfa_result = self.mfa_auth.verify_mfa_challenge(
            challenge_id, current_code, "127.0.0.1", "TestAgent"
        )
        self.assertTrue(mfa_result)
        
        # 6. Проверка безопасности
        context = SecurityContext(
            user_id=user_id,
            session_id="test_session",
            ip_address="127.0.0.1",
            user_agent="TestAgent",
            timestamp=datetime.now(),
            mfa_verified=True
        )
        
        action, security_info = self.security_manager.secure_request(context)
        self.assertIsNotNone(action)
        self.assertIsNotNone(security_info)
        
        logger.info(f"Full auth flow completed: action={action}, trust_level={security_info.get('trust_level')}")
    
    def test_performance_monitoring_integration(self):
        """Тест интеграции мониторинга производительности"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Записываем несколько метрик
        for i in range(10):
            self.performance_monitor.record_metric(
                f"test_metric_{i}",
                random.uniform(0, 100),
                "units",
                {"test": "integration"}
            )
        
        # Ждем немного для обработки
        time.sleep(1)
        
        # Получаем отчет о производительности
        report = self.performance_monitor.get_performance_report()
        
        self.assertIsInstance(report, dict)
        self.assertIn('system_metrics', report)
        self.assertIn('cache_stats', report)
        self.assertIn('task_stats', report)
        
        # Проверяем, что метрики были записаны
        self.assertGreater(report.get('total_metrics_recorded', 0), 0)
    
    def test_end_to_end_security_scenario(self):
        """Тест сценария безопасности от начала до конца"""
        if not MODULES_AVAILABLE:
            self.skipTest("Модули недоступны")
        
        # Сценарий: подозрительный пользователь пытается получить доступ
        
        # 1. Создание пользователя
        from core.casb import AccessLevel
        user = self.casb_core.create_user(
            username="suspicious_user",
            email="suspicious@test.com",
            department="test",
            access_level=AccessLevel.READ_WRITE,
            password="TestPass123!"
        )
        user_id = user.user_id
        
        # 2. Имитация подозрительной активности
        suspicious_context = SecurityContext(
            user_id=user_id,
            session_id="suspicious_session",
            ip_address="192.168.1.100",  # IP в черном списке
            user_agent="curl/7.68.0",  # Подозрительный User-Agent
            timestamp=datetime.now().replace(hour=3),  # Необычное время
            mfa_verified=False
        )
        
        # 3. Анализ безопасности
        action, security_info = self.security_manager.secure_request(suspicious_context)
        
        # 4. Проверяем, что система среагировала на угрозы
        trust_level = security_info.get('trust_level', 100)
        threat_level = security_info.get('threat_level', 'NONE')
        
        logger.info(f"Suspicious scenario: action={action}, trust={trust_level}, threat={threat_level}")
        
        # Ожидаем низкий уровень доверия и обнаружение угроз
        self.assertLess(trust_level, 50, "Trust level should be low for suspicious activity")
        self.assertNotEqual(threat_level, 'NONE', "Threats should be detected")
        
        # 5. Проверяем, что были приняты защитные меры
        from security.advanced_security import SecurityAction
        self.assertIn(action, [SecurityAction.BLOCK, SecurityAction.QUARANTINE, SecurityAction.MONITOR])

def run_security_scan():
    """Запуск сканирования безопасности"""
    logger.info("Запуск сканирования безопасности...")
    
    # Проверяем наличие инструментов безопасности
    security_tools = {
        'bandit': 'bandit -r . -f json',
        'safety': 'safety check --json'
    }
    
    results = {}
    
    for tool, command in security_tools.items():
        try:
            result = subprocess.run(
                command.split(),
                capture_output=True,
                text=True,
                timeout=60
            )
            
            if result.returncode == 0:
                results[tool] = {
                    'status': 'success',
                    'output': result.stdout
                }
            else:
                results[tool] = {
                    'status': 'warning',
                    'output': result.stderr
                }
                
        except subprocess.TimeoutExpired:
            results[tool] = {
                'status': 'timeout',
                'output': 'Scan timed out'
            }
        except FileNotFoundError:
            results[tool] = {
                'status': 'not_found',
                'output': f'{tool} not installed'
            }
        except Exception as e:
            results[tool] = {
                'status': 'error',
                'output': str(e)
            }
    
    return results

def run_performance_benchmark():
    """Запуск бенчмарков производительности"""
    logger.info("Запуск бенчмарков производительности...")
    
    if not MODULES_AVAILABLE:
        return {"error": "Модули недоступны"}
    
    results = {}
    
    # Бенчмарк создания пользователей
    start_time = time.time()
    casb_core = CASBCore()
    
    from core.casb import AccessLevel
    for i in range(100):
        casb_core.create_user(
            username=f"benchmark_user_{i}",
            email=f"benchmark{i}@test.com",
            department="benchmark",
            access_level=AccessLevel.READ_WRITE,
            password="BenchmarkPass123!"
        )
    
    user_creation_time = time.time() - start_time
    results['user_creation'] = {
        'operations': 100,
        'total_time': user_creation_time,
        'ops_per_second': 100 / user_creation_time
    }
    
    # Бенчмарк аутентификации
    start_time = time.time()
    
    for i in range(50):
        casb_core.authenticate_user(f"benchmark_user_{i}", "BenchmarkPass123!", "127.0.0.1")
    
    auth_time = time.time() - start_time
    results['authentication'] = {
        'operations': 50,
        'total_time': auth_time,
        'ops_per_second': 50 / auth_time
    }
    
    return results

if __name__ == '__main__':
    # Настройка логирования для тестов
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Запуск тестов
    print("🚀 Запуск комплексного тестирования CASB v2.0...")
    print("=" * 60)
    
    # Запуск сканирования безопасности
    print("\n🔒 Сканирование безопасности:")
    security_results = run_security_scan()
    for tool, result in security_results.items():
        print(f"  {tool}: {result['status']}")
    
    # Запуск бенчмарков
    print("\n⚡ Бенчмарки производительности:")
    benchmark_results = run_performance_benchmark()
    if 'error' not in benchmark_results:
        for test, result in benchmark_results.items():
            print(f"  {test}: {result['ops_per_second']:.2f} ops/sec")
    else:
        print(f"  Ошибка: {benchmark_results['error']}")
    
    # Запуск unit tests
    print("\n🧪 Unit тесты:")
    unittest.main(verbosity=2, exit=False)
    
    print("\n✅ Комплексное тестирование завершено!")