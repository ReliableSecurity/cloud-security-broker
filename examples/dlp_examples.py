#!/usr/bin/env python3
"""
Подробные примеры использования модуля DLP (Data Loss Prevention)
Демонстрирует различные сценарии защиты данных
"""

import sys
import os
import json
import tempfile
from datetime import datetime, timedelta

# Добавляем путь к модулям
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from dlp.data_loss_prevention import DLPEngine

def setup_logging():
    """Настройка логирования"""
    import logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    return logging.getLogger(__name__)

def create_test_files():
    """Создание тестовых файлов для демонстрации"""
    logger = setup_logging()
    
    # Создание временной директории
    test_dir = tempfile.mkdtemp(prefix="dlp_test_")
    logger.info(f"Созданы тестовые файлы в: {test_dir}")
    
    # Файл с персональными данными
    sensitive_data = """
Сотрудники компании:
1. Иванов Иван Иванович
   Email: ivanov@company.com
   Телефон: +7-495-123-45-67
   Паспорт: 45 03 123456
   ИНН: 123456789012
   
2. Петрова Мария Сергеевна
   Email: petrova@company.com
   Телефон: +7-916-987-65-43
   Паспорт: 45 03 654321
   ИНН: 210987654321
   Номер карты: 5555-5555-5555-4444
"""
    
    # Файл с коммерческими данными
    commercial_data = """
Конфиденциальные данные компании:
- Выручка Q3 2024: $2,500,000
- Клиентская база: 15,000 активных пользователей
- Новый продукт: Project Phoenix (релиз Q1 2025)
- API ключи: sk-1234567890abcdef, prod-api-key-xyz789
"""
    
    # Сохранение тестовых файлов
    files = {
        'employees.txt': sensitive_data,
        'financial_report.txt': commercial_data
    }
    
    for filename, content in files.items():
        file_path = os.path.join(test_dir, filename)
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(content)
    
    return test_dir, files

def policy_creation_examples():
    """Примеры создания различных политик DLP"""
    logger = setup_logging()
    logger.info("=== Примеры создания политик DLP ===")
    
    dlp = DLPEngine("dlp_examples.db")
    
    # 1. Базовая политика для ПДн
    pii_policy = dlp.create_policy(
        name="Personal Data Protection",
        description="Защита персональных данных сотрудников",
        data_types=["email", "phone", "passport", "inn"],
        actions=["audit", "encrypt", "notify"]
    )
    logger.info(f"Создана политика ПДн: {pii_policy}")
    
    # 2. Политика для финансовых данных
    financial_policy = dlp.create_policy(
        name="Financial Data Security",
        description="Защита финансовых и коммерческих данных",
        data_types=["credit_card", "bank_account", "financial_data"],
        actions=["block", "audit", "alert"]
    )
    logger.info(f"Создана финансовая политика: {financial_policy}")
    
    # 3. Продвинутая ML-политика
    ml_policy = dlp.create_advanced_policy(
        name="ML-Enhanced Sensitive Data Detection",
        ml_enabled=True,
        confidence_threshold=0.85,
        real_time_monitoring=True,
        adaptive_learning=True
    )
    logger.info(f"Создана ML-политика: {ml_policy}")
    
    return dlp, [pii_policy, financial_policy, ml_policy]

def scanning_examples(dlp, test_dir, policy_ids):
    """Примеры сканирования данных"""
    logger = setup_logging()
    logger.info("=== Примеры сканирования данных ===")
    
    # 1. Сканирование текста
    test_text = """
    Пользователь: john.doe@company.com
    Номер карты: 4111-1111-1111-1111
    API ключ: sk-1234567890abcdef
    """
    
    scan_result = dlp.scan_text(test_text, policy_ids[0])
    logger.info("Сканирование текста:")
    logger.info(f"  Найдено нарушений: {len(scan_result['violations'])}")
    
    for violation in scan_result['violations']:
        logger.info(f"  - {violation['data_type']}: {violation['matched_data']}")
    
    # 2. Сканирование файлов
    for filename in os.listdir(test_dir):
        file_path = os.path.join(test_dir, filename)
        
        try:
            file_scan = dlp.scan_file(file_path, policy_ids[0])
            logger.info(f"Сканирование файла {filename}:")
            logger.info(f"  Размер: {file_scan['file_size']} байт")
            logger.info(f"  Нарушений: {len(file_scan.get('violations', []))}")
            
        except Exception as e:
            logger.warning(f"Ошибка сканирования {filename}: {e}")
    
    # 3. Сканирование директории
    directory_scan = dlp.scan_directory(test_dir, policy_ids[0])
    logger.info("Сканирование директории:")
    logger.info(f"  Файлов просканировано: {directory_scan['files_scanned']}")
    logger.info(f"  Всего нарушений: {directory_scan['total_violations']}")
    
    return directory_scan

def main():
    """Главная функция демонстрации DLP"""
    logger = setup_logging()
    logger.info("🛡️ DLP System - Подробная демонстрация")
    logger.info("=" * 60)
    
    try:
        # Создание тестовых данных
        test_dir, test_files = create_test_files()
        logger.info(f"Тестовые файлы созданы в: {test_dir}")
        
        # 1. Создание политик
        dlp, policy_ids = policy_creation_examples()
        
        print("\n" + "=" * 60)
        
        # 2. Сканирование данных
        scan_results = scanning_examples(dlp, test_dir, policy_ids)
        
        print("\n" + "=" * 60)
        logger.info("✅ DLP демонстрация завершена успешно!")
        
        # Итоговый отчет
        final_report = {
            'timestamp': datetime.now().isoformat(),
            'demo_statistics': {
                'policies_created': len(policy_ids),
                'test_files': len(test_files),
                'scan_results': scan_results
            }
        }
        
        # Сохранение итогового отчета
        report_filename = f"dlp_demo_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(report_filename, 'w', encoding='utf-8') as f:
            json.dump(final_report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"📄 Итоговый отчет сохранен: {report_filename}")
        logger.info("🎯 Все функции DLP продемонстрированы")
        
    except Exception as e:
        logger.error(f"❌ Ошибка во время демонстрации: {e}")
        raise
    
    finally:
        # Очистка (опционально)
        cleanup = False  # Установите True для очистки
        if cleanup:
            try:
                import shutil
                if 'test_dir' in locals():
                    shutil.rmtree(test_dir)
                    logger.info(f"🧹 Тестовая директория очищена: {test_dir}")
                
                if os.path.exists("dlp_examples.db"):
                    os.remove("dlp_examples.db")
                    logger.info("🧹 DLP база данных очищена")
                    
            except Exception as e:
                logger.warning(f"Предупреждение при очистке: {e}")

if __name__ == "__main__":
    main()
