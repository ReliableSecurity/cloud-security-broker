# CASB Security System - Примеры использования

Данная директория содержит практические примеры использования Cloud Security Broker (CASB) системы, демонстрирующие различные функции DLP (Data Loss Prevention) и MFA (Multi-Factor Authentication).

## 📁 Структура примеров

### 🔧 basic_usage.py
**Базовые примеры использования системы**
- Простые сценарии DLP и MFA
- Интеграция между модулями
- Демонстрация основных функций
- Создание базовых политик безопасности

```bash
python examples/basic_usage.py
```

### 🛡️ dlp_examples.py
**Подробные примеры модуля DLP**
- Создание различных типов политик
- Сканирование файлов и текста
- Анонимизация и токенизация данных
- Классификация информации
- Мониторинг в реальном времени
- Машинное обучение и аналитика
- Соответствие стандартам (GDPR, HIPAA, SOX)
- Интеграция с внешними системами

```bash
python examples/dlp_examples.py
```

### 🔐 mfa_examples.py
**Подробные примеры модуля MFA**
- Настройка различных методов аутентификации
- TOTP, SMS, биометрия, push-уведомления
- Адаптивная аутентификация
- Zero Trust верификация
- Поведенческая аналитика
- Управление привилегированным доступом
- Кроссплатформенная синхронизация
- Система обнаружения мошенничества
- Реагирование на инциденты

```bash
python examples/mfa_examples.py
```

### 🌐 api_examples.py
**Примеры использования REST API**
- HTTP клиент для взаимодействия с API
- CRUD операции через REST
- Пакетные операции
- Аналитика через API
- Мониторинг и уведомления
- Тестирование производительности
- Обработка ошибок

```bash
python examples/api_examples.py
```

## 🚀 Быстрый старт

### Требования
```bash
pip install -r requirements.txt
```

### Запуск базовой демонстрации
```bash
# Переход в директорию проекта
cd /home/mans/cloud-security-broker

# Запуск базового примера
python examples/basic_usage.py
```

### Запуск подробных примеров
```bash
# DLP примеры
python examples/dlp_examples.py

# MFA примеры
python examples/mfa_examples.py

# API примеры (требует запущенного сервера)
python -m api.casb_api &  # Запуск API сервера
python examples/api_examples.py
```

## 📊 Типичные сценарии использования

### 1. Защита персональных данных (ПДн)
```python
from dlp.data_loss_prevention import DLPEngine

dlp = DLPEngine("production.db")

# Создание политики для ПДн
policy_id = dlp.create_policy(
    name="GDPR Personal Data Protection",
    data_types=["email", "phone", "passport", "inn"],
    actions=["audit", "encrypt", "notify"]
)

# Сканирование документа
result = dlp.scan_file("/path/to/document.pdf", policy_id)
```

### 2. Настройка многофакторной аутентификации
```python
from auth.mfa_auth import MFAAuthenticator

mfa = MFAAuthenticator("production.db")

# Настройка TOTP для пользователя
secret, qr_code = mfa.setup_totp("user123", "user@company.com")

# Создание вызова аутентификации
challenge = mfa.create_challenge("user123", "totp")

# Проверка кода
result = mfa.verify_challenge(challenge.challenge_id, "123456")
```

### 3. Адаптивная аутентификация
```python
# Оценка контекста безопасности
context = {
    'ip_address': '192.168.1.100',
    'device_fingerprint': 'trusted_device',
    'location': 'office',
    'time_of_day': '14:30'
}

adaptive_result = mfa.evaluate_adaptive_authentication("user123", context)
```

### 4. Соответствие стандартам
```python
# Создание политики GDPR
gdpr_policy = dlp.create_compliance_policy(
    compliance_framework="GDPR",
    auto_generate_rules=True,
    data_subject_rights=True
)

# Генерация отчета соответствия
report = dlp.generate_compliance_report("GDPR")
```

## 🔧 Конфигурация для примеров

### Настройка базы данных
Примеры используют локальные SQLite базы данных:
- `examples_casb.db` - для базовых примеров
- `dlp_examples.db` - для DLP примеров
- `mfa_examples.db` - для MFA примеров

### Настройка SMTP (опционально)
```python
smtp_config = {
    'enabled': True,
    'smtp_server': 'smtp.company.com',
    'smtp_port': 587,
    'username': 'casb@company.com',
    'password': 'your_password',
    'use_tls': True
}

mfa = MFAAuthenticator("database.db", smtp_config=smtp_config)
```

### Настройка логирования
```python
import logging

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('casb_examples.log'),
        logging.StreamHandler()
    ]
)
```

## 📈 Аналитика и отчетность

### DLP аналитика
```python
# Создание аналитической панели
dashboard = dlp.create_analytics_dashboard()

# Оценка общей безопасности
security_posture = dlp.assess_overall_security_posture()

# Анализ трендов
trends = dlp.analyze_security_trends(time_period=30)
```

### MFA аналитика
```python
# Техническая панель
technical_dashboard = mfa.create_mfa_analytics_dashboard("technical")

# Исполнительная панель
executive_dashboard = mfa.create_mfa_analytics_dashboard("executive")

# Статистика аутентификации
stats = mfa.get_mfa_statistics(days=7)
```

## 🔗 Интеграция с внешними системами

### Active Directory
```python
# DLP интеграция с AD
ad_integration = dlp.setup_active_directory_integration(
    ldap_server="ldap://ad.company.com",
    base_dn="DC=company,DC=com"
)

# MFA интеграция с AD
mfa_ad = mfa.setup_active_directory_integration(
    ldap_server="ldap://ad.company.com",
    base_dn="DC=company,DC=com"
)
```

### Webhook уведомления
```python
# Настройка webhook для DLP
webhook_id = dlp.setup_webhook_notifications(
    webhook_url="https://webhook.company.com/dlp",
    notification_types=["violation", "high_risk"]
)

# Настройка webhook для MFA
mfa_webhook = mfa.setup_webhook_integration(
    "security_alerts",
    "https://webhook.company.com/mfa"
)
```

### SIEM интеграция
```python
# Интеграция с Splunk
siem_config = dlp.setup_siem_integration(
    siem_platform="splunk",
    connection_config={
        "host": "splunk.company.com",
        "port": 8089,
        "index": "security_events"
    }
)
```

## 🧪 Тестирование

### Единичное тестирование
```bash
# Тестирование DLP модуля
python -m pytest tests/test_dlp.py -v

# Тестирование MFA модуля
python -m pytest tests/test_mfa.py -v

# Тестирование API
python -m pytest tests/test_api.py -v
```

### Интеграционное тестирование
```bash
# Полное тестирование системы
python -m pytest tests/ -v --integration
```

## 🐳 Docker примеры

### Запуск в Docker
```bash
# Сборка образа
docker build -t casb-security .

# Запуск контейнера
docker run -d \
  --name casb-security \
  -p 5000:5000 \
  -v $(pwd)/config:/app/config \
  -v $(pwd)/data:/app/data \
  casb-security
```

### Docker Compose
```bash
# Запуск всей системы
docker-compose up -d

# Просмотр логов
docker-compose logs -f casb-api
```

## 🔍 Мониторинг и диагностика

### Проверка состояния системы
```python
# Проверка DLP
dlp_health = dlp.get_system_health()

# Проверка MFA
mfa_health = mfa.get_system_health()

# Проверка производительности
performance_metrics = dlp.get_performance_metrics()
```

### Логирование
```bash
# Просмотр логов DLP
tail -f logs/dlp.log

# Просмотр логов MFA
tail -f logs/mfa.log

# Просмотр логов API
tail -f logs/api.log
```

## 🚨 Устранение неполадок

### Распространенные проблемы

1. **База данных не найдена**
   ```bash
   # Инициализация базы данных
   python -c "from dlp.data_loss_prevention import DLPEngine; DLPEngine('casb.db')"
   ```

2. **SMTP ошибки**
   ```python
   # Отключение SMTP для тестирования
   smtp_config = {'enabled': False}
   mfa = MFAAuthenticator("casb.db", smtp_config=smtp_config)
   ```

3. **Ошибки импорта модулей**
   ```python
   # Добавление пути к модулям
   import sys
   sys.path.append('/path/to/cloud-security-broker')
   ```

4. **API сервер не отвечает**
   ```bash
   # Запуск API сервера
   python -m api.casb_api
   # или
   flask --app api.casb_api run --host=0.0.0.0 --port=5000
   ```

### Отладка
```python
# Включение отладочного режима
import logging
logging.getLogger().setLevel(logging.DEBUG)

# Детальное логирование DLP
dlp = DLPEngine("casb.db", debug=True)

# Детальное логирование MFA
mfa = MFAAuthenticator("casb.db", debug=True)
```

## 📚 Дополнительные ресурсы

- **[README_DETAILED.md](../README_DETAILED.md)** - Подробная документация проекта
- **[config/settings.json](../config/settings.json)** - Конфигурация системы
- **[tests/](../tests/)** - Модульные и интеграционные тесты
- **[docs/](../docs/)** - Техническая документация
- **[deployment/](../deployment/)** - Файлы развертывания

## 🆘 Поддержка

При возникновении вопросов или проблем:

1. Проверьте логи системы
2. Убедитесь в корректности конфигурации
3. Проверьте требования к зависимостям
4. Обратитесь к документации API
5. Создайте issue в репозитории

## 📝 Примечания

- Все примеры используют демонстрационные данные
- SMTP и внешние интеграции отключены по умолчанию
- Для продакшена требуется настройка реальных конфигураций
- Рекомендуется тестирование в изолированной среде

---

**Версия примеров:** 2.0  
**Последнее обновление:** 2024-12-31  
**Совместимость:** Python 3.8+
