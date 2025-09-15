# CASB (Cloud Access Security Broker) - Российская система контроля доступа к облачным сервисам

## 🛡️ Описание

**CASB Security** - это комплексная российская система контроля доступа к облачным сервисам, разработанная для обеспечения безопасности при переходе в облака. Система предоставляет централизованное управление доступом, мониторинг активностей, защиту от утечек данных и управление политиками безопасности.

### ✨ Ключевые особенности

- 🔐 **Многофакторная аутентификация (MFA)** - TOTP, SMS, Email
- 📊 **Мониторинг в реальном времени** - отслеживание всех действий в облаке
- 🛡️ **Data Loss Prevention (DLP)** - предотвращение утечек конфиденциальных данных
- ⚖️ **Гибкая система политик** - настраиваемые правила безопасности
- 🌐 **Поддержка российских провайдеров** - Yandex Cloud, SberCloud, Mail.ru Cloud
- 🔍 **Аудит и отчетность** - детальные логи и аналитика
- 🎛️ **Современный веб-интерфейс** - удобная панель управления

## 🏗️ Архитектура системы

```
┌─────────────────────────────────────────────────────────────┐
│                    CASB Security System                     │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │   Web Interface │  │   REST API      │  │   MFA Auth  │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │  CASB Core      │  │  Policy Engine  │  │  DLP Engine │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────┐ │
│  │ Cloud Monitor   │  │ Audit Logger    │  │  Database   │ │
│  └─────────────────┘  └─────────────────┘  └─────────────┘ │
├─────────────────────────────────────────────────────────────┤
│              Cloud Providers Integration                    │
│    AWS  │  Azure  │  Yandex  │  Sber  │  Mail.ru  │  GCP  │
└─────────────────────────────────────────────────────────────┘
```

## 🚀 Быстрый старт

### Требования

- Python 3.8+
- SQLite3
- pip (для установки зависимостей)

### Установка

1. **Клонирование репозитория:**
```bash
git clone https://github.com/your-org/casb-security.git
cd casb-security
```

2. **Установка зависимостей:**
```bash
pip install -r requirements.txt
```

3. **Инициализация системы:**
```bash
python setup.py
```

4. **Запуск веб-интерфейса:**
```bash
python web/app.py
```

5. **Запуск API сервера:**
```bash
python api/cloud_integration.py
```

### Первый запуск

1. Откройте браузер и перейдите на `http://localhost:5000`
2. Войдите с учетными данными по умолчанию:
   - **Логин:** `admin`
   - **Пароль:** `secure_password_123`
3. Следуйте мастеру первоначальной настройки

## 📖 Компоненты системы

### 🏛️ CASB Core (`core/casb.py`)

Основной модуль системы, отвечающий за:
- Управление пользователями и ролями
- Аутентификацию и авторизацию
- Регистрацию облачных сервисов
- Обработку запросов доступа
- Расчет риск-скоров

**Пример использования:**
```python
from core.casb import CASBCore, AccessLevel

casb = CASBCore()

# Создание пользователя
user = casb.create_user(
    username="john.doe",
    email="john@company.ru",
    department="IT",
    access_level=AccessLevel.ADMIN,
    password="secure_password"
)

# Запрос доступа
access_request = casb.request_access(
    user_id=user.user_id,
    service_id="yandex_storage_01",
    action="read_files",
    ip_address="192.168.1.100",
    user_agent="Mozilla/5.0..."
)
```

### 🔐 MFA Authentication (`auth/mfa_auth.py`)

Модуль многофакторной аутентификации:
- TOTP (Google Authenticator, Authy)
- SMS коды
- Email коды
- Резервные коды

**Пример настройки TOTP:**
```python
from auth.mfa_auth import MFAAuthenticator

mfa = MFAAuthenticator("casb.db")

# Настройка TOTP
secret, qr_code = mfa.setup_totp(user_id, username)

# Создание вызова
challenge = mfa.create_challenge(user_id, "totp")

# Проверка кода
verified = mfa.verify_challenge(challenge.challenge_id, "123456")
```

### 📈 Cloud Monitor (`monitoring/cloud_monitor.py`)

Система мониторинга облачных активностей:
- Отслеживание событий в реальном времени
- Обнаружение аномалий
- Генерация оповещений
- Аналитика угроз

**Пример логирования события:**
```python
from monitoring.cloud_monitor import CloudActivityMonitor, EventType

monitor = CloudActivityMonitor("casb.db")

event = monitor.log_cloud_event(
    service_id="aws_s3_bucket",
    user_id="user123",
    event_type=EventType.FILE_DOWNLOAD,
    source_ip="203.0.113.1",
    user_agent="aws-cli/2.0.0",
    resource="/sensitive/document.pdf",
    action="download_file",
    result="success"
)
```

### 🛡️ DLP Engine (`dlp/data_protection.py`)

Система предотвращения утечек данных:
- Сканирование контента на конфиденциальность
- Классификация данных
- Автоматическое шифрование
- Карантин подозрительных файлов

**Поддерживаемые типы данных:**
- Паспортные данные РФ
- ИНН, СНИЛС
- Номера банковских карт
- Медицинские данные
- Финансовая информация

**Пример сканирования:**
```python
from dlp.data_protection import DataProtectionEngine

dlp = DataProtectionEngine("casb.db")

report = dlp.scan_content(
    content="Паспорт: 45 03 123456, ИНН: 123456789012",
    file_name="personal_data.txt"
)

print(f"Классификация: {report.classification.value}")
print(f"Риск-скор: {report.risk_score}")
```

### ⚖️ Policy Engine (`policies/policy_engine.py`)

Движок политик безопасности:
- Создание и управление политиками
- Оценка условий в реальном времени
- Автоматическое выполнение действий
- Шаблоны политик

**Пример создания политики:**
```python
from policies.policy_engine import PolicyEngine, PolicyType, PolicyScope

policy_engine = PolicyEngine("casb.db")

# Создание политики блокировки в нерабочее время
policy = policy_engine.create_policy_from_template(
    template_id="after_hours_block",
    name="Блокировка доступа после 18:00",
    target="finance_service"
)
```

## 🌐 REST API

### Базовый URL
```
http://localhost:5001/api
```

### Аутентификация
Все API запросы требуют заголовок:
```
X-API-Key: your_api_key
```

### Основные endpoints

#### Проверка состояния
```bash
GET /api/health
```

#### Управление облачными провайдерами
```bash
# Получение списка поддерживаемых провайдеров
GET /api/providers

# Добавление учетных данных
POST /api/credentials
{
  "provider": "yandex",
  "name": "Production Environment",
  "access_key": "your_access_key",
  "secret_key": "your_secret_key",
  "region": "ru-central1-a"
}
```

#### Синхронизация ресурсов
```bash
# Запуск синхронизации
POST /api/sync
{
  "credential_id": "abc123",
  "resource_types": ["compute_instance", "storage_bucket"]
}

# Получение ресурсов
GET /api/resources?credential_id=abc123&use_cache=true
```

#### Аудит и соответствие
```bash
# Получение событий аудита
GET /api/audit?credential_id=abc123&start_time=2024-01-01T00:00:00Z&end_time=2024-01-02T00:00:00Z

# Проверка соответствия
POST /api/compliance/check
{
  "credential_id": "abc123",
  "framework": "152-fz"
}
```

## ⚙️ Конфигурация

### Основной конфигурационный файл (`config/casb_config.json`)

```json
{
  "database": "casb.db",
  "jwt_secret": "your_jwt_secret_here",
  "session_timeout": 3600,
  "max_failed_attempts": 5,
  "threat_threshold": 0.7,
  "monitoring": {
    "monitoring_interval": 60,
    "retention_days": 90,
    "webhook_url": "https://your-webhook.com/alerts"
  },
  "smtp": {
    "enabled": true,
    "smtp_server": "smtp.company.ru",
    "smtp_port": 587,
    "use_tls": true,
    "username": "casb@company.ru",
    "password": "smtp_password",
    "from_email": "casb@company.ru"
  },
  "sms": {
    "enabled": false,
    "provider": "sms.ru",
    "api_key": "your_sms_api_key"
  }
}
```

### Конфигурация политик безопасности

```json
{
  "name": "Блокировка критичных операций",
  "description": "Блокирование удаления и изменения критичных ресурсов",
  "policy_type": "access_control",
  "scope": "global",
  "conditions": [
    {
      "field": "request.action",
      "operator": "regex_match",
      "value": ".*(delete|remove|destroy).*"
    },
    {
      "field": "service.risk_level",
      "operator": "in_list",
      "value": ["high", "critical"]
    }
  ],
  "actions": [
    {
      "action_type": "block",
      "parameters": {"reason": "Критичная операция заблокирована"}
    },
    {
      "action_type": "alert",
      "parameters": {"severity": "high"}
    }
  ]
}
```

## 🔧 Развертывание

### Docker развертывание

1. **Создание Docker образа:**
```bash
docker build -t casb-security .
```

2. **Запуск контейнера:**
```bash
docker run -d \
  --name casb-security \
  -p 5000:5000 \
  -p 5001:5001 \
  -v ./data:/app/data \
  -v ./config:/app/config \
  casb-security
```

### Системное развертывание

1. **Создание systemd сервиса:**
```ini
[Unit]
Description=CASB Security System
After=network.target

[Service]
Type=simple
User=casb
WorkingDirectory=/opt/casb-security
ExecStart=/opt/casb-security/venv/bin/python web/app.py
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

2. **Запуск сервиса:**
```bash
sudo systemctl enable casb-security
sudo systemctl start casb-security
```

## 🔐 Безопасность

### Рекомендации по безопасности

1. **Смена паролей по умолчанию:**
   - Измените `jwt_secret` в конфигурации
   - Смените пароль администратора
   - Сгенерируйте новые ключи шифрования

2. **Настройка HTTPS:**
   - Используйте SSL/TLS сертификаты
   - Настройте reverse proxy (nginx/apache)

3. **Резервное копирование:**
   - Регулярно создавайте резервные копии базы данных
   - Шифруйте резервные копии

4. **Мониторинг:**
   - Настройте уведомления о критичных событиях
   - Регулярно проверяйте логи системы

## 📊 Мониторинг и метрики

### Основные метрики

- **Общие запросы доступа** - количество обработанных запросов
- **Заблокированные запросы** - количество отклоненных запросов
- **Обнаруженные угрозы** - количество выявленных угроз
- **DLP сканирования** - статистика проверок данных
- **Политики безопасности** - эффективность применения политик

### Дашборды

1. **Общий дашборд** - сводная информация по всей системе
2. **Мониторинг активности** - детальная аналитика событий
3. **DLP дашборд** - статистика защиты данных
4. **Управление политиками** - настройка и мониторинг политик

## 🛠️ API интеграция

### Поддерживаемые облачные провайдеры

| Провайдер | Статус | Поддерживаемые сервисы |
|-----------|--------|------------------------|
| **Yandex Cloud** | ✅ Полная поддержка | Compute, Storage, IAM, Audit Trails |
| **SberCloud** | ✅ Базовая поддержка | Compute, Storage, Security |
| **Mail.ru Cloud** | ✅ Базовая поддержка | Compute, Storage |
| **AWS** | 🔄 В разработке | EC2, S3, IAM, CloudTrail |
| **Azure** | 🔄 В разработке | Virtual Machines, Storage, Monitor |
| **Google Cloud** | 📋 Планируется | Compute Engine, Cloud Storage |

### Пример интеграции

```python
import requests

# Добавление учетных данных Yandex Cloud
response = requests.post('http://localhost:5001/api/credentials', 
    headers={'X-API-Key': 'your_api_key'},
    json={
        'provider': 'yandex',
        'name': 'Production',
        'access_key': 'your_access_key',
        'secret_key': 'your_secret_key',
        'region': 'ru-central1-a'
    }
)

credential_id = response.json()['data']['credential_id']

# Синхронизация ресурсов
requests.post('http://localhost:5001/api/sync', 
    headers={'X-API-Key': 'your_api_key'},
    json={'credential_id': credential_id}
)
```

## 🎯 Сценарии использования

### 1. Контроль доступа сотрудников к облачным ресурсам

```python
# Настройка политики доступа для отдела
policy = create_department_access_policy(
    department="Finance",
    allowed_services=["storage", "analytics"],
    time_restrictions={"hours": [9, 18]},
    require_mfa=True
)
```

### 2. Предотвращение утечек персональных данных

```python
# Сканирование файла перед загрузкой в облако
scan_result = dlp_engine.scan_file("/path/to/document.pdf")

if scan_result.classification == DataClassification.CONFIDENTIAL:
    # Автоматическое шифрование
    dlp_engine.encrypt_file("/path/to/document.pdf")
```

### 3. Мониторинг подозрительной активности

```python
# Создание правила обнаружения аномалий
alert_rule = monitor.create_alert_rule(
    name="Массовое скачивание данных",
    conditions={
        "event_type": "file_download",
        "count_threshold": 100,
        "time_window_minutes": 60
    },
    severity=Severity.WARNING
)
```

## 📋 DLP (Data Loss Prevention)

### Поддерживаемые типы конфиденциальных данных

1. **Персональные данные:**
   - Номера паспортов РФ
   - ИНН физических лиц
   - СНИЛС
   - Номера телефонов

2. **Финансовые данные:**
   - Номера банковских карт
   - Реквизиты счетов
   - Финансовые документы

3. **Медицинские данные:**
   - Медицинские заключения
   - Результаты анализов
   - Персональная медицинская информация

4. **Корпоративные данные:**
   - API ключи и токены
   - Конфиденциальные документы
   - Внутренняя переписка

### Действия при обнаружении нарушений

- **Блокировка** - запрет операции
- **Карантин** - изоляция файла
- **Шифрование** - автоматическая защита
- **Оповещение** - уведомление администраторов
- **Логирование** - запись в журнал аудита

## 🔍 Политики безопасности

### Типы политик

1. **Контроль доступа** - управление правами пользователей
2. **Защита данных** - правила обработки конфиденциальной информации
3. **Аутентификация** - требования к входу в систему
4. **Сетевая безопасность** - контроль сетевого доступа
5. **Соответствие требованиям** - выполнение регуляторных требований

### Примеры политик

#### Блокировка доступа в нерабочее время
```json
{
  "name": "After Hours Access Block",
  "conditions": [
    {"field": "request.timestamp", "operator": "time_range", "value": {"hours": [18, 8]}},
    {"field": "service.risk_level", "operator": "equals", "value": "critical"}
  ],
  "actions": [
    {"action_type": "block", "parameters": {"reason": "Доступ запрещен в нерабочее время"}}
  ]
}
```

#### Требование MFA для администраторов
```json
{
  "name": "Admin MFA Requirement",
  "conditions": [
    {"field": "user.access_level", "operator": "equals", "value": "admin"},
    {"field": "request.action", "operator": "regex_match", "value": ".*(delete|config).*"}
  ],
  "actions": [
    {"action_type": "require_mfa", "parameters": {"methods": ["totp", "sms"]}}
  ]
}
```

## 📊 Отчетность и аудит

### Типы отчетов

1. **Отчет активности пользователей** - детальная статистика по пользователям
2. **Отчет соответствия** - проверка выполнения требований безопасности
3. **Отчет DLP** - статистика обнаружения конфиденциальных данных
4. **Отчет инцидентов** - анализ нарушений безопасности

### Экспорт отчетов

```python
# Экспорт аудита за период
audit_report = casb.export_audit_report(
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 1, 31)
)

# Экспорт DLP отчета
dlp_report = dlp_engine.export_dlp_report(
    start_date=datetime(2024, 1, 1),
    end_date=datetime(2024, 1, 31)
)
```

## 🏢 Соответствие требованиям

### Поддерживаемые стандарты

- **152-ФЗ** "О персональных данных"
- **GDPR** (General Data Protection Regulation)
- **ISO 27001** - Управление информационной безопасностью
- **SOC 2** - Security, Availability, and Confidentiality

### Функции соответствия

- Автоматическая классификация данных
- Контроль доступа к персональным данным
- Журналирование всех операций
- Уведомления о нарушениях
- Регулярные проверки безопасности

## 🆘 Устранение неполадок

### Частые проблемы

1. **Ошибка подключения к базе данных:**
   ```bash
   # Проверка файла базы данных
   ls -la casb.db
   # Восстановление из резервной копии
   cp casb.db.backup casb.db
   ```

2. **Проблемы с MFA:**
   ```bash
   # Сброс MFA для пользователя
   python -c "from auth.mfa_auth import MFAAuthenticator; mfa = MFAAuthenticator('casb.db'); mfa.disable_mfa_method('user_id', 'method_id')"
   ```

3. **Высокое потребление ресурсов:**
   ```bash
   # Очистка старых данных
   python maintenance/cleanup.py --days 30
   ```

### Логи

Основные файлы логов:
- `casb.log` - основные логи системы
- `web.log` - логи веб-интерфейса
- `api.log` - логи REST API
- `dlp.log` - логи DLP сканирования

## 🤝 Поддержка и развитие

### Контакты

- **Email:** reliablesecurity@protonmail.com
- **Telegram:** @reliablesecurity
- **GitHub:** https://github.com/ReliableSecurity/cloud-security-broker
  
### Участие в разработке

1. Fork репозитория
2. Создайте feature branch
3. Внесите изменения
4. Создайте Pull Request

### Лицензия

Система распространяется под лицензией MIT. См. файл `LICENSE` для подробностей.

## 📈 Дорожная карта

### Версия 1.1 (Q2 2025)
- ✅ Базовая функциональность CASB
- ✅ Веб-интерфейс администратора
- ✅ API для интеграции
- ✅ Поддержка российских облачных провайдеров

### Версия 1.2 (Q3 2025)
- 🔄 Расширенная интеграция с AWS и Azure
- 🔄 Машинное обучение для обнаружения аномалий
- 🔄 Мобильное приложение для администраторов
- 🔄 Интеграция с SIEM системами

### Версия 2.0 (Q4 2025)
- 📋 Микросервисная архитектура
- 📋 Поддержка Kubernetes
- 📋 Расширенная аналитика
- 📋 Интеграция с блокчейн для аудита

---

**Разработано в России для российского рынка** 🇷🇺

*CASB Security - надежная защита ваших облачных ресурсов*
