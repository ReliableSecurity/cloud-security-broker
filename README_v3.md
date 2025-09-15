# 🛡️ Cloud Access Security Broker (CASB) v3.0

## 🚀 Российский аналог системы контроля доступа к облачным сервисам

**CASB v3.0** - это комплексная система безопасности для контроля и защиты доступа к облачным сервисам, разработанная с учётом российских требований безопасности и соответствием международным стандартам.

---

## 📋 Содержание

- [🎯 Основные возможности](#-основные-возможности)
- [🏗️ Архитектура системы](#️-архитектура-системы)
- [⚡ Быстрый старт](#-быстрый-старт)
- [🔧 Детальная установка](#-детальная-установка)
- [🔒 Безопасность](#-безопасность)
- [📊 Мониторинг и аналитика](#-мониторинг-и-аналитика)
- [🧪 Тестирование](#-тестирование)
- [📚 Документация](#-документация)
- [🌐 Поддерживаемые провайдеры](#-поддерживаемые-провайдеры)
- [📈 Производительность](#-производительность)
- [🤝 Участие в разработке](#-участие-в-разработке)

---

## 🎯 Основные возможности

### 🔐 Усиленная безопасность
- **Zero-Trust архитектура** с динамической оценкой доверия
- **Многофакторная аутентификация** (TOTP, SMS, Email, WebAuthn, Biometric)
- **Продвинутое шифрование** AES-256-GCM, RSA-2048/4096
- **Обнаружение угроз в реальном времени** с ML-алгоритмами
- **Защита от атак**: SQL injection, XSS, CSRF, Brute Force

### 📊 Мониторинг и аналитика  
- **Реальное время мониторинга** облачной активности
- **Интеллектуальное обнаружение аномалий** поведения
- **Комплексная аналитика безопасности** с визуализацией
- **Продвинутая отчётность** в форматах JSON, CSV, HTML, XML, PDF
- **Дашборд с графиками** для анализа трендов

### 🛡️ Защита данных (DLP)
- **Предотвращение утечки данных** с поддержкой российских типов данных
- **Сканирование контента** на предмет конфиденциальной информации
- **Политики безопасности** с гибкой настройкой правил
- **Автоматическое блокирование** подозрительных передач

### 🌐 Облачные провайдеры
- **AWS, Microsoft Azure, Google Cloud Platform**
- **Yandex.Cloud, SberCloud, Mail.ru Cloud**
- **Настраиваемые интеграции** для корпоративных облаков

### 📋 Соответствие стандартам
- **GDPR** (General Data Protection Regulation)
- **ФЗ-152** "О персональных данных"
- **PCI DSS** Level 1
- **SOX** (Sarbanes-Oxley Act)
- **ISO 27001** рекомендации

---

## 🏗️ Архитектура системы

```
┌─────────────────────────────────────────────────────────────┐
│                    🌐 Web Interface                         │
├─────────────────────────────────────────────────────────────┤
│  🔒 Security Layer   │  📊 Monitoring   │  📋 Reporting    │
│  - Zero Trust        │  - Real-time     │  - Analytics     │
│  - MFA              │  - Anomaly Det.   │  - Compliance    │
│  - Threat Intel     │  - Metrics        │  - Dashboards    │
├─────────────────────────────────────────────────────────────┤
│                    ⚙️ Core CASB Engine                      │
│  - Policy Engine    │  - User Mgmt     │  - Session Mgmt   │
│  - Access Control   │  - Audit Log     │  - Encryption     │
├─────────────────────────────────────────────────────────────┤
│  🔌 Cloud Connectors                                        │
│  AWS | Azure | GCP | Yandex | Sber | Mail.ru              │
├─────────────────────────────────────────────────────────────┤
│  💾 Data Layer                                              │
│  SQLite | Redis | File System | Logs                       │
└─────────────────────────────────────────────────────────────┘
```

### Компоненты системы

| Компонент | Описание | Файлы |
|-----------|----------|-------|
| **Core** | Основная логика CASB | `core/casb.py` |
| **Auth** | Аутентификация и MFA | `auth/mfa_auth.py` |
| **Security** | Zero-Trust и защита | `security/advanced_security.py` |
| **Monitoring** | Мониторинг активности | `monitoring/cloud_monitor.py` |
| **DLP** | Защита от утечек данных | `dlp/data_protection.py` |
| **Policies** | Движок политик | `policies/policy_engine.py` |
| **Enterprise** | Отчётность и аналитика | `enterprise/reporting.py` |
| **Performance** | Оптимизация и кеширование | `performance/performance_monitor.py` |

---

## ⚡ Быстрый старт

### Системные требования

- **Python**: 3.8+ (рекомендуется 3.11+)
- **ОС**: Linux (Ubuntu 20.04+, CentOS 8+, Debian 11+), macOS, Windows
- **RAM**: минимум 2GB, рекомендуется 8GB+
- **Диск**: минимум 5GB свободного места
- **Сеть**: доступ к интернету для обновлений угроз

### Установка за 5 минут

```bash
# 1. Клонирование репозитория
git clone https://github.com/ReliableSecurity/cloud-security-broker.git
cd cloud-security-broker

# 2. Создание виртуального окружения
python -m venv venv
source venv/bin/activate  # Linux/macOS
# venv\Scripts\activate   # Windows

# 3. Установка зависимостей
pip install -r requirements.txt

# 4. Инициализация системы
python setup.py install

# 5. Запуск CASB
python app.py
```

Система будет доступна по адресу: `http://localhost:5000`

### Docker развёртывание

```bash
# Сборка образа
docker build -t casb:v3.0 .

# Запуск контейнера
docker run -d \
  --name casb-system \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  -v $(pwd)/logs:/app/logs \
  casb:v3.0
```

---

## 🔧 Детальная установка

### 1. Подготовка системы

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install python3 python3-pip python3-venv \
                 sqlite3 redis-server nginx supervisor
```

**CentOS/RHEL:**
```bash
sudo yum install python3 python3-pip \
                 sqlite redis nginx supervisor
```

### 2. Настройка базы данных

```bash
# SQLite (по умолчанию) - автоматически создаётся
# Для PostgreSQL (опционально)
sudo apt install postgresql postgresql-contrib
sudo -u postgres createdb casb_db
```

### 3. Настройка Redis (кеширование)

```bash
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 4. Конфигурация

Создайте файл конфигурации:
```bash
cp config/casb_config.example.json config/casb_config.json
```

Отредактируйте настройки:
```json
{
  "database": "data/casb.db",
  "redis": {
    "enabled": true,
    "host": "localhost",
    "port": 6379
  },
  "security": {
    "jwt_secret": "your-super-secret-key-change-this",
    "session_timeout": 3600,
    "mfa_required": true
  },
  "monitoring": {
    "log_level": "INFO",
    "webhook_url": "https://your-webhook.com/alerts"
  }
}
```

### 5. Развёртывание в продакшне

См. подробное руководство в [DEPLOYMENT.md](DEPLOYMENT.md)

---

## 🔒 Безопасность

### Zero-Trust архитектура

CASB v3.0 реализует принципы Zero-Trust:

- **"Никому не доверяй, всегда проверяй"**
- **Динамическая оценка доверия** на основе:
  - История устройства
  - Геолокация
  - Поведенческие паттерны
  - Время доступа
- **Непрерывная верификация** сессий

### Многофакторная аутентификация

Поддерживаемые методы MFA:
- **TOTP** (Google Authenticator, Authy)
- **SMS** коды
- **Email** подтверждения
- **WebAuthn** (FIDO2)
- **Биометрия** (отпечатки, Face ID)

### Шифрование данных

- **AES-256-GCM** для симметричного шифрования
- **RSA-2048/4096** для асимметричного шифрования
- **PBKDF2** для генерации ключей из паролей
- **Salt** для защиты паролей
- **TLS 1.3** для сетевых соединений

### Обнаружение угроз

Система автоматически обнаруживает:
- SQL injection попытки
- XSS атаки
- Brute force атаки
- Аномальные паттерны доступа
- Подозрительные геолокации
- Быстрая смена IP адресов

---

## 📊 Мониторинг и аналитика

### Real-time мониторинг

```python
from monitoring.cloud_monitor import CloudActivityMonitor

monitor = CloudActivityMonitor('casb.db')
events = monitor.get_recent_events(hours=24)
```

### Генерация отчётов

```python
from enterprise.reporting import EnterpriseReportManager, ReportType

report_manager = EnterpriseReportManager('casb.db')
config = ReportConfig(
    report_type=ReportType.SECURITY_SUMMARY,
    start_date=datetime.now() - timedelta(days=7),
    end_date=datetime.now()
)
report = report_manager.generate_report(config)
```

### Дашборд метрик

Веб-интерфейс предоставляет:
- **Статистика безопасности** в реальном времени
- **Графики активности** пользователей
- **Карты угроз** по геолокации
- **Тренды соответствия** стандартам
- **Производительность системы**

---

## 🧪 Тестирование

### Запуск тестов

```bash
# Все тесты
pytest

# Только unit тесты
pytest tests/test_casb_core.py

# Тесты безопасности
pytest tests/test_security.py

# Стресс-тесты производительности
python tests/test_performance_and_security.py

# Интеграционные тесты
pytest tests/test_integration.py
```

### Покрытие кода

```bash
pytest --cov=. --cov-report=html
```

### Безопасность сканирование

```bash
# Статический анализ
bandit -r .

# Проверка зависимостей
safety check

# Автоматические пентесты
python tests/test_performance_and_security.py
```

---

## 📚 Документация

### API документация

```bash
# Генерация Swagger документации
python -m flask openapi
```

### Архитектурная документация

- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - Архитектура системы
- [API.md](docs/API.md) - REST API документация
- [SECURITY.md](docs/SECURITY.md) - Модель безопасности
- [COMPLIANCE.md](docs/COMPLIANCE.md) - Соответствие стандартам

### Примеры использования

```python
# Базовое использование
from core.casb import CASBCore, AccessLevel

casb = CASBCore()
user = casb.create_user(
    username="john.doe",
    email="john@company.com",
    department="IT",
    access_level=AccessLevel.READ_WRITE,
    password="secure_password"
)

# Запрос доступа к облачному сервису
access_request = casb.request_access(
    user_id=user.user_id,
    service_id="aws-s3-prod",
    action="read",
    ip_address="192.168.1.100",
    user_agent="MyApp/1.0"
)
```

---

## 🌐 Поддерживаемые провайдеры

| Провайдер | Статус | Возможности |
|-----------|--------|-------------|
| **AWS** | ✅ Полная поддержка | S3, EC2, Lambda, RDS |
| **Microsoft Azure** | ✅ Полная поддержка | Blob, VM, Functions |
| **Google Cloud** | ✅ Полная поддержка | Storage, Compute, AI |
| **Yandex.Cloud** | ✅ Полная поддержка | Object Storage, Compute |
| **SberCloud** | ✅ Базовая поддержка | Storage, VM |
| **Mail.ru Cloud** | 🔄 В разработке | Storage |

### Добавление нового провайдера

```python
from core.casb import CloudProvider, ThreatLevel

# Регистрация сервиса
service = casb.register_cloud_service(
    name="Custom Cloud Storage",
    provider=CloudProvider.CUSTOM,
    endpoint="https://api.custom-cloud.com",
    api_key="your-api-key",
    service_type="storage",
    risk_level=ThreatLevel.MEDIUM
)
```

---

## 📈 Производительность

### Бенчмарки

| Операция | Производительность | Примечания |
|----------|-------------------|------------|
| Создание пользователя | ~1000 ops/sec | SQLite, локально |
| Аутентификация | ~500 ops/sec | С хешированием |
| Проверка доступа | ~2000 ops/sec | С кешированием |
| Обнаружение угроз | ~100 ops/sec | Полный анализ |
| Генерация отчётов | ~10 отчётов/sec | С графиками |

### Оптимизация

- **Кеширование**: Redis для горячих данных
- **Пул соединений**: SQLite WAL режим
- **Асинхронная обработка**: Background tasks
- **Сжатие**: Логи и архивы
- **CDN**: Статические ресурсы

### Масштабирование

```yaml
# docker-compose.yml для горизонтального масштабирования
version: '3.8'
services:
  casb-app:
    image: casb:v3.0
    deploy:
      replicas: 3
  casb-db:
    image: postgres:13
  casb-cache:
    image: redis:6
  casb-lb:
    image: nginx:alpine
```

---

## 🛠️ Настройка для разработки

### Локальная разработка

```bash
# Режим разработки
export FLASK_ENV=development
export FLASK_DEBUG=1

# Горячая перезагрузка
python app.py --reload

# Логирование в DEBUG режиме
tail -f logs/casb.log
```

### Pre-commit хуки

```bash
pip install pre-commit
pre-commit install
```

### Линтеры и форматтеры

```bash
# Проверка стиля кода
flake8 .
black .
mypy .

# Автоматическое исправление
autopep8 --in-place --recursive .
```

---

## 🤝 Участие в разработке

### Вклад в проект

1. **Fork** репозитория
2. Создайте **feature branch**: `git checkout -b feature/amazing-feature`
3. **Commit** изменения: `git commit -m 'Add amazing feature'`
4. **Push** в branch: `git push origin feature/amazing-feature`
5. Создайте **Pull Request**

### Рекомендации

- Следуйте [PEP 8](https://peps.python.org/pep-0008/)
- Пишите тесты для нового кода
- Обновляйте документацию
- Используйте осмысленные commit сообщения

### Сообщество

- **GitHub Issues**: Сообщения об ошибках
- **GitHub Discussions**: Обсуждения функций
- **Telegram**: [@casb_security](https://t.me/casb_security)
- **Email**: security@casb-project.ru

---

## 📄 Лицензия

Этот проект лицензирован под **MIT License** - см. файл [LICENSE](LICENSE) для подробностей.

---

## 🙏 Благодарности

- **Команде безопасности** за аудит кода
- **Сообществу контрибьюторов** за улучшения
- **Пользователям** за обратную связь и тестирование
- **Open Source проектам** за используемые библиотеки

---

## 📞 Поддержка

Если у вас есть вопросы или проблемы:

- 📖 Ознакомьтесь с [документацией](docs/)
- 🐛 Создайте [Issue](https://github.com/ReliableSecurity/cloud-security-broker/issues)
- 💬 Задайте вопрос в [Discussions](https://github.com/ReliableSecurity/cloud-security-broker/discussions)
- 📧 Напишите на: support@casb-project.ru

---

<div align="center">

**🛡️ CASB v3.0 - Ваша надёжная защита в облаке! ☁️**

[![GitHub stars](https://img.shields.io/github/stars/ReliableSecurity/cloud-security-broker?style=social)](https://github.com/ReliableSecurity/cloud-security-broker/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/ReliableSecurity/cloud-security-broker?style=social)](https://github.com/ReliableSecurity/cloud-security-broker/network)

</div>