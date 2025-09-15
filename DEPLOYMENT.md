# CASB Security System - Deployment Guide
# Руководство по развертыванию системы безопасности CASB

## 🎯 Обзор

CASB (Cloud Access Security Broker) Security System - это комплексная система контроля доступа к облачным сервисам, разработанная для обеспечения максимальной безопасности при работе в облачной среде.

### Ключевые возможности
- 🔐 Многофакторная аутентификация (TOTP, SMS, Email)
- 📊 Мониторинг в реальном времени
- 🛡️ Data Loss Prevention (DLP)
- ⚖️ Система политик безопасности
- 🌐 Поддержка российских облачных провайдеров
- 🔍 Аудит и отчетность

## 📋 Системные требования

### Минимальные требования
- **OS**: Linux Ubuntu 20.04+, CentOS 8+, RHEL 8+
- **Python**: 3.8+
- **RAM**: 4GB
- **Disk**: 20GB свободного места
- **CPU**: 2 cores
- **Network**: Доступ в интернет для загрузки зависимостей

### Рекомендуемые требования
- **OS**: Linux Ubuntu 22.04 LTS
- **Python**: 3.11+
- **RAM**: 8GB+
- **Disk**: 100GB SSD
- **CPU**: 4+ cores
- **Network**: Выделенная сеть для безопасности

## 🚀 Быстрая установка

### 1. Подготовка системы

```bash
# Обновление системы (Ubuntu/Debian)
sudo apt update && sudo apt upgrade -y

# Установка зависимостей системы
sudo apt install -y python3 python3-pip python3-venv git sqlite3 nginx supervisor redis-server

# Создание пользователя для CASB
sudo useradd -m -s /bin/bash casb
sudo usermod -aG sudo casb

# Переключение на пользователя CASB
sudo su - casb
```

### 2. Клонирование репозитория

```bash
# Клонирование из GitHub
git clone https://github.com/ReliableSecurity/cloud-security-broker.git
cd cloud-security-broker

# Создание виртуального окружения
python3 -m venv venv
source venv/bin/activate

# Установка Python зависимостей
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Конфигурация

```bash
# Создание директорий
mkdir -p {data,logs,backups,certs}

# Копирование конфигурации по умолчанию
cp config.yaml.example config.yaml

# Редактирование конфигурации
nano config.yaml
```

**Важные настройки в config.yaml:**
```yaml
system:
  secret_key: "ИЗМЕНИТЕ_НА_СЛУЧАЙНУЮ_СТРОКУ_64_СИМВОЛА"  # ОБЯЗАТЕЛЬНО!
  debug: false
  environment: "production"

database:
  path: "data/casb.db"
  encryption_enabled: true

security:
  max_failed_attempts: 5
  threat_threshold: 0.7

server:
  host: "0.0.0.0"
  port: 5000
  ssl_enabled: true  # Рекомендуется для продакшена
```

### 4. Инициализация базы данных

```bash
# Запуск инициализации
python setup.py

# Создание администратора (интерактивно)
python -c "
from core.casb import CASBCore, AccessLevel
casb = CASBCore()
admin = casb.create_user(
    username='admin',
    email='admin@company.com',
    department='IT',
    access_level=AccessLevel.ADMIN,
    password='СОЗДАЙТЕ_БЕЗОПАСНЫЙ_ПАРОЛЬ'
)
print(f'Администратор создан: {admin.username}')
"
```

### 5. Тестирование установки

```bash
# Запуск интеграционных тестов
python test_integration.py

# Запуск системы в тестовом режиме
python app.py

# В другом терминале - проверка работы
curl -k https://localhost:5000/health
```

## 🐳 Установка через Docker

### 1. Создание Docker образа

```bash
# Создание Dockerfile
cat > Dockerfile << 'EOF'
FROM python:3.11-slim

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    sqlite3 \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Создание пользователя приложения
RUN useradd -m -u 1000 casb

# Установка Python зависимостей
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Копирование кода приложения
COPY --chown=casb:casb . .

# Создание необходимых директорий
RUN mkdir -p data logs backups && chown -R casb:casb .

USER casb

EXPOSE 5000

CMD ["python", "app.py"]
EOF

# Сборка образа
docker build -t casb-security:latest .
```

### 2. Docker Compose для полного развертывания

```bash
# Создание docker-compose.yml
cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  casb:
    build: .
    ports:
      - "5000:5000"
    volumes:
      - casb_data:/app/data
      - casb_logs:/app/logs
      - casb_backups:/app/backups
      - ./config.yaml:/app/config.yaml:ro
    environment:
      - CASB_CONFIG_PATH=/app/config.yaml
    depends_on:
      - redis
    restart: unless-stopped

  redis:
    image: redis:alpine
    volumes:
      - redis_data:/data
    restart: unless-stopped

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - casb
    restart: unless-stopped

volumes:
  casb_data:
  casb_logs:
  casb_backups:
  redis_data:
EOF

# Запуск системы
docker-compose up -d
```

## ⚙️ Детальная конфигурация

### Настройка SSL/TLS

```bash
# Генерация самоподписанного сертификата (для тестирования)
openssl req -x509 -newkey rsa:4096 -keyout certs/server.key -out certs/server.crt -days 365 -nodes

# Или использование Let's Encrypt (рекомендуется)
sudo certbot certonly --standalone -d your-casb-domain.com
sudo cp /etc/letsencrypt/live/your-casb-domain.com/fullchain.pem certs/server.crt
sudo cp /etc/letsencrypt/live/your-casb-domain.com/privkey.pem certs/server.key
sudo chown casb:casb certs/server.*
```

### Настройка Nginx (обратный прокси)

```bash
cat > /etc/nginx/sites-available/casb << 'EOF'
server {
    listen 80;
    server_name your-casb-domain.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name your-casb-domain.com;

    ssl_certificate /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # SSL настройки безопасности
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256;

    # Заголовки безопасности
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        # WebSocket поддержка
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
    }

    # Статические файлы
    location /static/ {
        alias /home/casb/cloud-security-broker/static/;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Логи
    access_log /var/log/nginx/casb_access.log;
    error_log /var/log/nginx/casb_error.log;
}
EOF

# Активация конфигурации
sudo ln -s /etc/nginx/sites-available/casb /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

### Настройка Supervisor (автозапуск)

```bash
cat > /etc/supervisor/conf.d/casb.conf << 'EOF'
[program:casb-web]
command=/home/casb/cloud-security-broker/venv/bin/python app.py
directory=/home/casb/cloud-security-broker
user=casb
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/home/casb/cloud-security-broker/logs/supervisor.log
environment=PATH="/home/casb/cloud-security-broker/venv/bin"

[program:casb-api]
command=/home/casb/cloud-security-broker/venv/bin/gunicorn --config gunicorn.conf.py api.main:app
directory=/home/casb/cloud-security-broker
user=casb
autostart=true
autorestart=true
redirect_stderr=true
stdout_logfile=/home/casb/cloud-security-broker/logs/api_supervisor.log
environment=PATH="/home/casb/cloud-security-broker/venv/bin"
EOF

# Перезагрузка supervisor
sudo supervisorctl reread
sudo supervisorctl update
sudo supervisorctl start casb-web casb-api
```

## 🛠️ Производственное развертывание

### 1. Настройка для высокой нагрузки

```bash
# Создание gunicorn.conf.py
cat > gunicorn.conf.py << 'EOF'
bind = "127.0.0.1:5000"
workers = 4
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
preload_app = True
keepalive = 5
timeout = 120
graceful_timeout = 30
user = "casb"
group = "casb"
tmp_upload_dir = None
secure_scheme_headers = {
    'X-FORWARDED-PROTOCOL': 'ssl',
    'X-FORWARDED-PROTO': 'https',
    'X-FORWARDED-SSL': 'on'
}
EOF
```

### 2. Мониторинг и алерты

```bash
# Настройка Prometheus метрик
echo "monitoring:
  metrics:
    enabled: true
    prometheus_endpoint: '/metrics'
    collection_interval: 30" >> config.yaml

# Настройка алертов
echo "notifications:
  smtp:
    enabled: true
    server: 'smtp.company.com'
    from_email: 'casb@company.com'
  slack:
    enabled: true
    webhook_url: 'https://hooks.slack.com/...'
    channel: '#security-alerts'" >> config.yaml
```

### 3. Резервное копирование

```bash
# Создание скрипта резервного копирования
cat > backup.sh << 'EOF'
#!/bin/bash
BACKUP_DIR="/home/casb/cloud-security-broker/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_PATH="/home/casb/cloud-security-broker/data/casb.db"

# Создание резервной копии БД
sqlite3 $DB_PATH ".backup $BACKUP_DIR/casb_backup_$DATE.db"

# Создание архива конфигурации
tar -czf "$BACKUP_DIR/config_backup_$DATE.tar.gz" config.yaml certs/

# Удаление старых резервных копий (старше 30 дней)
find $BACKUP_DIR -name "*.db" -mtime +30 -delete
find $BACKUP_DIR -name "*.tar.gz" -mtime +30 -delete

echo "Backup completed: $DATE"
EOF

chmod +x backup.sh

# Добавление в crontab
(crontab -l 2>/dev/null; echo "0 2 * * * /home/casb/cloud-security-broker/backup.sh") | crontab -
```

### 4. Безопасность системы

```bash
# Настройка файрвола (UFW)
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# Настройка fail2ban
sudo apt install fail2ban

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 5

[casb-auth]
enabled = true
port = 443
protocol = tcp
filter = casb-auth
logpath = /home/casb/cloud-security-broker/logs/casb.log
maxretry = 3
EOF

# Создание фильтра fail2ban
cat > /etc/fail2ban/filter.d/casb-auth.conf << 'EOF'
[Definition]
failregex = \[AUTHENTICATION\] Ошибка аутентификации.*<HOST>
            \[SECURITY\] Подозрительная активность.*<HOST>
ignoreregex =
EOF

sudo systemctl restart fail2ban
```

## 🔧 Обслуживание и мониторинг

### Команды управления

```bash
# Проверка состояния
sudo supervisorctl status casb-web casb-api

# Просмотр логов
tail -f logs/casb.log
tail -f logs/casb_errors.log

# Перезапуск сервисов
sudo supervisorctl restart casb-web casb-api

# Обновление системы
git pull origin main
pip install -r requirements.txt
sudo supervisorctl restart all
```

### Мониторинг производительности

```bash
# Проверка ресурсов
htop
iotop -o

# Проверка базы данных
sqlite3 data/casb.db "PRAGMA integrity_check;"
sqlite3 data/casb.db "SELECT COUNT(*) FROM users;"

# Проверка дискового пространства
df -h
du -sh data/ logs/ backups/
```

### Здоровье системы

```bash
# Health check endpoint
curl -k https://localhost:443/health

# Метрики Prometheus
curl -k https://localhost:443/metrics

# Статистика ошибок
python -c "
from utils.error_handler import CASBLogger
logger = CASBLogger()
stats = logger.get_error_statistics()
print(stats)
"
```

## 🚨 Устранение неполадок

### Частые проблемы

1. **Ошибка подключения к базе данных**
   ```bash
   # Проверка прав доступа
   ls -la data/casb.db
   # Восстановление из резервной копии
   cp backups/casb_backup_latest.db data/casb.db
   ```

2. **Проблемы с SSL сертификатами**
   ```bash
   # Проверка сертификата
   openssl x509 -in certs/server.crt -text -noout
   # Обновление Let's Encrypt
   sudo certbot renew
   ```

3. **Высокое потребление памяти**
   ```bash
   # Оптимизация базы данных
   sqlite3 data/casb.db "VACUUM;"
   # Очистка старых логов
   find logs/ -name "*.log" -mtime +7 -exec truncate -s 0 {} \;
   ```

### Логи для диагностики

- **Основные логи**: `logs/casb.log`
- **Ошибки**: `logs/casb_errors.log`
- **Веб-сервер**: `logs/web.log`
- **API**: `logs/api.log`
- **Системные**: `/var/log/supervisor/casb-*.log`

## 📈 Масштабирование

### Горизонтальное масштабирование

```bash
# Настройка балансировщика нагрузки
# Обновление nginx.conf для нескольких экземпляров
upstream casb_backend {
    server 127.0.0.1:5000;
    server 127.0.0.1:5001;
    server 127.0.0.1:5002;
}

server {
    # ... SSL настройки ...
    
    location / {
        proxy_pass http://casb_backend;
        # ... остальные настройки ...
    }
}
```

### Кластерная конфигурация

```bash
# Использование внешней БД (PostgreSQL)
pip install psycopg2-binary

# Настройка Redis для сессий
pip install redis

# Обновление config.yaml
echo "database:
  type: 'postgresql'
  host: 'db.company.com'
  port: 5432
  name: 'casb'
  user: 'casb_user'
  password: 'secure_password'

cache:
  type: 'redis'
  host: 'redis.company.com'
  port: 6379" >> config.yaml
```

## 🔐 Безопасность

### Рекомендации по безопасности

1. **Регулярно обновляйте систему и зависимости**
2. **Используйте сильные пароли и регулярно их меняйте**
3. **Настройте автоматическое резервное копирование**
4. **Мониторьте логи безопасности**
5. **Ограничьте сетевой доступ файрволом**
6. **Используйте SSL/TLS для всех соединений**

### Аудит безопасности

```bash
# Запуск тестов безопасности
python -m pytest tests/test_security.py -v

# Проверка уязвимостей в зависимостях
pip install safety
safety check

# Анализ кода
pip install bandit
bandit -r . -x tests/
```

## 📞 Поддержка

При возникновении проблем:

1. Проверьте логи системы
2. Обратитесь к разделу "Устранение неполадок"
3. Создайте issue в GitHub репозитории
4. Обратитесь в техническую поддержку

---

**© 2025 CASB Security System. Разработано в России для российского рынка 🇷🇺**