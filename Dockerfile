# CASB Security System - Docker Image
FROM python:3.11-slim

# Метаданные
LABEL maintainer="CASB Security Team"
LABEL version="1.0.0"
LABEL description="Cloud Access Security Broker для российских организаций"

# Установка системных зависимостей
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libmagic1 \
    libmagic-dev \
    sqlite3 \
    curl \
    wget \
    cron \
    supervisor \
    nginx \
    && rm -rf /var/lib/apt/lists/*

# Создание пользователя для безопасности
RUN useradd -m -s /bin/bash casb && \
    mkdir -p /app /app/data /app/logs /app/backup && \
    chown -R casb:casb /app

# Установка рабочей директории
WORKDIR /app

# Копирование файлов зависимостей
COPY requirements.txt .
COPY config.yaml .

# Установка Python зависимостей
RUN pip install --no-cache-dir -r requirements.txt

# Копирование исходного кода
COPY . .

# Настройка прав доступа
RUN chown -R casb:casb /app && \
    chmod +x scripts/start.sh scripts/backup.sh

# Создание директорий для данных
RUN mkdir -p \
    /app/data/quarantine \
    /app/data/encrypted \
    /app/data/backups \
    /app/logs/audit \
    /app/logs/system \
    /app/ssl

# Копирование конфигурации supervisor
COPY docker/supervisor.conf /etc/supervisor/conf.d/casb.conf

# Копирование конфигурации nginx
COPY docker/nginx.conf /etc/nginx/sites-available/casb
RUN ln -sf /etc/nginx/sites-available/casb /etc/nginx/sites-enabled/default

# Открытие портов
EXPOSE 80 443 5000 9090

# Настройка переменных окружения
ENV PYTHONPATH=/app
ENV FLASK_APP=app.py
ENV FLASK_ENV=production
ENV CASB_CONFIG_PATH=/app/config.yaml

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:5000/health || exit 1

# Точка монтирования для данных
VOLUME ["/app/data", "/app/logs", "/app/ssl"]

# Переключение на непривилегированного пользователя
USER casb

# Команда запуска
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/conf.d/casb.conf"]
