#!/bin/bash

# CASB Security System - Startup Script
# Скрипт запуска системы CASB для производственной среды

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция логирования
log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Проверка переменных окружения
check_environment() {
    log "Проверка переменных окружения..."
    
    if [ -z "$CASB_CONFIG_PATH" ]; then
        export CASB_CONFIG_PATH="/app/config.yaml"
        warning "CASB_CONFIG_PATH не установлен, используется /app/config.yaml"
    fi
    
    if [ -z "$FLASK_ENV" ]; then
        export FLASK_ENV="production"
        warning "FLASK_ENV не установлен, используется production"
    fi
    
    if [ -z "$PYTHONPATH" ]; then
        export PYTHONPATH="/app"
        warning "PYTHONPATH не установлен, используется /app"
    fi
}

# Проверка зависимостей
check_dependencies() {
    log "Проверка зависимостей..."
    
    # Проверка Python
    if ! command -v python3 &> /dev/null; then
        error "Python3 не найден"
        exit 1
    fi
    
    # Проверка pip пакетов
    if ! python3 -c "import flask, cryptography, pyotp" &> /dev/null; then
        error "Не все Python зависимости установлены"
        exit 1
    fi
    
    success "Зависимости проверены"
}

# Создание необходимых директорий
create_directories() {
    log "Создание директорий..."
    
    mkdir -p /app/data/{quarantine,encrypted,backups}
    mkdir -p /app/logs/{audit,system,access}
    mkdir -p /app/ssl
    mkdir -p /tmp/casb
    
    # Установка прав доступа
    chmod 700 /app/data/quarantine
    chmod 700 /app/data/encrypted
    chmod 755 /app/logs
    chmod 700 /app/ssl
    
    success "Директории созданы"
}

# Инициализация базы данных
init_database() {
    log "Инициализация базы данных..."
    
    if [ -f "/app/casb_core.py" ]; then
        python3 -c "
from casb_core import CASBCore
import os
os.makedirs('/app/data', exist_ok=True)
casb = CASBCore('/app/data/casb.db')
print('База данных инициализирована')
"
        success "База данных SQLite инициализирована"
    else
        warning "Файл casb_core.py не найден, пропускаем инициализацию"
    fi
}

# Проверка конфигурации
check_config() {
    log "Проверка конфигурации..."
    
    if [ ! -f "$CASB_CONFIG_PATH" ]; then
        error "Файл конфигурации не найден: $CASB_CONFIG_PATH"
        exit 1
    fi
    
    # Проверка YAML синтаксиса
    if command -v python3 &> /dev/null; then
        python3 -c "
import yaml
try:
    with open('$CASB_CONFIG_PATH', 'r', encoding='utf-8') as f:
        yaml.safe_load(f)
    print('Конфигурация валидна')
except Exception as e:
    print(f'Ошибка в конфигурации: {e}')
    exit(1)
"
    fi
    
    success "Конфигурация проверена"
}

# Генерация SSL сертификатов (для разработки)
generate_ssl_certs() {
    if [ "$FLASK_ENV" = "development" ] && [ ! -f "/app/ssl/casb.crt" ]; then
        log "Генерация SSL сертификатов для разработки..."
        
        openssl req -x509 -newkey rsa:4096 -keyout /app/ssl/casb.key -out /app/ssl/casb.crt \
            -days 365 -nodes -subj "/C=RU/ST=Moscow/L=Moscow/O=CASB/CN=localhost" 2>/dev/null
        
        chmod 600 /app/ssl/casb.key
        chmod 644 /app/ssl/casb.crt
        
        success "SSL сертификаты созданы"
    fi
}

# Проверка здоровья системы
health_check() {
    log "Проверка состояния системы..."
    
    # Проверка свободного места на диске
    DISK_USAGE=$(df /app | tail -1 | awk '{print $5}' | sed 's/%//')
    if [ "$DISK_USAGE" -gt 85 ]; then
        warning "Мало свободного места на диске: ${DISK_USAGE}%"
    fi
    
    # Проверка использования памяти
    if command -v free &> /dev/null; then
        MEMORY_USAGE=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100.0)}')
        if [ "$MEMORY_USAGE" -gt 90 ]; then
            warning "Высокое использование памяти: ${MEMORY_USAGE}%"
        fi
    fi
    
    success "Проверка здоровья завершена"
}

# Запуск CASB системы
start_casb() {
    log "Запуск CASB Security System..."
    
    # Определение режима запуска
    if [ "$FLASK_ENV" = "development" ]; then
        log "Запуск в режиме разработки..."
        python3 app.py
    elif [ "$FLASK_ENV" = "production" ]; then
        log "Запуск в производственном режиме..."
        
        # Использование Gunicorn для production
        if command -v gunicorn &> /dev/null; then
            gunicorn -c gunicorn.conf.py app:app
        else
            warning "Gunicorn не найден, запуск через Flask (не рекомендуется для production)"
            python3 app.py
        fi
    else
        log "Запуск в стандартном режиме..."
        python3 app.py
    fi
}

# Функция остановки
stop_casb() {
    log "Остановка CASB Security System..."
    
    # Найти и остановить процессы
    pkill -f "python.*app.py" || true
    pkill -f "gunicorn.*app:app" || true
    
    success "CASB система остановлена"
}

# Функция перезапуска
restart_casb() {
    log "Перезапуск CASB Security System..."
    stop_casb
    sleep 2
    start_casb
}

# Обработка сигналов
trap 'stop_casb; exit 0' SIGTERM SIGINT

# Основная логика
main() {
    case "${1:-start}" in
        start)
            log "=== Запуск CASB Security System ==="
            check_environment
            check_dependencies
            create_directories
            check_config
            generate_ssl_certs
            init_database
            health_check
            start_casb
            ;;
        stop)
            stop_casb
            ;;
        restart)
            restart_casb
            ;;
        status)
            if pgrep -f "python.*app.py\|gunicorn.*app:app" > /dev/null; then
                success "CASB система запущена"
                ps aux | grep -E "python.*app.py|gunicorn.*app:app" | grep -v grep
            else
                warning "CASB система не запущена"
            fi
            ;;
        health)
            health_check
            ;;
        *)
            echo "Использование: $0 {start|stop|restart|status|health}"
            echo "  start   - Запуск системы"
            echo "  stop    - Остановка системы"
            echo "  restart - Перезапуск системы"
            echo "  status  - Проверка статуса"
            echo "  health  - Проверка здоровья системы"
            exit 1
            ;;
    esac
}

# Запуск основной функции
main "$@"
