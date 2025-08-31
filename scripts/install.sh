#!/bin/bash

# CASB Security System - Installation Script
# Скрипт установки системы CASB

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Настройки установки
INSTALL_DIR="/opt/casb"
SERVICE_USER="casb"
SERVICE_GROUP="casb"
PYTHON_VERSION="3.11"

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

# Проверка прав администратора
check_root() {
    if [ "$EUID" -ne 0 ]; then
        error "Скрипт должен запускаться с правами администратора (sudo)"
        exit 1
    fi
}

# Определение операционной системы
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    else
        error "Не удалось определить операционную систему"
        exit 1
    fi
    
    log "Обнаружена ОС: $OS $VERSION"
}

# Установка зависимостей для Ubuntu/Debian
install_deps_debian() {
    log "Установка зависимостей для Debian/Ubuntu..."
    
    apt-get update
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        python3-dev \
        gcc \
        g++ \
        libmagic1 \
        libmagic-dev \
        sqlite3 \
        nginx \
        supervisor \
        openssl \
        curl \
        wget \
        git \
        cron \
        logrotate \
        rsync
    
    success "Зависимости для Debian/Ubuntu установлены"
}

# Установка зависимостей для CentOS/RHEL/Fedora
install_deps_redhat() {
    log "Установка зависимостей для CentOS/RHEL/Fedora..."
    
    if command -v dnf &> /dev/null; then
        DNF_CMD="dnf"
    else
        DNF_CMD="yum"
    fi
    
    $DNF_CMD update -y
    $DNF_CMD install -y \
        python3 \
        python3-pip \
        python3-devel \
        gcc \
        gcc-c++ \
        file-devel \
        sqlite \
        nginx \
        supervisor \
        openssl \
        curl \
        wget \
        git \
        cronie \
        logrotate \
        rsync
    
    success "Зависимости для CentOS/RHEL/Fedora установлены"
}

# Создание системного пользователя
create_user() {
    log "Создание системного пользователя $SERVICE_USER..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -c "CASB Security System" "$SERVICE_USER"
        success "Пользователь $SERVICE_USER создан"
    else
        log "Пользователь $SERVICE_USER уже существует"
    fi
}

# Создание директорий
create_directories() {
    log "Создание директорий..."
    
    mkdir -p "$INSTALL_DIR"/{data,logs,ssl,backup}
    mkdir -p "$INSTALL_DIR"/data/{quarantine,encrypted,backups}
    mkdir -p "$INSTALL_DIR"/logs/{audit,system,access}
    
    # Установка прав доступа
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    chmod 700 "$INSTALL_DIR"/data/quarantine
    chmod 700 "$INSTALL_DIR"/data/encrypted
    chmod 755 "$INSTALL_DIR"/logs
    chmod 700 "$INSTALL_DIR"/ssl
    
    success "Директории созданы"
}

# Копирование файлов
copy_files() {
    log "Копирование файлов CASB системы..."
    
    # Копирование исходного кода
    cp -r . "$INSTALL_DIR/"
    
    # Удаление ненужных файлов
    rm -rf "$INSTALL_DIR"/.git "$INSTALL_DIR"/.gitignore
    
    # Установка прав доступа
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chmod +x "$INSTALL_DIR"/scripts/*.sh
    
    success "Файлы скопированы"
}

# Установка Python зависимостей
install_python_deps() {
    log "Установка Python зависимостей..."
    
    # Создание виртуального окружения
    python3 -m venv "$INSTALL_DIR/venv"
    
    # Активация виртуального окружения и установка зависимостей
    source "$INSTALL_DIR/venv/bin/activate"
    pip install --upgrade pip
    pip install -r "$INSTALL_DIR/requirements.txt"
    
    # Установка прав доступа
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/venv"
    
    success "Python зависимости установлены"
}

# Настройка конфигурации
setup_config() {
    log "Настройка конфигурации..."
    
    # Генерация секретных ключей
    SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    JWT_SECRET=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
    
    # Обновление конфигурации
    sed -i "s/your-secret-key-change-in-production/$SECRET_KEY/g" "$INSTALL_DIR/config.yaml"
    sed -i "s/jwt-secret-key-change-in-production/$JWT_SECRET/g" "$INSTALL_DIR/config.yaml"
    
    # Установка правильных путей
    sed -i "s|/app/|$INSTALL_DIR/|g" "$INSTALL_DIR/config.yaml"
    
    success "Конфигурация настроена"
}

# Генерация SSL сертификатов
generate_ssl() {
    log "Генерация SSL сертификатов..."
    
    openssl req -x509 -newkey rsa:4096 -keyout "$INSTALL_DIR/ssl/casb.key" -out "$INSTALL_DIR/ssl/casb.crt" \
        -days 365 -nodes -subj "/C=RU/ST=Moscow/L=Moscow/O=CASB/CN=$(hostname -f)" 2>/dev/null
    
    chmod 600 "$INSTALL_DIR/ssl/casb.key"
    chmod 644 "$INSTALL_DIR/ssl/casb.crt"
    chown "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR/ssl"/*
    
    success "SSL сертификаты созданы"
}

# Настройка Nginx
setup_nginx() {
    log "Настройка Nginx..."
    
    # Копирование конфигурации
    cp "$INSTALL_DIR/docker/nginx.conf" /etc/nginx/sites-available/casb
    
    # Обновление путей в конфигурации
    sed -i "s|/app/|$INSTALL_DIR/|g" /etc/nginx/sites-available/casb
    
    # Активация сайта
    ln -sf /etc/nginx/sites-available/casb /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Проверка конфигурации
    nginx -t
    
    # Перезапуск Nginx
    systemctl enable nginx
    systemctl restart nginx
    
    success "Nginx настроен"
}

# Настройка systemd сервиса
setup_systemd() {
    log "Настройка systemd сервиса..."
    
    # Копирование файла сервиса
    cp "$INSTALL_DIR/scripts/casb.service" /etc/systemd/system/
    
    # Обновление путей в сервисе
    sed -i "s|/opt/casb|$INSTALL_DIR|g" /etc/systemd/system/casb.service
    
    # Перезагрузка systemd
    systemctl daemon-reload
    systemctl enable casb
    
    success "Systemd сервис настроен"
}

# Настройка logrotate
setup_logrotate() {
    log "Настройка ротации логов..."
    
    cat > /etc/logrotate.d/casb << EOF
$INSTALL_DIR/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $SERVICE_USER $SERVICE_GROUP
}

$INSTALL_DIR/logs/*/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    copytruncate
    su $SERVICE_USER $SERVICE_GROUP
}
EOF
    
    success "Ротация логов настроена"
}

# Настройка cron задач
setup_cron() {
    log "Настройка cron задач..."
    
    # Создание cron файла для пользователя casb
    cat > /tmp/casb_crontab << EOF
# CASB Security System - Automated Tasks

# Резервное копирование каждый день в 2:00
0 2 * * * $INSTALL_DIR/scripts/backup.sh

# Очистка старых резервных копий каждое воскресенье в 3:00
0 3 * * 0 $INSTALL_DIR/scripts/backup.sh --cleanup

# Проверка состояния системы каждые 15 минут
*/15 * * * * $INSTALL_DIR/scripts/start.sh health >> $INSTALL_DIR/logs/health.log 2>&1

# Очистка временных файлов каждый час
0 * * * * find /tmp -name "casb_*" -mtime +1 -delete

# Анализ логов безопасности каждые 30 минут
*/30 * * * * $INSTALL_DIR/scripts/security_check.sh >> $INSTALL_DIR/logs/security_check.log 2>&1
EOF
    
    # Установка cron задач
    sudo -u "$SERVICE_USER" crontab /tmp/casb_crontab
    rm /tmp/casb_crontab
    
    success "Cron задачи настроены"
}

# Инициализация базы данных
init_database() {
    log "Инициализация базы данных..."
    
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/venv/bin/python" -c "
import sys
sys.path.insert(0, '$INSTALL_DIR')
from casb_core import CASBCore
casb = CASBCore('$INSTALL_DIR/data/casb.db')
print('База данных инициализирована')
"
    
    success "База данных инициализирована"
}

# Настройка firewall
setup_firewall() {
    log "Настройка firewall..."
    
    # UFW (Ubuntu)
    if command -v ufw &> /dev/null; then
        ufw allow 80/tcp
        ufw allow 443/tcp
        ufw allow 22/tcp
        ufw --force enable
        success "UFW firewall настроен"
    # firewalld (CentOS/RHEL)
    elif command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-service=http
        firewall-cmd --permanent --add-service=https
        firewall-cmd --permanent --add-service=ssh
        firewall-cmd --reload
        success "Firewalld настроен"
    else
        warning "Firewall не найден, настройте его вручную"
    fi
}

# Проверка установки
verify_installation() {
    log "Проверка установки..."
    
    # Проверка файлов
    if [ ! -f "$INSTALL_DIR/app.py" ]; then
        error "Основной файл приложения не найден"
        return 1
    fi
    
    # Проверка виртуального окружения
    if [ ! -f "$INSTALL_DIR/venv/bin/python" ]; then
        error "Виртуальное окружение не создано"
        return 1
    fi
    
    # Проверка базы данных
    if [ ! -f "$INSTALL_DIR/data/casb.db" ]; then
        error "База данных не инициализирована"
        return 1
    fi
    
    # Проверка SSL сертификатов
    if [ ! -f "$INSTALL_DIR/ssl/casb.crt" ]; then
        error "SSL сертификаты не созданы"
        return 1
    fi
    
    # Проверка systemd сервиса
    if ! systemctl is-enabled casb &>/dev/null; then
        error "Systemd сервис не активирован"
        return 1
    fi
    
    success "Установка проверена успешно"
}

# Запуск системы
start_system() {
    log "Запуск CASB системы..."
    
    # Запуск сервиса
    systemctl start casb
    
    # Проверка статуса
    sleep 5
    if systemctl is-active --quiet casb; then
        success "CASB система запущена"
        log "Статус сервиса:"
        systemctl status casb --no-pager
    else
        error "Не удалось запустить CASB систему"
        log "Проверьте логи: journalctl -u casb -f"
        return 1
    fi
}

# Показ информации после установки
show_info() {
    log "=== Установка CASB Security System завершена ==="
    echo ""
    echo "Информация о системе:"
    echo "  Директория установки: $INSTALL_DIR"
    echo "  Пользователь сервиса: $SERVICE_USER"
    echo "  Конфигурация: $INSTALL_DIR/config.yaml"
    echo "  Логи: $INSTALL_DIR/logs/"
    echo ""
    echo "Веб-интерфейс:"
    echo "  HTTP:  http://$(hostname -I | awk '{print $1}')/"
    echo "  HTTPS: https://$(hostname -I | awk '{print $1}')/"
    echo "  Логин: admin"
    echo "  Пароль: admin123 (ОБЯЗАТЕЛЬНО СМЕНИТЕ!)"
    echo ""
    echo "Управление сервисом:"
    echo "  Запуск:     sudo systemctl start casb"
    echo "  Остановка:  sudo systemctl stop casb"
    echo "  Перезапуск: sudo systemctl restart casb"
    echo "  Статус:     sudo systemctl status casb"
    echo "  Логи:       sudo journalctl -u casb -f"
    echo ""
    echo "Резервное копирование:"
    echo "  Создание:      sudo -u $SERVICE_USER $INSTALL_DIR/scripts/backup.sh"
    echo "  Восстановление: sudo -u $SERVICE_USER $INSTALL_DIR/scripts/backup.sh restore <имя_копии>"
    echo "  Список копий:   sudo -u $SERVICE_USER $INSTALL_DIR/scripts/backup.sh list"
    echo ""
    echo "ВАЖНО:"
    echo "  1. Смените пароли по умолчанию в $INSTALL_DIR/config.yaml"
    echo "  2. Настройте интеграцию с облачными провайдерами"
    echo "  3. Проверьте настройки firewall"
    echo "  4. Настройте SSL сертификаты от доверенного CA"
    echo ""
}

# Удаление системы (для отладки)
uninstall() {
    log "=== Удаление CASB Security System ==="
    
    # Остановка и отключение сервиса
    systemctl stop casb || true
    systemctl disable casb || true
    rm -f /etc/systemd/system/casb.service
    systemctl daemon-reload
    
    # Удаление пользователя
    userdel -r "$SERVICE_USER" || true
    
    # Удаление файлов
    rm -rf "$INSTALL_DIR"
    rm -f /etc/nginx/sites-enabled/casb
    rm -f /etc/nginx/sites-available/casb
    rm -f /etc/logrotate.d/casb
    
    # Перезапуск Nginx
    systemctl restart nginx || true
    
    success "CASB система удалена"
}

# Обновление системы
update() {
    log "=== Обновление CASB Security System ==="
    
    # Создание резервной копии
    sudo -u "$SERVICE_USER" "$INSTALL_DIR/scripts/backup.sh" --name "pre_update_backup"
    
    # Остановка сервиса
    systemctl stop casb
    
    # Обновление файлов
    cp -r *.py "$INSTALL_DIR/"
    cp -r templates "$INSTALL_DIR/"
    cp -r api "$INSTALL_DIR/"
    cp requirements.txt "$INSTALL_DIR/"
    
    # Обновление зависимостей
    source "$INSTALL_DIR/venv/bin/activate"
    pip install -r "$INSTALL_DIR/requirements.txt" --upgrade
    
    # Установка прав доступа
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    
    # Запуск сервиса
    systemctl start casb
    
    success "Обновление завершено"
}

# Основная функция установки
install() {
    log "=== Установка CASB Security System ==="
    
    check_root
    detect_os
    
    # Установка зависимостей в зависимости от ОС
    case "$OS" in
        *"Ubuntu"*|*"Debian"*)
            install_deps_debian
            ;;
        *"CentOS"*|*"Red Hat"*|*"Fedora"*)
            install_deps_redhat
            ;;
        *)
            warning "Неподдерживаемая ОС: $OS"
            warning "Попытка установки зависимостей для Debian/Ubuntu..."
            install_deps_debian
            ;;
    esac
    
    create_user
    create_directories
    copy_files
    install_python_deps
    setup_config
    generate_ssl
    setup_nginx
    setup_systemd
    setup_logrotate
    setup_cron
    init_database
    setup_firewall
    verify_installation
    start_system
    show_info
}

# Обработка аргументов
case "${1:-install}" in
    install)
        install
        ;;
    uninstall)
        if [ "$EUID" -ne 0 ]; then
            error "Требуются права администратора"
            exit 1
        fi
        read -p "Вы уверены, что хотите удалить CASB систему? (y/N): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            uninstall
        else
            log "Удаление отменено"
        fi
        ;;
    update)
        if [ "$EUID" -ne 0 ]; then
            error "Требуются права администратора"
            exit 1
        fi
        update
        ;;
    *)
        echo "Использование: $0 {install|uninstall|update}"
        echo "  install   - Установка CASB системы"
        echo "  uninstall - Удаление CASB системы"
        echo "  update    - Обновление CASB системы"
        exit 1
        ;;
esac
