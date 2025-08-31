#!/bin/bash

# CASB Security System - Backup Script
# Скрипт резервного копирования данных системы CASB

set -e

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Настройки по умолчанию
BACKUP_DIR="/app/data/backups"
DATA_DIR="/app/data"
LOGS_DIR="/app/logs"
CONFIG_DIR="/app"
RETENTION_DAYS=30
COMPRESS=true
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_NAME="casb_backup_${TIMESTAMP}"

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

# Функция показа справки
show_help() {
    echo "CASB Security System - Backup Script"
    echo ""
    echo "Использование: $0 [OPTIONS]"
    echo ""
    echo "Опции:"
    echo "  -d, --dir DIR          Директория для сохранения резервных копий (по умолчанию: $BACKUP_DIR)"
    echo "  -r, --retention DAYS   Количество дней хранения резервных копий (по умолчанию: $RETENTION_DAYS)"
    echo "  -n, --name NAME        Имя резервной копии (по умолчанию: casb_backup_TIMESTAMP)"
    echo "  --no-compress          Не сжимать резервную копию"
    echo "  --database-only        Резервная копия только базы данных"
    echo "  --config-only          Резервная копия только конфигурации"
    echo "  --logs-only            Резервная копия только логов"
    echo "  --cleanup              Только очистка старых резервных копий"
    echo "  -h, --help             Показать эту справку"
    echo ""
    echo "Примеры:"
    echo "  $0                     # Полная резервная копия"
    echo "  $0 --database-only     # Только база данных"
    echo "  $0 --cleanup           # Очистка старых резервных копий"
}

# Обработка аргументов командной строки
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -d|--dir)
                BACKUP_DIR="$2"
                shift 2
                ;;
            -r|--retention)
                RETENTION_DAYS="$2"
                shift 2
                ;;
            -n|--name)
                BACKUP_NAME="$2"
                shift 2
                ;;
            --no-compress)
                COMPRESS=false
                shift
                ;;
            --database-only)
                BACKUP_TYPE="database"
                shift
                ;;
            --config-only)
                BACKUP_TYPE="config"
                shift
                ;;
            --logs-only)
                BACKUP_TYPE="logs"
                shift
                ;;
            --cleanup)
                BACKUP_TYPE="cleanup"
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                error "Неизвестная опция: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Создание директории для резервных копий
create_backup_dir() {
    log "Создание директории резервных копий: $BACKUP_DIR"
    mkdir -p "$BACKUP_DIR"
    chmod 700 "$BACKUP_DIR"
}

# Резервная копия базы данных
backup_database() {
    log "Создание резервной копии базы данных..."
    
    local db_backup_dir="$BACKUP_DIR/$BACKUP_NAME/database"
    mkdir -p "$db_backup_dir"
    
    # SQLite база данных
    if [ -f "$DATA_DIR/casb.db" ]; then
        log "Копирование SQLite базы данных..."
        sqlite3 "$DATA_DIR/casb.db" ".backup '$db_backup_dir/casb.db'"
        
        # Создание SQL дампа для восстановления
        sqlite3 "$DATA_DIR/casb.db" ".dump" > "$db_backup_dir/casb_dump.sql"
        
        success "SQLite база данных скопирована"
    fi
    
    # PostgreSQL база данных (если используется)
    if [ ! -z "$POSTGRES_HOST" ] && command -v pg_dump &> /dev/null; then
        log "Создание дампа PostgreSQL..."
        pg_dump -h "$POSTGRES_HOST" -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
            > "$db_backup_dir/postgres_dump.sql"
        success "PostgreSQL дамп создан"
    fi
}

# Резервная копия конфигурации
backup_config() {
    log "Создание резервной копии конфигурации..."
    
    local config_backup_dir="$BACKUP_DIR/$BACKUP_NAME/config"
    mkdir -p "$config_backup_dir"
    
    # Копирование конфигурационных файлов
    [ -f "$CONFIG_DIR/config.yaml" ] && cp "$CONFIG_DIR/config.yaml" "$config_backup_dir/"
    [ -f "$CONFIG_DIR/requirements.txt" ] && cp "$CONFIG_DIR/requirements.txt" "$config_backup_dir/"
    [ -f "$CONFIG_DIR/gunicorn.conf.py" ] && cp "$CONFIG_DIR/gunicorn.conf.py" "$config_backup_dir/"
    
    # Копирование SSL сертификатов
    if [ -d "/app/ssl" ] && [ "$(ls -A /app/ssl)" ]; then
        cp -r /app/ssl "$config_backup_dir/"
    fi
    
    success "Конфигурация скопирована"
}

# Резервная копия логов
backup_logs() {
    log "Создание резервной копии логов..."
    
    local logs_backup_dir="$BACKUP_DIR/$BACKUP_NAME/logs"
    mkdir -p "$logs_backup_dir"
    
    # Копирование логов
    if [ -d "$LOGS_DIR" ] && [ "$(ls -A $LOGS_DIR)" ]; then
        cp -r "$LOGS_DIR"/* "$logs_backup_dir/" || true
    fi
    
    success "Логи скопированы"
}

# Резервная копия пользовательских данных
backup_user_data() {
    log "Создание резервной копии пользовательских данных..."
    
    local data_backup_dir="$BACKUP_DIR/$BACKUP_NAME/user_data"
    mkdir -p "$data_backup_dir"
    
    # Копирование зашифрованных файлов
    if [ -d "$DATA_DIR/encrypted" ] && [ "$(ls -A $DATA_DIR/encrypted)" ]; then
        cp -r "$DATA_DIR/encrypted" "$data_backup_dir/"
    fi
    
    # Копирование карантинных файлов (только метаданные)
    if [ -d "$DATA_DIR/quarantine" ]; then
        mkdir -p "$data_backup_dir/quarantine"
        find "$DATA_DIR/quarantine" -name "*.meta" -exec cp {} "$data_backup_dir/quarantine/" \;
    fi
    
    success "Пользовательские данные скопированы"
}

# Создание метаданных резервной копии
create_backup_metadata() {
    log "Создание метаданных резервной копии..."
    
    local metadata_file="$BACKUP_DIR/$BACKUP_NAME/backup_metadata.json"
    
    cat > "$metadata_file" << EOF
{
    "backup_name": "$BACKUP_NAME",
    "timestamp": "$TIMESTAMP",
    "creation_date": "$(date -Iseconds)",
    "hostname": "$(hostname)",
    "casb_version": "1.0.0",
    "backup_type": "${BACKUP_TYPE:-full}",
    "compression": $COMPRESS,
    "retention_days": $RETENTION_DAYS,
    "components": {
        "database": $([ -d "$BACKUP_DIR/$BACKUP_NAME/database" ] && echo "true" || echo "false"),
        "config": $([ -d "$BACKUP_DIR/$BACKUP_NAME/config" ] && echo "true" || echo "false"),
        "logs": $([ -d "$BACKUP_DIR/$BACKUP_NAME/logs" ] && echo "true" || echo "false"),
        "user_data": $([ -d "$BACKUP_DIR/$BACKUP_NAME/user_data" ] && echo "true" || echo "false")
    },
    "size_bytes": $(du -sb "$BACKUP_DIR/$BACKUP_NAME" | cut -f1),
    "file_count": $(find "$BACKUP_DIR/$BACKUP_NAME" -type f | wc -l)
}
EOF
    
    success "Метаданные созданы"
}

# Сжатие резервной копии
compress_backup() {
    if [ "$COMPRESS" = true ]; then
        log "Сжатие резервной копии..."
        
        cd "$BACKUP_DIR"
        tar -czf "${BACKUP_NAME}.tar.gz" "$BACKUP_NAME"
        
        if [ $? -eq 0 ]; then
            rm -rf "$BACKUP_NAME"
            success "Резервная копия сжата: ${BACKUP_NAME}.tar.gz"
        else
            error "Ошибка при сжатии резервной копии"
            return 1
        fi
    fi
}

# Очистка старых резервных копий
cleanup_old_backups() {
    log "Очистка старых резервных копий (старше $RETENTION_DAYS дней)..."
    
    local deleted_count=0
    
    # Удаление старых сжатых резервных копий
    find "$BACKUP_DIR" -name "casb_backup_*.tar.gz" -mtime +$RETENTION_DAYS -type f | while read -r file; do
        log "Удаление старой резервной копии: $(basename "$file")"
        rm -f "$file"
        ((deleted_count++))
    done
    
    # Удаление старых несжатых резервных копий
    find "$BACKUP_DIR" -name "casb_backup_*" -mtime +$RETENTION_DAYS -type d | while read -r dir; do
        log "Удаление старой резервной копии: $(basename "$dir")"
        rm -rf "$dir"
        ((deleted_count++))
    done
    
    if [ $deleted_count -gt 0 ]; then
        success "Удалено $deleted_count старых резервных копий"
    else
        log "Старые резервные копии не найдены"
    fi
}

# Проверка целостности резервной копии
verify_backup() {
    log "Проверка целостности резервной копии..."
    
    local backup_path
    if [ "$COMPRESS" = true ]; then
        backup_path="$BACKUP_DIR/${BACKUP_NAME}.tar.gz"
        
        # Проверка архива
        if tar -tzf "$backup_path" >/dev/null 2>&1; then
            success "Архив резервной копии корректен"
        else
            error "Архив резервной копии поврежден"
            return 1
        fi
    else
        backup_path="$BACKUP_DIR/$BACKUP_NAME"
        
        # Проверка структуры директории
        if [ -d "$backup_path" ] && [ -f "$backup_path/backup_metadata.json" ]; then
            success "Структура резервной копии корректна"
        else
            error "Структура резервной копии нарушена"
            return 1
        fi
    fi
    
    # Вычисление и сохранение контрольной суммы
    local checksum_file="$BACKUP_DIR/${BACKUP_NAME}.sha256"
    if [ "$COMPRESS" = true ]; then
        sha256sum "$backup_path" > "$checksum_file"
    else
        find "$backup_path" -type f -exec sha256sum {} \; | sort > "$checksum_file"
    fi
    
    success "Контрольная сумма сохранена: ${BACKUP_NAME}.sha256"
}

# Отправка уведомления о резервном копировании
send_notification() {
    local status="$1"
    local message="$2"
    
    log "Отправка уведомления о резервном копировании..."
    
    # Здесь можно добавить интеграцию с системами уведомлений
    # Например, отправка email, Slack, Telegram и т.д.
    
    # Пример записи в лог
    echo "$(date -Iseconds) - Backup $status: $message" >> "$LOGS_DIR/backup.log"
}

# Основная функция резервного копирования
perform_backup() {
    log "=== Начало резервного копирования CASB ==="
    log "Тип резервной копии: ${BACKUP_TYPE:-full}"
    log "Имя резервной копии: $BACKUP_NAME"
    
    local start_time=$(date +%s)
    
    create_backup_dir
    
    case "${BACKUP_TYPE:-full}" in
        database)
            backup_database
            ;;
        config)
            backup_config
            ;;
        logs)
            backup_logs
            ;;
        full)
            backup_database
            backup_config
            backup_logs
            backup_user_data
            ;;
    esac
    
    create_backup_metadata
    compress_backup
    verify_backup
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    success "Резервное копирование завершено за ${duration}s"
    
    # Статистика
    if [ "$COMPRESS" = true ]; then
        local backup_size=$(du -h "$BACKUP_DIR/${BACKUP_NAME}.tar.gz" | cut -f1)
        log "Размер резервной копии: $backup_size"
    else
        local backup_size=$(du -h "$BACKUP_DIR/$BACKUP_NAME" | cut -f1)
        log "Размер резервной копии: $backup_size"
    fi
    
    send_notification "SUCCESS" "Резервная копия $BACKUP_NAME создана успешно"
}

# Восстановление из резервной копии
restore_backup() {
    local backup_name="$1"
    
    if [ -z "$backup_name" ]; then
        error "Не указано имя резервной копии для восстановления"
        echo "Доступные резервные копии:"
        ls -la "$BACKUP_DIR"/ | grep -E "casb_backup_|\.tar\.gz$" || echo "Резервные копии не найдены"
        return 1
    fi
    
    log "=== Восстановление из резервной копии: $backup_name ==="
    
    # Проверка существования резервной копии
    local backup_path="$BACKUP_DIR/$backup_name"
    local compressed_path="$BACKUP_DIR/${backup_name}.tar.gz"
    
    if [ -f "$compressed_path" ]; then
        log "Извлечение сжатой резервной копии..."
        cd "$BACKUP_DIR"
        tar -xzf "${backup_name}.tar.gz"
        backup_path="$BACKUP_DIR/$backup_name"
    elif [ ! -d "$backup_path" ]; then
        error "Резервная копия не найдена: $backup_name"
        return 1
    fi
    
    # Остановка системы перед восстановлением
    warning "Остановка CASB системы для восстановления..."
    pkill -f "python.*app.py" || true
    pkill -f "gunicorn.*app:app" || true
    sleep 2
    
    # Создание резервной копии текущих данных
    local current_backup="casb_backup_before_restore_$(date +%Y%m%d_%H%M%S)"
    log "Создание резервной копии текущих данных: $current_backup"
    mkdir -p "$BACKUP_DIR/$current_backup"
    cp -r "$DATA_DIR" "$BACKUP_DIR/$current_backup/" 2>/dev/null || true
    
    # Восстановление данных
    if [ -d "$backup_path/database" ]; then
        log "Восстановление базы данных..."
        [ -f "$backup_path/database/casb.db" ] && cp "$backup_path/database/casb.db" "$DATA_DIR/"
    fi
    
    if [ -d "$backup_path/config" ]; then
        log "Восстановление конфигурации..."
        [ -f "$backup_path/config/config.yaml" ] && cp "$backup_path/config/config.yaml" "$CONFIG_DIR/"
        
        # Восстановление SSL сертификатов
        if [ -d "$backup_path/config/ssl" ]; then
            cp -r "$backup_path/config/ssl" /app/
        fi
    fi
    
    if [ -d "$backup_path/user_data" ]; then
        log "Восстановление пользовательских данных..."
        [ -d "$backup_path/user_data/encrypted" ] && cp -r "$backup_path/user_data/encrypted" "$DATA_DIR/"
    fi
    
    success "Восстановление завершено"
    log "Резервная копия текущих данных сохранена в: $current_backup"
    warning "Не забудьте перезапустить CASB систему"
}

# Список резервных копий
list_backups() {
    log "Доступные резервные копии:"
    
    if [ ! -d "$BACKUP_DIR" ]; then
        warning "Директория резервных копий не существует: $BACKUP_DIR"
        return 0
    fi
    
    echo ""
    echo "Сжатые резервные копии:"
    find "$BACKUP_DIR" -name "casb_backup_*.tar.gz" -printf "%f\t%TY-%Tm-%Td %TH:%TM\t%s bytes\n" | sort -r | head -20
    
    echo ""
    echo "Несжатые резервные копии:"
    find "$BACKUP_DIR" -name "casb_backup_*" -type d -printf "%f\t%TY-%Tm-%Td %TH:%TM\n" | sort -r | head -10
}

# Проверка резервной копии
verify_backup_integrity() {
    local backup_name="$1"
    
    if [ -z "$backup_name" ]; then
        error "Не указано имя резервной копии для проверки"
        return 1
    fi
    
    log "Проверка целостности резервной копии: $backup_name"
    
    local checksum_file="$BACKUP_DIR/${backup_name}.sha256"
    local backup_file="$BACKUP_DIR/${backup_name}.tar.gz"
    
    if [ -f "$checksum_file" ] && [ -f "$backup_file" ]; then
        if sha256sum -c "$checksum_file"; then
            success "Целостность резервной копии подтверждена"
        else
            error "Нарушена целостность резервной копии"
            return 1
        fi
    else
        warning "Файл контрольной суммы не найден"
    fi
}

# Основная логика
main() {
    parse_arguments "$@"
    
    case "${BACKUP_TYPE:-full}" in
        cleanup)
            cleanup_old_backups
            ;;
        full|database|config|logs)
            perform_backup
            cleanup_old_backups
            ;;
        restore)
            if [ -z "$2" ]; then
                list_backups
                echo ""
                echo "Для восстановления используйте: $0 restore <имя_резервной_копии>"
            else
                restore_backup "$2"
            fi
            ;;
        list)
            list_backups
            ;;
        verify)
            if [ -z "$2" ]; then
                echo "Использование: $0 verify <имя_резервной_копии>"
                list_backups
            else
                verify_backup_integrity "$2"
            fi
            ;;
        *)
            error "Неизвестный тип резервного копирования: $BACKUP_TYPE"
            show_help
            exit 1
            ;;
    esac
}

# Обработка сигналов
trap 'error "Резервное копирование прервано"; exit 1' SIGTERM SIGINT

# Проверка аргументов и запуск
if [ "$1" = "restore" ] || [ "$1" = "list" ] || [ "$1" = "verify" ]; then
    BACKUP_TYPE="$1"
    shift
fi

main "$@"
