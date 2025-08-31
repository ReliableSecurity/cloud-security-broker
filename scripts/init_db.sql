-- CASB Security System - Database Initialization Script
-- Создание базы данных и таблиц для PostgreSQL

-- Создание расширений
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Создание схемы для CASB
CREATE SCHEMA IF NOT EXISTS casb;

-- Таблица пользователей
CREATE TABLE IF NOT EXISTS casb.users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    department VARCHAR(100),
    is_active BOOLEAN DEFAULT true,
    mfa_enabled BOOLEAN DEFAULT false,
    mfa_secret VARCHAR(32),
    backup_codes TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP
);

-- Таблица облачных сервисов
CREATE TABLE IF NOT EXISTS casb.cloud_services (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(100) NOT NULL,
    provider VARCHAR(50) NOT NULL,
    service_type VARCHAR(50) NOT NULL,
    endpoint_url VARCHAR(500),
    region VARCHAR(50),
    is_active BOOLEAN DEFAULT true,
    risk_score INTEGER DEFAULT 0,
    compliance_status VARCHAR(50) DEFAULT 'unknown',
    last_scanned TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица запросов доступа
CREATE TABLE IF NOT EXISTS casb.access_requests (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES casb.users(id),
    service_id UUID REFERENCES casb.cloud_services(id),
    request_type VARCHAR(50) NOT NULL,
    resource_path VARCHAR(500),
    action VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending',
    risk_score INTEGER DEFAULT 0,
    source_ip INET,
    user_agent TEXT,
    geolocation JSONB,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed_at TIMESTAMP,
    approved_by UUID REFERENCES casb.users(id),
    denial_reason TEXT
);

-- Таблица политик безопасности
CREATE TABLE IF NOT EXISTS casb.security_policies (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(200) NOT NULL,
    description TEXT,
    policy_type VARCHAR(50) NOT NULL,
    scope VARCHAR(50) NOT NULL,
    conditions JSONB NOT NULL,
    action VARCHAR(50) NOT NULL,
    priority INTEGER DEFAULT 1,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES casb.users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица событий мониторинга
CREATE TABLE IF NOT EXISTS casb.monitoring_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    source_service VARCHAR(100),
    user_id UUID REFERENCES casb.users(id),
    service_id UUID REFERENCES casb.cloud_services(id),
    event_data JSONB,
    message TEXT,
    source_ip INET,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    processed BOOLEAN DEFAULT false,
    alert_sent BOOLEAN DEFAULT false
);

-- Таблица аудита
CREATE TABLE IF NOT EXISTS casb.audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES casb.users(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50),
    resource_id VARCHAR(255),
    details JSONB,
    result VARCHAR(50),
    source_ip INET,
    user_agent TEXT,
    session_id VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица сессий пользователей
CREATE TABLE IF NOT EXISTS casb.user_sessions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES casb.users(id),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица DLP событий
CREATE TABLE IF NOT EXISTS casb.dlp_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    file_name VARCHAR(500) NOT NULL,
    file_path VARCHAR(1000),
    file_size BIGINT,
    file_hash VARCHAR(64),
    scan_result JSONB,
    risk_score INTEGER NOT NULL,
    classification VARCHAR(50),
    action_taken VARCHAR(50),
    user_id UUID REFERENCES casb.users(id),
    service_id UUID REFERENCES casb.cloud_services(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    quarantined BOOLEAN DEFAULT false,
    encrypted BOOLEAN DEFAULT false
);

-- Таблица конфигурации системы
CREATE TABLE IF NOT EXISTS casb.system_config (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    config_key VARCHAR(100) UNIQUE NOT NULL,
    config_value TEXT,
    config_type VARCHAR(50) DEFAULT 'string',
    description TEXT,
    is_sensitive BOOLEAN DEFAULT false,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Таблица учетных данных облачных провайдеров
CREATE TABLE IF NOT EXISTS casb.cloud_credentials (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(50) NOT NULL,
    credential_name VARCHAR(100) NOT NULL,
    credentials JSONB NOT NULL, -- зашифрованные учетные данные
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES casb.users(id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_used TIMESTAMP
);

-- Таблица кэша ресурсов
CREATE TABLE IF NOT EXISTS casb.resource_cache (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    provider VARCHAR(50) NOT NULL,
    service_type VARCHAR(50) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255) NOT NULL,
    resource_data JSONB NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    UNIQUE(provider, service_type, resource_id)
);

-- Создание индексов для оптимизации производительности
CREATE INDEX IF NOT EXISTS idx_users_username ON casb.users(username);
CREATE INDEX IF NOT EXISTS idx_users_email ON casb.users(email);
CREATE INDEX IF NOT EXISTS idx_users_role ON casb.users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON casb.users(is_active);

CREATE INDEX IF NOT EXISTS idx_access_requests_user ON casb.access_requests(user_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_service ON casb.access_requests(service_id);
CREATE INDEX IF NOT EXISTS idx_access_requests_status ON casb.access_requests(status);
CREATE INDEX IF NOT EXISTS idx_access_requests_created ON casb.access_requests(created_at);

CREATE INDEX IF NOT EXISTS idx_security_policies_type ON casb.security_policies(policy_type);
CREATE INDEX IF NOT EXISTS idx_security_policies_active ON casb.security_policies(is_active);
CREATE INDEX IF NOT EXISTS idx_security_policies_priority ON casb.security_policies(priority);

CREATE INDEX IF NOT EXISTS idx_monitoring_events_type ON casb.monitoring_events(event_type);
CREATE INDEX IF NOT EXISTS idx_monitoring_events_severity ON casb.monitoring_events(severity);
CREATE INDEX IF NOT EXISTS idx_monitoring_events_created ON casb.monitoring_events(created_at);
CREATE INDEX IF NOT EXISTS idx_monitoring_events_processed ON casb.monitoring_events(processed);

CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON casb.audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON casb.audit_logs(action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON casb.audit_logs(created_at);

CREATE INDEX IF NOT EXISTS idx_user_sessions_user ON casb.user_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_sessions_token ON casb.user_sessions(session_token);
CREATE INDEX IF NOT EXISTS idx_user_sessions_active ON casb.user_sessions(is_active);

CREATE INDEX IF NOT EXISTS idx_dlp_events_risk ON casb.dlp_events(risk_score);
CREATE INDEX IF NOT EXISTS idx_dlp_events_created ON casb.dlp_events(created_at);
CREATE INDEX IF NOT EXISTS idx_dlp_events_action ON casb.dlp_events(action_taken);

CREATE INDEX IF NOT EXISTS idx_cloud_credentials_provider ON casb.cloud_credentials(provider);
CREATE INDEX IF NOT EXISTS idx_cloud_credentials_active ON casb.cloud_credentials(is_active);

CREATE INDEX IF NOT EXISTS idx_resource_cache_provider ON casb.resource_cache(provider, service_type);
CREATE INDEX IF NOT EXISTS idx_resource_cache_expires ON casb.resource_cache(expires_at);

-- Создание представлений для упрощения запросов
CREATE OR REPLACE VIEW casb.active_users AS
SELECT 
    u.id,
    u.username,
    u.email,
    u.role,
    u.department,
    u.mfa_enabled,
    u.last_login,
    COUNT(s.id) as active_sessions
FROM casb.users u
LEFT JOIN casb.user_sessions s ON u.id = s.user_id AND s.is_active = true
WHERE u.is_active = true
GROUP BY u.id, u.username, u.email, u.role, u.department, u.mfa_enabled, u.last_login;

CREATE OR REPLACE VIEW casb.security_dashboard AS
SELECT 
    (SELECT COUNT(*) FROM casb.access_requests WHERE created_at > CURRENT_DATE) as daily_requests,
    (SELECT COUNT(*) FROM casb.access_requests WHERE status = 'blocked' AND created_at > CURRENT_DATE) as blocked_requests,
    (SELECT COUNT(*) FROM casb.monitoring_events WHERE severity IN ('high', 'critical') AND created_at > CURRENT_DATE) as threat_detections,
    (SELECT COUNT(*) FROM casb.active_users) as active_users,
    (SELECT COUNT(*) FROM casb.dlp_events WHERE created_at > CURRENT_DATE) as dlp_events,
    (SELECT COUNT(*) FROM casb.security_policies WHERE is_active = true) as active_policies;

-- Функция для автоматического обновления updated_at
CREATE OR REPLACE FUNCTION casb.update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Триггеры для автоматического обновления updated_at
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON casb.users 
    FOR EACH ROW EXECUTE FUNCTION casb.update_updated_at_column();

CREATE TRIGGER update_cloud_services_updated_at BEFORE UPDATE ON casb.cloud_services 
    FOR EACH ROW EXECUTE FUNCTION casb.update_updated_at_column();

CREATE TRIGGER update_security_policies_updated_at BEFORE UPDATE ON casb.security_policies 
    FOR EACH ROW EXECUTE FUNCTION casb.update_updated_at_column();

CREATE TRIGGER update_cloud_credentials_updated_at BEFORE UPDATE ON casb.cloud_credentials 
    FOR EACH ROW EXECUTE FUNCTION casb.update_updated_at_column();

CREATE TRIGGER update_system_config_updated_at BEFORE UPDATE ON casb.system_config 
    FOR EACH ROW EXECUTE FUNCTION casb.update_updated_at_column();

-- Вставка начальных данных
INSERT INTO casb.users (username, email, password_hash, role) VALUES 
('admin', 'admin@casb.local', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LdHydcyOG0dWL4ot6', 'admin') -- пароль: admin123
ON CONFLICT (username) DO NOTHING;

INSERT INTO casb.system_config (config_key, config_value, config_type, description) VALUES 
('system_initialized', 'true', 'boolean', 'Флаг инициализации системы'),
('default_risk_threshold', '70', 'integer', 'Порог риска по умолчанию'),
('audit_retention_days', '365', 'integer', 'Срок хранения аудит логов'),
('session_timeout', '3600', 'integer', 'Время жизни сессии в секундах')
ON CONFLICT (config_key) DO NOTHING;

-- Создание политик безопасности по умолчанию
INSERT INTO casb.security_policies (name, description, policy_type, scope, conditions, action, priority) VALUES 
(
    'Блокировка подозрительных IP',
    'Автоматическая блокировка запросов с подозрительных IP адресов',
    'access_control',
    'global',
    '[{"field": "source_ip", "operator": "in_blacklist", "value": "suspicious_ips"}]'::jsonb,
    'block',
    1
),
(
    'Требование MFA для администраторов',
    'Обязательная многофакторная аутентификация для административных ролей',
    'authentication',
    'role',
    '[{"field": "user_role", "operator": "equals", "value": "admin"}]'::jsonb,
    'require_mfa',
    2
),
(
    'Ограничение доступа по времени',
    'Разрешение доступа только в рабочее время',
    'access_control',
    'time',
    '[{"field": "access_time", "operator": "between", "value": "09:00-18:00"}, {"field": "access_day", "operator": "in", "value": [1,2,3,4,5]}]'::jsonb,
    'allow',
    3
),
(
    'Шифрование конфиденциальных файлов',
    'Автоматическое шифрование файлов с высокой степенью конфиденциальности',
    'data_protection',
    'data',
    '[{"field": "data_classification", "operator": "equals", "value": "confidential"}]'::jsonb,
    'encrypt',
    4
)
ON CONFLICT DO NOTHING;

-- Функция очистки старых логов
CREATE OR REPLACE FUNCTION casb.cleanup_old_logs()
RETURNS INTEGER AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    -- Удаление старых аудит логов (старше 1 года)
    DELETE FROM casb.audit_logs WHERE created_at < CURRENT_DATE - INTERVAL '365 days';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    
    -- Удаление старых событий мониторинга (старше 90 дней)
    DELETE FROM casb.monitoring_events WHERE created_at < CURRENT_DATE - INTERVAL '90 days';
    
    -- Удаление истекших сессий
    DELETE FROM casb.user_sessions WHERE expires_at < CURRENT_TIMESTAMP;
    
    -- Удаление истекшего кэша
    DELETE FROM casb.resource_cache WHERE expires_at < CURRENT_TIMESTAMP;
    
    RETURN deleted_count;
END;
$$ LANGUAGE plpgsql;

-- Создание роли для приложения
DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'casb_app') THEN
        CREATE ROLE casb_app WITH LOGIN PASSWORD 'casb_app_password_change_me';
    END IF;
END
$$;

-- Предоставление прав для роли приложения
GRANT USAGE ON SCHEMA casb TO casb_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA casb TO casb_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA casb TO casb_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA casb TO casb_app;

-- Настройка автоматической очистки (выполняется через cron или pg_cron)
-- SELECT cron.schedule('cleanup-logs', '0 3 * * *', 'SELECT casb.cleanup_old_logs();');

COMMIT;
