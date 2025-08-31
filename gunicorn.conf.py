# Gunicorn Configuration для CASB Security System
# Конфигурация для production развертывания

import multiprocessing
import os

# Основные настройки сервера
bind = "0.0.0.0:5000"
workers = multiprocessing.cpu_count() * 2 + 1
worker_class = "gevent"
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 100
preload_app = True
timeout = 30
keepalive = 5

# Настройки процессов
daemon = False
pidfile = "/tmp/casb_gunicorn.pid"
user = None
group = None
tmp_upload_dir = "/tmp"

# Логирование
accesslog = "/app/logs/access.log"
errorlog = "/app/logs/error.log"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# Настройки SSL (если включено)
keyfile = None
certfile = None
ssl_version = None
cert_reqs = None
ca_certs = None
suppress_ragged_eofs = True

# Настройки производительности
worker_tmp_dir = "/dev/shm"
enable_stdio_inheritance = True

# Настройки безопасности
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190

# Настройки перезапуска
reload = False
reload_engine = "auto"
reload_extra_files = []

# Хуки для дополнительной настройки
def when_ready(server):
    """Вызывается когда сервер готов принимать соединения"""
    server.log.info("CASB Security System готов к работе")

def worker_init(worker):
    """Вызывается при инициализации worker процесса"""
    worker.log.info(f"Worker {worker.pid} инициализирован")

def worker_exit(server, worker):
    """Вызывается при завершении worker процесса"""
    server.log.info(f"Worker {worker.pid} завершен")

def pre_fork(server, worker):
    """Вызывается перед fork worker процесса"""
    pass

def post_fork(server, worker):
    """Вызывается после fork worker процесса"""
    pass

def pre_exec(server):
    """Вызывается перед перезапуском сервера"""
    server.log.info("Перезапуск CASB сервера")

def on_exit(server):
    """Вызывается при выходе из сервера"""
    server.log.info("CASB сервер завершен")

def on_reload(server):
    """Вызывается при перезагрузке конфигурации"""
    server.log.info("Перезагрузка конфигурации CASB")

# Дополнительные настройки из переменных окружения
if os.getenv('CASB_WORKERS'):
    workers = int(os.getenv('CASB_WORKERS'))

if os.getenv('CASB_BIND'):
    bind = os.getenv('CASB_BIND')

if os.getenv('CASB_TIMEOUT'):
    timeout = int(os.getenv('CASB_TIMEOUT'))

if os.getenv('CASB_SSL_CERT') and os.getenv('CASB_SSL_KEY'):
    certfile = os.getenv('CASB_SSL_CERT')
    keyfile = os.getenv('CASB_SSL_KEY')

# Настройки для development режима
if os.getenv('FLASK_ENV') == 'development':
    reload = True
    loglevel = "debug"
    workers = 1
