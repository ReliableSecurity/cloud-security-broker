#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Advanced Performance Monitor for CASB
Implements caching, database optimization, async processing, and performance analytics

Автор: AI Assistant
"""

import time
import asyncio
import threading
import psutil
import logging
import json
import sqlite3
import redis
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from collections import deque, defaultdict
from functools import wraps, lru_cache
import weakref
import gc
from concurrent.futures import ThreadPoolExecutor, as_completed
import queue
import multiprocessing

logger = logging.getLogger(__name__)

@dataclass
class PerformanceMetric:
    """Метрика производительности"""
    name: str
    value: float
    unit: str
    timestamp: datetime
    tags: Dict[str, str] = None

@dataclass
class SystemMetrics:
    """Системные метрики"""
    cpu_percent: float
    memory_percent: float
    memory_available: int
    disk_usage_percent: float
    network_sent: int
    network_recv: int
    active_connections: int
    timestamp: datetime

class MemoryCache:
    """Расширенный кеш в памяти с TTL и статистикой"""
    
    def __init__(self, max_size: int = 1000, default_ttl: int = 3600):
        self.max_size = max_size
        self.default_ttl = default_ttl
        self._cache = {}
        self._access_times = {}
        self._expiry_times = {}
        self._lock = threading.RLock()
        self._stats = {
            'hits': 0,
            'misses': 0,
            'evictions': 0,
            'size': 0
        }
    
    def get(self, key: str) -> Any:
        """Получение значения из кеша"""
        with self._lock:
            current_time = time.time()
            
            # Проверяем существование и срок жизни
            if key in self._cache:
                if current_time < self._expiry_times[key]:
                    self._access_times[key] = current_time
                    self._stats['hits'] += 1
                    return self._cache[key]
                else:
                    # Удаляем истекший элемент
                    self._remove_key(key)
            
            self._stats['misses'] += 1
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        """Установка значения в кеш"""
        with self._lock:
            current_time = time.time()
            ttl = ttl or self.default_ttl
            
            # Удаляем старое значение если есть
            if key in self._cache:
                self._remove_key(key)
            
            # Проверяем размер кеша
            if len(self._cache) >= self.max_size:
                self._evict_lru()
            
            # Добавляем новое значение
            self._cache[key] = value
            self._access_times[key] = current_time
            self._expiry_times[key] = current_time + ttl
            self._stats['size'] = len(self._cache)
    
    def delete(self, key: str) -> bool:
        """Удаление ключа из кеша"""
        with self._lock:
            if key in self._cache:
                self._remove_key(key)
                return True
            return False
    
    def clear(self):
        """Очистка кеша"""
        with self._lock:
            self._cache.clear()
            self._access_times.clear()
            self._expiry_times.clear()
            self._stats['size'] = 0
            self._stats['evictions'] += 1
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики кеша"""
        with self._lock:
            hit_rate = 0
            if self._stats['hits'] + self._stats['misses'] > 0:
                hit_rate = self._stats['hits'] / (self._stats['hits'] + self._stats['misses'])
            
            return {
                **self._stats,
                'hit_rate': hit_rate,
                'current_size': len(self._cache)
            }
    
    def _remove_key(self, key: str):
        """Удаление ключа из всех структур"""
        if key in self._cache:
            del self._cache[key]
            del self._access_times[key]
            del self._expiry_times[key]
            self._stats['size'] = len(self._cache)
    
    def _evict_lru(self):
        """Удаление наименее используемого элемента"""
        if not self._access_times:
            return
        
        lru_key = min(self._access_times, key=self._access_times.get)
        self._remove_key(lru_key)
        self._stats['evictions'] += 1

class DatabaseOptimizer:
    """Оптимизатор базы данных"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.connection_pool = []
        self.pool_lock = threading.Lock()
        self.max_connections = 10
        
        # Создаем пул соединений
        self._init_connection_pool()
        
        # Статистика запросов
        self.query_stats = defaultdict(lambda: {
            'count': 0,
            'total_time': 0,
            'avg_time': 0,
            'min_time': float('inf'),
            'max_time': 0
        })
    
    def _init_connection_pool(self):
        """Инициализация пула соединений"""
        for _ in range(self.max_connections):
            conn = sqlite3.connect(
                self.db_path, 
                check_same_thread=False,
                timeout=30.0
            )
            conn.execute('PRAGMA journal_mode=WAL')
            conn.execute('PRAGMA synchronous=NORMAL')
            conn.execute('PRAGMA cache_size=10000')
            conn.execute('PRAGMA temp_store=MEMORY')
            self.connection_pool.append(conn)
    
    def get_connection(self):
        """Получение соединения из пула"""
        with self.pool_lock:
            if self.connection_pool:
                return self.connection_pool.pop()
            else:
                # Создаем новое соединение если пул пуст
                conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,
                    timeout=30.0
                )
                conn.execute('PRAGMA journal_mode=WAL')
                conn.execute('PRAGMA synchronous=NORMAL')
                return conn
    
    def return_connection(self, conn):
        """Возврат соединения в пул"""
        with self.pool_lock:
            if len(self.connection_pool) < self.max_connections:
                self.connection_pool.append(conn)
            else:
                conn.close()
    
    def execute_query(self, query: str, params: tuple = None) -> List[tuple]:
        """Выполнение запроса с мониторингом производительности"""
        start_time = time.time()
        conn = self.get_connection()
        
        try:
            cursor = conn.cursor()
            if params:
                cursor.execute(query, params)
            else:
                cursor.execute(query)
            
            result = cursor.fetchall()
            conn.commit()
            
            # Обновляем статистику
            execution_time = time.time() - start_time
            self._update_query_stats(query, execution_time)
            
            return result
            
        except Exception as e:
            logger.error(f"Database query error: {e}")
            conn.rollback()
            raise
        finally:
            self.return_connection(conn)
    
    def _update_query_stats(self, query: str, execution_time: float):
        """Обновление статистики запросов"""
        # Нормализуем запрос для статистики
        query_type = query.strip().split()[0].upper()
        
        stats = self.query_stats[query_type]
        stats['count'] += 1
        stats['total_time'] += execution_time
        stats['avg_time'] = stats['total_time'] / stats['count']
        stats['min_time'] = min(stats['min_time'], execution_time)
        stats['max_time'] = max(stats['max_time'], execution_time)
    
    def get_query_stats(self) -> Dict[str, Any]:
        """Получение статистики запросов"""
        return dict(self.query_stats)
    
    def optimize_database(self):
        """Оптимизация базы данных"""
        conn = self.get_connection()
        try:
            # Анализируем статистику
            conn.execute('ANALYZE')
            
            # Очищаем WAL файл
            conn.execute('PRAGMA wal_checkpoint(TRUNCATE)')
            
            # Вакуумируем базу
            conn.execute('VACUUM')
            
            logger.info("Database optimization completed")
        finally:
            self.return_connection(conn)

class AsyncTaskManager:
    """Менеджер асинхронных задач"""
    
    def __init__(self, max_workers: int = None):
        self.max_workers = max_workers or multiprocessing.cpu_count()
        self.executor = ThreadPoolExecutor(max_workers=self.max_workers)
        self.task_queue = queue.Queue()
        self.running_tasks = {}
        self.completed_tasks = deque(maxlen=1000)
        self._task_id_counter = 0
        self._lock = threading.Lock()
    
    def submit_task(self, func: Callable, *args, **kwargs) -> str:
        """Отправка задачи на выполнение"""
        with self._lock:
            task_id = f"task_{self._task_id_counter}"
            self._task_id_counter += 1
        
        future = self.executor.submit(self._execute_task, task_id, func, *args, **kwargs)
        
        with self._lock:
            self.running_tasks[task_id] = {
                'future': future,
                'start_time': time.time(),
                'function': func.__name__ if hasattr(func, '__name__') else str(func)
            }
        
        return task_id
    
    def _execute_task(self, task_id: str, func: Callable, *args, **kwargs):
        """Выполнение задачи"""
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            
            # Записываем результат
            with self._lock:
                if task_id in self.running_tasks:
                    task_info = self.running_tasks.pop(task_id)
                    self.completed_tasks.append({
                        'task_id': task_id,
                        'function': task_info['function'],
                        'start_time': task_info['start_time'],
                        'end_time': time.time(),
                        'duration': time.time() - start_time,
                        'status': 'completed',
                        'result': str(result)[:200]  # Ограничиваем размер
                    })
            
            return result
            
        except Exception as e:
            # Записываем ошибку
            with self._lock:
                if task_id in self.running_tasks:
                    task_info = self.running_tasks.pop(task_id)
                    self.completed_tasks.append({
                        'task_id': task_id,
                        'function': task_info['function'],
                        'start_time': task_info['start_time'],
                        'end_time': time.time(),
                        'duration': time.time() - start_time,
                        'status': 'failed',
                        'error': str(e)
                    })
            
            raise
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Получение статуса задачи"""
        with self._lock:
            # Проверяем запущенные задачи
            if task_id in self.running_tasks:
                task = self.running_tasks[task_id]
                return {
                    'status': 'running',
                    'start_time': task['start_time'],
                    'duration': time.time() - task['start_time'],
                    'function': task['function']
                }
            
            # Проверяем завершенные задачи
            for task in self.completed_tasks:
                if task['task_id'] == task_id:
                    return task
            
            return None
    
    def get_running_tasks(self) -> List[Dict[str, Any]]:
        """Получение списка запущенных задач"""
        with self._lock:
            return [
                {
                    'task_id': task_id,
                    'function': info['function'],
                    'start_time': info['start_time'],
                    'duration': time.time() - info['start_time']
                }
                for task_id, info in self.running_tasks.items()
            ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Получение статистики задач"""
        with self._lock:
            completed_count = len(self.completed_tasks)
            running_count = len(self.running_tasks)
            
            if completed_count > 0:
                avg_duration = sum(task.get('duration', 0) for task in self.completed_tasks) / completed_count
                success_rate = sum(1 for task in self.completed_tasks if task['status'] == 'completed') / completed_count
            else:
                avg_duration = 0
                success_rate = 0
            
            return {
                'running_tasks': running_count,
                'completed_tasks': completed_count,
                'avg_duration': avg_duration,
                'success_rate': success_rate,
                'max_workers': self.max_workers
            }

class PerformanceMonitor:
    """Главный монитор производительности"""
    
    def __init__(self, db_path: str, config: Dict[str, Any] = None):
        self.db_path = db_path
        self.config = config or {}
        
        # Компоненты
        self.cache = MemoryCache(
            max_size=self.config.get('cache_size', 10000),
            default_ttl=self.config.get('cache_ttl', 3600)
        )
        self.db_optimizer = DatabaseOptimizer(db_path)
        self.task_manager = AsyncTaskManager(
            max_workers=self.config.get('max_workers', multiprocessing.cpu_count())
        )
        
        # Redis кеш (если доступен)
        self.redis_client = None
        if self.config.get('redis_enabled', False):
            try:
                import redis
                self.redis_client = redis.Redis(
                    host=self.config.get('redis_host', 'localhost'),
                    port=self.config.get('redis_port', 6379),
                    db=self.config.get('redis_db', 0)
                )
                self.redis_client.ping()  # Проверяем соединение
            except Exception as e:
                logger.warning(f"Redis недоступен: {e}")
                self.redis_client = None
        
        # Метрики
        self.metrics_history = deque(maxlen=10000)
        self.system_metrics_history = deque(maxlen=1000)
        
        # Мониторинг
        self.monitoring_active = True
        self.monitor_thread = threading.Thread(target=self._monitor_system, daemon=True)
        self.monitor_thread.start()
        
        self._init_performance_tables()
        
        logger.info("Performance Monitor инициализирован")
    
    def _init_performance_tables(self):
        """Инициализация таблиц производительности"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS performance_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                value REAL NOT NULL,
                unit TEXT,
                tags TEXT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cpu_percent REAL,
                memory_percent REAL,
                memory_available INTEGER,
                disk_usage_percent REAL,
                network_sent INTEGER,
                network_recv INTEGER,
                active_connections INTEGER,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Создаем индексы для оптимизации
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_perf_metrics_name_time ON performance_metrics(name, timestamp)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_system_metrics_time ON system_metrics(timestamp)')
        
        conn.commit()
        conn.close()
    
    def record_metric(self, name: str, value: float, unit: str = None, tags: Dict[str, str] = None):
        """Запись метрики производительности"""
        metric = PerformanceMetric(
            name=name,
            value=value,
            unit=unit or '',
            timestamp=datetime.now(),
            tags=tags or {}
        )
        
        # Добавляем в историю
        self.metrics_history.append(metric)
        
        # Сохраняем в базу асинхронно
        self.task_manager.submit_task(self._save_metric_to_db, metric)
    
    def _save_metric_to_db(self, metric: PerformanceMetric):
        """Сохранение метрики в базу данных"""
        try:
            self.db_optimizer.execute_query('''
                INSERT INTO performance_metrics (name, value, unit, tags, timestamp)
                VALUES (?, ?, ?, ?, ?)
            ''', (
                metric.name,
                metric.value,
                metric.unit,
                json.dumps(metric.tags),
                metric.timestamp
            ))
        except Exception as e:
            logger.error(f"Ошибка сохранения метрики: {e}")
    
    def get_metric_history(self, name: str, hours: int = 24) -> List[PerformanceMetric]:
        """Получение истории метрики"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        
        try:
            results = self.db_optimizer.execute_query('''
                SELECT name, value, unit, tags, timestamp
                FROM performance_metrics
                WHERE name = ? AND timestamp > ?
                ORDER BY timestamp DESC
            ''', (name, cutoff_time))
            
            metrics = []
            for row in results:
                metric = PerformanceMetric(
                    name=row[0],
                    value=row[1],
                    unit=row[2],
                    timestamp=datetime.fromisoformat(row[4]),
                    tags=json.loads(row[3]) if row[3] else {}
                )
                metrics.append(metric)
            
            return metrics
        except Exception as e:
            logger.error(f"Ошибка получения истории метрик: {e}")
            return []
    
    def get_system_metrics(self) -> SystemMetrics:
        """Получение текущих системных метрик"""
        try:
            # CPU
            cpu_percent = psutil.cpu_percent(interval=1)
            
            # Memory
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            memory_available = memory.available
            
            # Disk
            disk = psutil.disk_usage('/')
            disk_usage_percent = disk.percent
            
            # Network
            network = psutil.net_io_counters()
            network_sent = network.bytes_sent
            network_recv = network.bytes_recv
            
            # Connections
            active_connections = len(psutil.net_connections())
            
            metrics = SystemMetrics(
                cpu_percent=cpu_percent,
                memory_percent=memory_percent,
                memory_available=memory_available,
                disk_usage_percent=disk_usage_percent,
                network_sent=network_sent,
                network_recv=network_recv,
                active_connections=active_connections,
                timestamp=datetime.now()
            )
            
            return metrics
        except Exception as e:
            logger.error(f"Ошибка получения системных метрик: {e}")
            return None
    
    def _monitor_system(self):
        """Фоновый мониторинг системы"""
        while self.monitoring_active:
            try:
                # Получаем системные метрики
                metrics = self.get_system_metrics()
                if metrics:
                    self.system_metrics_history.append(metrics)
                    
                    # Сохраняем в базу
                    self.task_manager.submit_task(self._save_system_metrics, metrics)
                    
                    # Записываем отдельные метрики
                    self.record_metric('cpu_percent', metrics.cpu_percent, '%')
                    self.record_metric('memory_percent', metrics.memory_percent, '%')
                    self.record_metric('disk_usage_percent', metrics.disk_usage_percent, '%')
                    self.record_metric('active_connections', metrics.active_connections)
                
                # Очищаем истекшие элементы кеша
                self._cleanup_cache()
                
                # Оптимизация памяти
                if len(self.metrics_history) > 8000:
                    # Принудительная сборка мусора
                    gc.collect()
                
                time.sleep(60)  # Раз в минуту
                
            except Exception as e:
                logger.error(f"Ошибка мониторинга системы: {e}")
                time.sleep(10)
    
    def _save_system_metrics(self, metrics: SystemMetrics):
        """Сохранение системных метрик в базу"""
        try:
            self.db_optimizer.execute_query('''
                INSERT INTO system_metrics 
                (cpu_percent, memory_percent, memory_available, disk_usage_percent,
                 network_sent, network_recv, active_connections, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                metrics.cpu_percent,
                metrics.memory_percent,
                metrics.memory_available,
                metrics.disk_usage_percent,
                metrics.network_sent,
                metrics.network_recv,
                metrics.active_connections,
                metrics.timestamp
            ))
        except Exception as e:
            logger.error(f"Ошибка сохранения системных метрик: {e}")
    
    def _cleanup_cache(self):
        """Очистка устаревших элементов кеша"""
        # Память кеш самоочищается
        
        # Redis кеш
        if self.redis_client:
            try:
                # Удаляем ключи с истекшим TTL (Redis делает это автоматически)
                pass
            except Exception as e:
                logger.error(f"Ошибка очистки Redis кеша: {e}")
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Получение отчета о производительности"""
        try:
            # Системные метрики
            current_system = self.get_system_metrics()
            
            # Статистика кеша
            cache_stats = self.cache.get_stats()
            
            # Статистика базы данных
            db_stats = self.db_optimizer.get_query_stats()
            
            # Статистика задач
            task_stats = self.task_manager.get_stats()
            
            # Redis статистика
            redis_stats = {}
            if self.redis_client:
                try:
                    redis_info = self.redis_client.info()
                    redis_stats = {
                        'used_memory': redis_info.get('used_memory', 0),
                        'connected_clients': redis_info.get('connected_clients', 0),
                        'total_commands_processed': redis_info.get('total_commands_processed', 0)
                    }
                except Exception as e:
                    logger.error(f"Ошибка получения Redis статистики: {e}")
            
            # Последние метрики
            recent_metrics = {}
            for metric in list(self.metrics_history)[-100:]:  # Последние 100
                if metric.name not in recent_metrics:
                    recent_metrics[metric.name] = []
                recent_metrics[metric.name].append({
                    'value': metric.value,
                    'timestamp': metric.timestamp.isoformat()
                })
            
            return {
                'system_metrics': asdict(current_system) if current_system else {},
                'cache_stats': cache_stats,
                'database_stats': db_stats,
                'task_stats': task_stats,
                'redis_stats': redis_stats,
                'recent_metrics': recent_metrics,
                'total_metrics_recorded': len(self.metrics_history),
                'system_metrics_recorded': len(self.system_metrics_history)
            }
        except Exception as e:
            logger.error(f"Ошибка генерации отчета о производительности: {e}")
            return {}
    
    def optimize_performance(self):
        """Оптимизация производительности"""
        try:
            logger.info("Начинаем оптимизацию производительности...")
            
            # Оптимизация базы данных
            self.db_optimizer.optimize_database()
            
            # Очистка кеша если он переполнен
            cache_stats = self.cache.get_stats()
            if cache_stats['hit_rate'] < 0.5:  # Низкий hit rate
                logger.info("Очищаем кеш из-за низкого hit rate")
                self.cache.clear()
            
            # Принудительная сборка мусора
            gc.collect()
            
            # Очистка старых метрик из памяти (оставляем только последние 5000)
            if len(self.metrics_history) > 5000:
                # Конвертируем в список, обрезаем, конвертируем обратно
                recent_metrics = list(self.metrics_history)[-5000:]
                self.metrics_history.clear()
                self.metrics_history.extend(recent_metrics)
            
            logger.info("Оптимизация производительности завершена")
            
        except Exception as e:
            logger.error(f"Ошибка оптимизации производительности: {e}")

def performance_monitor(monitor_instance: PerformanceMonitor):
    """Декоратор для мониторинга производительности функций"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            func_name = f"{func.__module__}.{func.__name__}"
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                
                # Записываем успешное выполнение
                monitor_instance.record_metric(
                    f"function.{func_name}.execution_time",
                    execution_time * 1000,  # в миллисекундах
                    'ms',
                    {'status': 'success'}
                )
                
                monitor_instance.record_metric(
                    f"function.{func_name}.calls",
                    1,
                    'count',
                    {'status': 'success'}
                )
                
                return result
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                # Записываем неудачное выполнение
                monitor_instance.record_metric(
                    f"function.{func_name}.execution_time",
                    execution_time * 1000,
                    'ms',
                    {'status': 'error'}
                )
                
                monitor_instance.record_metric(
                    f"function.{func_name}.calls",
                    1,
                    'count',
                    {'status': 'error'}
                )
                
                raise
        
        return wrapper
    return decorator

@lru_cache(maxsize=1000)
def cached_expensive_operation(param: str) -> str:
    """Пример кешированной дорогой операции"""
    # Имитируем дорогую операцию
    time.sleep(0.1)
    return f"processed_{param}"