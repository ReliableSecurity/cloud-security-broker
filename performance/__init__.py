"""
Advanced Performance Module для CASB
Система мониторинга производительности, кеширования и оптимизации
"""

try:
    from .performance_monitor import (
        PerformanceMonitor,
        MemoryCache,
        DatabaseOptimizer,
        AsyncTaskManager,
        PerformanceMetric,
        SystemMetrics,
        performance_monitor
    )
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Некоторые компоненты performance модуля недоступны: {e}")
    
    # Заглушки для отсутствующих компонентов
    class PerformanceMonitor:
        def __init__(self, *args, **kwargs):
            pass
    
    class MemoryCache:
        def __init__(self, *args, **kwargs):
            pass
    
    performance_monitor = lambda x: lambda func: func

__all__ = [
    'PerformanceMonitor',
    'MemoryCache',
    'DatabaseOptimizer',
    'AsyncTaskManager',
    'PerformanceMetric',
    'SystemMetrics',
    'performance_monitor'
]