"""
Enterprise Module для CASB
Корпоративные функции: отчетность, аналитика, соответствие стандартам
"""

try:
    from .reporting import (
        EnterpriseReportManager,
        ReportConfig,
        ReportData,
        ReportType,
        ExportFormat,
        SecurityReportGenerator,
        ComplianceReportGenerator,
        ChartGenerator,
        ReportExporter
    )
    REPORTING_AVAILABLE = True
except ImportError as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"Некоторые компоненты enterprise модуля недоступны: {e}")
    
    # Заглушки для отсутствующих компонентов
    class EnterpriseReportManager:
        def __init__(self, *args, **kwargs):
            pass
    
    class ReportConfig:
        def __init__(self, *args, **kwargs):
            pass
    
    REPORTING_AVAILABLE = False

__all__ = [
    'EnterpriseReportManager',
    'ReportConfig',
    'ReportData',
    'ReportType',
    'ExportFormat',
    'SecurityReportGenerator',
    'ComplianceReportGenerator',
    'ChartGenerator',
    'ReportExporter',
    'REPORTING_AVAILABLE'
]