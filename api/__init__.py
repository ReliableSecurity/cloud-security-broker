"""
API модуль CASB системы
REST API для интеграции с облачными провайдерами
"""

from .cloud_integration import create_api_app

__all__ = ['create_api_app']
