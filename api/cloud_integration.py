"""
REST API для интеграции с облачными провайдерами
Поддержка AWS, Azure, Google Cloud, Yandex Cloud и других

Автор: AI Assistant
"""

from flask import Flask, request, jsonify, g
from flask_restful import Api, Resource
import json
import logging
import hashlib
import time
import asyncio
import aiohttp
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import sqlite3
import jwt
from functools import wraps

logger = logging.getLogger(__name__)

# Модели данных для API
@dataclass
class APIResponse:
    """Стандартный ответ API"""
    success: bool
    data: Any = None
    error: str = None
    timestamp: datetime = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now()
    
    def to_dict(self):
        return {
            'success': self.success,
            'data': self.data,
            'error': self.error,
            'timestamp': self.timestamp.isoformat()
        }

@dataclass
class CloudCredentials:
    """Учетные данные для облачного провайдера"""
    provider: str
    access_key: str
    secret_key: str
    region: str = None
    endpoint: str = None
    additional_params: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.additional_params is None:
            self.additional_params = {}

@dataclass
class CloudResource:
    """Ресурс в облаке"""
    resource_id: str
    name: str
    resource_type: str
    provider: str
    region: str
    status: str
    metadata: Dict[str, Any]
    created_at: datetime
    last_modified: datetime

# Абстрактный класс для интеграции с облачными провайдерами
class CloudProviderAdapter(ABC):
    """Абстрактный адаптер для облачных провайдеров"""
    
    @abstractmethod
    async def authenticate(self, credentials: CloudCredentials) -> bool:
        """Аутентификация в облачном провайдере"""
        pass
    
    @abstractmethod
    async def list_resources(self, resource_type: str = None) -> List[CloudResource]:
        """Получение списка ресурсов"""
        pass
    
    @abstractmethod
    async def get_audit_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Получение журналов аудита"""
        pass
    
    @abstractmethod
    async def check_permissions(self, resource_id: str, user_id: str) -> Dict[str, Any]:
        """Проверка прав доступа"""
        pass

class AWSAdapter(CloudProviderAdapter):
    """Адаптер для Amazon Web Services"""
    
    def __init__(self, credentials: CloudCredentials):
        self.credentials = credentials
        self.session = None
    
    async def authenticate(self, credentials: CloudCredentials) -> bool:
        """Аутентификация в AWS"""
        try:
            # Здесь будет реальная аутентификация через boto3
            # import boto3
            # session = boto3.Session(
            #     aws_access_key_id=credentials.access_key,
            #     aws_secret_access_key=credentials.secret_key,
            #     region_name=credentials.region
            # )
            # sts = session.client('sts')
            # response = sts.get_caller_identity()
            
            # Для демонстрации
            logger.info(f"AWS аутентификация успешна для региона {credentials.region}")
            return True
            
        except Exception as e:
            logger.error(f"Ошибка AWS аутентификации: {e}")
            return False
    
    async def list_resources(self, resource_type: str = None) -> List[CloudResource]:
        """Получение списка AWS ресурсов"""
        # Заглушка для демонстрации
        demo_resources = [
            CloudResource(
                resource_id="i-1234567890abcdef0",
                name="web-server-01",
                resource_type="ec2_instance",
                provider="aws",
                region=self.credentials.region or "us-east-1",
                status="running",
                metadata={"instance_type": "t3.micro", "vpc_id": "vpc-12345"},
                created_at=datetime.now() - timedelta(days=5),
                last_modified=datetime.now() - timedelta(hours=2)
            ),
            CloudResource(
                resource_id="vol-1234567890abcdef0",
                name="web-server-storage",
                resource_type="ebs_volume",
                provider="aws",
                region=self.credentials.region or "us-east-1",
                status="in-use",
                metadata={"size_gb": 20, "volume_type": "gp3"},
                created_at=datetime.now() - timedelta(days=5),
                last_modified=datetime.now() - timedelta(days=1)
            )
        ]
        
        if resource_type:
            return [r for r in demo_resources if r.resource_type == resource_type]
        
        return demo_resources
    
    async def get_audit_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Получение AWS CloudTrail логов"""
        # Заглушка для демонстрации
        return [
            {
                "event_time": (datetime.now() - timedelta(hours=1)).isoformat(),
                "event_name": "RunInstances",
                "user_name": "admin@company.com",
                "source_ip": "203.0.113.1",
                "user_agent": "aws-cli/2.0.0",
                "resource_name": "i-1234567890abcdef0",
                "event_source": "ec2.amazonaws.com"
            }
        ]
    
    async def check_permissions(self, resource_id: str, user_id: str) -> Dict[str, Any]:
        """Проверка прав доступа в AWS"""
        return {
            "has_access": True,
            "permissions": ["read", "write"],
            "policy_source": "IAM Role: EC2-Admin"
        }

class AzureAdapter(CloudProviderAdapter):
    """Адаптер для Microsoft Azure"""
    
    def __init__(self, credentials: CloudCredentials):
        self.credentials = credentials
    
    async def authenticate(self, credentials: CloudCredentials) -> bool:
        """Аутентификация в Azure"""
        try:
            # Здесь будет реальная аутентификация через Azure SDK
            logger.info("Azure аутентификация успешна")
            return True
        except Exception as e:
            logger.error(f"Ошибка Azure аутентификации: {e}")
            return False
    
    async def list_resources(self, resource_type: str = None) -> List[CloudResource]:
        """Получение списка Azure ресурсов"""
        demo_resources = [
            CloudResource(
                resource_id="/subscriptions/12345/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm-prod-01",
                name="vm-prod-01",
                resource_type="virtual_machine",
                provider="azure",
                region="East US",
                status="running",
                metadata={"vm_size": "Standard_B2s", "os_type": "Linux"},
                created_at=datetime.now() - timedelta(days=10),
                last_modified=datetime.now() - timedelta(hours=6)
            )
        ]
        
        if resource_type:
            return [r for r in demo_resources if r.resource_type == resource_type]
        
        return demo_resources
    
    async def get_audit_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Получение Azure Activity Log"""
        return [
            {
                "event_time": (datetime.now() - timedelta(hours=2)).isoformat(),
                "operation_name": "Microsoft.Compute/virtualMachines/start/action",
                "caller": "admin@company.onmicrosoft.com",
                "source_ip": "203.0.113.2",
                "resource_id": "/subscriptions/12345/resourceGroups/prod/providers/Microsoft.Compute/virtualMachines/vm-prod-01",
                "status": "Succeeded"
            }
        ]
    
    async def check_permissions(self, resource_id: str, user_id: str) -> Dict[str, Any]:
        """Проверка прав доступа в Azure"""
        return {
            "has_access": True,
            "permissions": ["read", "write", "delete"],
            "policy_source": "Azure RBAC: Contributor"
        }

class YandexCloudAdapter(CloudProviderAdapter):
    """Адаптер для Yandex Cloud"""
    
    def __init__(self, credentials: CloudCredentials):
        self.credentials = credentials
    
    async def authenticate(self, credentials: CloudCredentials) -> bool:
        """Аутентификация в Yandex Cloud"""
        try:
            # Здесь будет реальная аутентификация через Yandex Cloud SDK
            logger.info("Yandex Cloud аутентификация успешна")
            return True
        except Exception as e:
            logger.error(f"Ошибка Yandex Cloud аутентификации: {e}")
            return False
    
    async def list_resources(self, resource_type: str = None) -> List[CloudResource]:
        """Получение списка Yandex Cloud ресурсов"""
        demo_resources = [
            CloudResource(
                resource_id="fhm4gvautg1d5h9oipnl",
                name="web-server-yc",
                resource_type="compute_instance",
                provider="yandex",
                region="ru-central1-a",
                status="RUNNING",
                metadata={"platform_id": "standard-v3", "cores": 2, "memory": 4},
                created_at=datetime.now() - timedelta(days=7),
                last_modified=datetime.now() - timedelta(hours=4)
            ),
            CloudResource(
                resource_id="bltign4vafmks37p8e87",
                name="storage-bucket",
                resource_type="storage_bucket",
                provider="yandex",
                region="ru-central1",
                status="active",
                metadata={"storage_class": "standard", "size_bytes": 1073741824},
                created_at=datetime.now() - timedelta(days=3),
                last_modified=datetime.now() - timedelta(hours=1)
            )
        ]
        
        if resource_type:
            return [r for r in demo_resources if r.resource_type == resource_type]
        
        return demo_resources
    
    async def get_audit_logs(self, start_time: datetime, end_time: datetime) -> List[Dict]:
        """Получение Yandex Cloud Audit Trails"""
        return [
            {
                "event_time": (datetime.now() - timedelta(hours=3)).isoformat(),
                "service_name": "compute",
                "resource_name": "fhm4gvautg1d5h9oipnl",
                "operation": "yandex.cloud.compute.v1.InstanceService.Start",
                "subject": {"type": "user_account", "id": "aje6o61dvog2h6g9a33s"},
                "source_ip": "203.0.113.3",
                "status": "SUCCESS"
            }
        ]
    
    async def check_permissions(self, resource_id: str, user_id: str) -> Dict[str, Any]:
        """Проверка прав доступа в Yandex Cloud"""
        return {
            "has_access": True,
            "permissions": ["compute.instances.use", "storage.buckets.get"],
            "policy_source": "IAM Role: editor"
        }

class CloudIntegrationAPI:
    """API для интеграции с облачными провайдерами"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.adapters = {}
        self.credentials_store = {}
        
        # Регистрируем адаптеры
        self.register_adapter("aws", AWSAdapter)
        self.register_adapter("azure", AzureAdapter)
        self.register_adapter("yandex", YandexCloudAdapter)
        
        self._init_api_tables()
        logger.info("Cloud Integration API инициализирован")
    
    def register_adapter(self, provider: str, adapter_class):
        """Регистрация адаптера провайдера"""
        self.adapters[provider] = adapter_class
        logger.info(f"Зарегистрирован адаптер для {provider}")
    
    def _init_api_tables(self):
        """Инициализация таблиц API"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Таблица учетных данных облачных провайдеров
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cloud_credentials (
                credential_id TEXT PRIMARY KEY,
                provider TEXT NOT NULL,
                name TEXT NOT NULL,
                access_key_encrypted TEXT,
                secret_key_encrypted TEXT,
                region TEXT,
                endpoint TEXT,
                additional_params TEXT,
                enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used TIMESTAMP
            )
        ''')
        
        # Таблица синхронизации ресурсов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resource_sync (
                sync_id TEXT PRIMARY KEY,
                provider TEXT,
                credential_id TEXT,
                resource_type TEXT,
                sync_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                resources_found INTEGER,
                sync_duration_ms REAL,
                status TEXT,
                error_message TEXT
            )
        ''')
        
        # Таблица кэша ресурсов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cached_resources (
                resource_id TEXT PRIMARY KEY,
                provider TEXT,
                credential_id TEXT,
                resource_data TEXT,
                cache_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ttl_minutes INTEGER DEFAULT 60
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def add_credentials(self, provider: str, name: str, access_key: str, 
                       secret_key: str, region: str = None, endpoint: str = None,
                       additional_params: Dict = None) -> str:
        """Добавление учетных данных провайдера"""
        credential_id = hashlib.sha256(f"{provider}_{name}_{time.time()}".encode()).hexdigest()[:16]
        
        # Шифрование учетных данных (упрощенная версия)
        access_key_encrypted = hashlib.sha256(access_key.encode()).hexdigest()
        secret_key_encrypted = hashlib.sha256(secret_key.encode()).hexdigest()
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO cloud_credentials 
            (credential_id, provider, name, access_key_encrypted, secret_key_encrypted, 
             region, endpoint, additional_params)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (credential_id, provider, name, access_key_encrypted, secret_key_encrypted,
              region, endpoint, json.dumps(additional_params or {})))
        
        conn.commit()
        conn.close()
        
        # Сохраняем в кэше для использования
        credentials = CloudCredentials(
            provider=provider,
            access_key=access_key,
            secret_key=secret_key,
            region=region,
            endpoint=endpoint,
            additional_params=additional_params or {}
        )
        self.credentials_store[credential_id] = credentials
        
        logger.info(f"Добавлены учетные данные для {provider}: {name}")
        return credential_id
    
    async def sync_resources(self, credential_id: str, resource_types: List[str] = None) -> Dict[str, Any]:
        """Синхронизация ресурсов с облачным провайдером"""
        start_time = time.time()
        sync_id = hashlib.sha256(f"{credential_id}_{start_time}".encode()).hexdigest()[:16]
        
        if credential_id not in self.credentials_store:
            logger.error(f"Учетные данные не найдены: {credential_id}")
            return APIResponse(False, error="Учетные данные не найдены").to_dict()
        
        credentials = self.credentials_store[credential_id]
        
        # Получаем адаптер
        if credentials.provider not in self.adapters:
            logger.error(f"Адаптер не найден для провайдера: {credentials.provider}")
            return APIResponse(False, error="Неподдерживаемый провайдер").to_dict()
        
        adapter = self.adapters[credentials.provider](credentials)
        
        try:
            # Аутентификация
            if not await adapter.authenticate(credentials):
                raise Exception("Ошибка аутентификации")
            
            # Получение ресурсов
            all_resources = []
            
            if resource_types:
                for resource_type in resource_types:
                    resources = await adapter.list_resources(resource_type)
                    all_resources.extend(resources)
            else:
                all_resources = await adapter.list_resources()
            
            # Сохранение в кэш
            await self._cache_resources(credential_id, all_resources)
            
            # Логирование синхронизации
            duration_ms = (time.time() - start_time) * 1000
            self._log_sync_operation(sync_id, credentials.provider, credential_id, 
                                   len(all_resources), duration_ms, "success")
            
            logger.info(f"Синхронизация завершена: {len(all_resources)} ресурсов за {duration_ms:.2f}мс")
            
            return APIResponse(True, {
                'sync_id': sync_id,
                'resources_count': len(all_resources),
                'duration_ms': duration_ms,
                'resources': [asdict(resource) for resource in all_resources]
            }).to_dict()
            
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            self._log_sync_operation(sync_id, credentials.provider, credential_id, 
                                   0, duration_ms, "error", str(e))
            
            logger.error(f"Ошибка синхронизации ресурсов: {e}")
            return APIResponse(False, error=str(e)).to_dict()
    
    async def _cache_resources(self, credential_id: str, resources: List[CloudResource]):
        """Кэширование ресурсов"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Очищаем старый кэш для этого провайдера
        cursor.execute('DELETE FROM cached_resources WHERE credential_id = ?', (credential_id,))
        
        # Добавляем новые ресурсы
        for resource in resources:
            cursor.execute('''
                INSERT INTO cached_resources (resource_id, provider, credential_id, resource_data)
                VALUES (?, ?, ?, ?)
            ''', (resource.resource_id, resource.provider, credential_id, 
                  json.dumps(asdict(resource), default=str, ensure_ascii=False)))
        
        conn.commit()
        conn.close()
    
    def _log_sync_operation(self, sync_id: str, provider: str, credential_id: str,
                           resources_count: int, duration_ms: float, status: str, 
                           error_message: str = None):
        """Логирование операции синхронизации"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO resource_sync 
            (sync_id, provider, credential_id, resources_found, sync_duration_ms, status, error_message)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (sync_id, provider, credential_id, resources_count, duration_ms, status, error_message))
        
        conn.commit()
        conn.close()
    
    async def get_cached_resources(self, credential_id: str, resource_type: str = None,
                                  max_age_minutes: int = 60) -> List[CloudResource]:
        """Получение ресурсов из кэша"""
        cutoff_time = datetime.now() - timedelta(minutes=max_age_minutes)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        query = '''
            SELECT resource_data FROM cached_resources 
            WHERE credential_id = ? AND cache_timestamp > ?
        '''
        params = [credential_id, cutoff_time]
        
        cursor.execute(query, params)
        results = cursor.fetchall()
        conn.close()
        
        resources = []
        for result in results:
            resource_data = json.loads(result[0])
            resource = CloudResource(**resource_data)
            
            if resource_type is None or resource.resource_type == resource_type:
                resources.append(resource)
        
        return resources
    
    async def get_audit_events(self, credential_id: str, start_time: datetime, 
                              end_time: datetime) -> List[Dict]:
        """Получение событий аудита"""
        if credential_id not in self.credentials_store:
            return []
        
        credentials = self.credentials_store[credential_id]
        
        if credentials.provider not in self.adapters:
            return []
        
        adapter = self.adapters[credentials.provider](credentials)
        
        try:
            if await adapter.authenticate(credentials):
                return await adapter.get_audit_logs(start_time, end_time)
        except Exception as e:
            logger.error(f"Ошибка получения событий аудита: {e}")
        
        return []
    
    def get_sync_history(self, days: int = 7) -> List[Dict]:
        """Получение истории синхронизации"""
        since = datetime.now() - timedelta(days=days)
        
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT rs.*, cc.name as credential_name
            FROM resource_sync rs
            LEFT JOIN cloud_credentials cc ON rs.credential_id = cc.credential_id
            WHERE rs.sync_timestamp > ?
            ORDER BY rs.sync_timestamp DESC
        ''', (since,))
        
        results = cursor.fetchall()
        conn.close()
        
        history = []
        for result in results:
            history.append({
                'sync_id': result[0],
                'provider': result[1],
                'credential_name': result[8] if result[8] else 'Unknown',
                'resources_found': result[4],
                'duration_ms': result[5],
                'status': result[6],
                'timestamp': result[3],
                'error_message': result[7]
            })
        
        return history
    
    def get_provider_statistics(self) -> Dict[str, Any]:
        """Получение статистики по провайдерам"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Статистика учетных данных
        cursor.execute('''
            SELECT provider, COUNT(*) as credentials_count
            FROM cloud_credentials 
            WHERE enabled = TRUE
            GROUP BY provider
        ''')
        credentials_stats = cursor.fetchall()
        
        # Статистика ресурсов
        cursor.execute('''
            SELECT provider, COUNT(*) as resources_count
            FROM cached_resources cr
            JOIN cloud_credentials cc ON cr.credential_id = cc.credential_id
            WHERE cr.cache_timestamp > datetime('now', '-1 hour')
            GROUP BY provider
        ''')
        resources_stats = cursor.fetchall()
        
        # Последние синхронизации
        cursor.execute('''
            SELECT provider, MAX(sync_timestamp) as last_sync
            FROM resource_sync
            GROUP BY provider
        ''')
        last_sync_stats = cursor.fetchall()
        
        conn.close()
        
        return {
            'credentials_by_provider': dict(credentials_stats),
            'resources_by_provider': dict(resources_stats),
            'last_sync_by_provider': dict(last_sync_stats)
        }

# Flask ресурсы для REST API
app = Flask(__name__)
api = Api(app)

# Инициализация API
cloud_api = CloudIntegrationAPI("casb.db")

def require_api_key(f):
    """Декоратор для проверки API ключа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return {'error': 'API ключ не предоставлен'}, 401
        
        # Здесь должна быть проверка API ключа
        # В демо версии принимаем любой ключ
        
        return f(*args, **kwargs)
    return decorated_function

class ProviderCredentials(Resource):
    """Управление учетными данными провайдеров"""
    
    @require_api_key
    def post(self):
        """Добавление учетных данных"""
        data = request.get_json()
        
        required_fields = ['provider', 'name', 'access_key', 'secret_key']
        if not all(field in data for field in required_fields):
            return APIResponse(False, error="Отсутствуют обязательные поля").to_dict(), 400
        
        try:
            credential_id = cloud_api.add_credentials(
                provider=data['provider'],
                name=data['name'],
                access_key=data['access_key'],
                secret_key=data['secret_key'],
                region=data.get('region'),
                endpoint=data.get('endpoint'),
                additional_params=data.get('additional_params')
            )
            
            return APIResponse(True, {'credential_id': credential_id}).to_dict()
            
        except Exception as e:
            logger.error(f"Ошибка добавления учетных данных: {e}")
            return APIResponse(False, error=str(e)).to_dict(), 500

class ResourceSync(Resource):
    """Синхронизация ресурсов"""
    
    @require_api_key
    def post(self):
        """Запуск синхронизации ресурсов"""
        data = request.get_json()
        
        credential_id = data.get('credential_id')
        if not credential_id:
            return APIResponse(False, error="Не указан credential_id").to_dict(), 400
        
        resource_types = data.get('resource_types')
        
        try:
            # Запускаем синхронизацию асинхронно
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(
                cloud_api.sync_resources(credential_id, resource_types)
            )
            loop.close()
            
            return result
            
        except Exception as e:
            logger.error(f"Ошибка синхронизации: {e}")
            return APIResponse(False, error=str(e)).to_dict(), 500
    
    def get(self):
        """Получение истории синхронизации"""
        days = request.args.get('days', 7, type=int)
        history = cloud_api.get_sync_history(days)
        
        return APIResponse(True, {'sync_history': history}).to_dict()

class CloudResources(Resource):
    """Управление облачными ресурсами"""
    
    @require_api_key
    def get(self):
        """Получение списка ресурсов"""
        credential_id = request.args.get('credential_id')
        resource_type = request.args.get('resource_type')
        use_cache = request.args.get('use_cache', 'true').lower() == 'true'
        max_age_minutes = request.args.get('max_age_minutes', 60, type=int)
        
        if not credential_id:
            return APIResponse(False, error="Не указан credential_id").to_dict(), 400
        
        try:
            if use_cache:
                # Получаем из кэша
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                resources = loop.run_until_complete(
                    cloud_api.get_cached_resources(credential_id, resource_type, max_age_minutes)
                )
                loop.close()
            else:
                # Синхронизация и получение свежих данных
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                sync_result = loop.run_until_complete(
                    cloud_api.sync_resources(credential_id, [resource_type] if resource_type else None)
                )
                loop.close()
                
                if sync_result['success']:
                    resources = [CloudResource(**r) for r in sync_result['data']['resources']]
                else:
                    return sync_result, 500
            
            return APIResponse(True, {
                'resources': [asdict(r) for r in resources],
                'count': len(resources),
                'cached': use_cache
            }).to_dict()
            
        except Exception as e:
            logger.error(f"Ошибка получения ресурсов: {e}")
            return APIResponse(False, error=str(e)).to_dict(), 500

class AuditEvents(Resource):
    """Получение событий аудита"""
    
    @require_api_key
    def get(self):
        """Получение событий аудита от облачного провайдера"""
        credential_id = request.args.get('credential_id')
        start_time_str = request.args.get('start_time')
        end_time_str = request.args.get('end_time')
        
        if not all([credential_id, start_time_str, end_time_str]):
            return APIResponse(False, error="Отсутствуют обязательные параметры").to_dict(), 400
        
        try:
            start_time = datetime.fromisoformat(start_time_str.replace('Z', '+00:00'))
            end_time = datetime.fromisoformat(end_time_str.replace('Z', '+00:00'))
            
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            events = loop.run_until_complete(
                cloud_api.get_audit_events(credential_id, start_time, end_time)
            )
            loop.close()
            
            return APIResponse(True, {
                'events': events,
                'count': len(events),
                'period': {
                    'start': start_time.isoformat(),
                    'end': end_time.isoformat()
                }
            }).to_dict()
            
        except Exception as e:
            logger.error(f"Ошибка получения событий аудита: {e}")
            return APIResponse(False, error=str(e)).to_dict(), 500

class ProviderStats(Resource):
    """Статистика по провайдерам"""
    
    @require_api_key
    def get(self):
        """Получение статистики по облачным провайдерам"""
        try:
            stats = cloud_api.get_provider_statistics()
            return APIResponse(True, stats).to_dict()
        except Exception as e:
            logger.error(f"Ошибка получения статистики: {e}")
            return APIResponse(False, error=str(e)).to_dict(), 500

class HealthCheck(Resource):
    """Проверка состояния API"""
    
    def get(self):
        """Проверка здоровья API"""
        return {
            'status': 'healthy',
            'version': '1.0.0',
            'timestamp': datetime.now().isoformat(),
            'supported_providers': list(cloud_api.adapters.keys())
        }

# Регистрация ресурсов API
api.add_resource(HealthCheck, '/api/health')
api.add_resource(ProviderCredentials, '/api/credentials')
api.add_resource(ResourceSync, '/api/sync')
api.add_resource(CloudResources, '/api/resources')
api.add_resource(AuditEvents, '/api/audit')
api.add_resource(ProviderStats, '/api/stats')

# Дополнительные endpoint'ы для специфических операций

@app.route('/api/providers', methods=['GET'])
@require_api_key
def get_supported_providers():
    """Получение списка поддерживаемых провайдеров"""
    providers = {
        'aws': {
            'name': 'Amazon Web Services',
            'regions': ['us-east-1', 'us-west-2', 'eu-west-1', 'ap-southeast-1'],
            'supported_services': ['ec2', 's3', 'iam', 'cloudtrail', 'vpc']
        },
        'azure': {
            'name': 'Microsoft Azure',
            'regions': ['East US', 'West Europe', 'Southeast Asia'],
            'supported_services': ['virtual_machines', 'storage', 'active_directory', 'monitor']
        },
        'yandex': {
            'name': 'Yandex Cloud',
            'regions': ['ru-central1-a', 'ru-central1-b', 'ru-central1-c'],
            'supported_services': ['compute', 'storage', 'iam', 'audit-trails']
        },
        'sber': {
            'name': 'SberCloud',
            'regions': ['ru-moscow-1'],
            'supported_services': ['compute', 'storage', 'security']
        },
        'mailru': {
            'name': 'Mail.ru Cloud',
            'regions': ['ru-moscow-1'],
            'supported_services': ['compute', 'storage']
        }
    }
    
    return APIResponse(True, providers).to_dict()

@app.route('/api/compliance/check', methods=['POST'])
@require_api_key
def compliance_check():
    """Проверка соответствия требованиям"""
    data = request.get_json()
    credential_id = data.get('credential_id')
    compliance_framework = data.get('framework', 'gdpr')  # GDPR, 152-ФЗ, etc.
    
    # Заглушка для демонстрации
    compliance_results = {
        'framework': compliance_framework,
        'overall_score': 85,
        'checks': [
            {
                'check_name': 'Шифрование данных в покое',
                'status': 'passed',
                'score': 100,
                'details': 'Все хранилища зашифрованы'
            },
            {
                'check_name': 'Аудит доступа',
                'status': 'warning',
                'score': 70,
                'details': 'Некоторые действия не логируются'
            },
            {
                'check_name': 'Управление доступом',
                'status': 'passed',
                'score': 90,
                'details': 'Реализована ролевая модель'
            }
        ],
        'recommendations': [
            'Включить логирование для всех API вызовов',
            'Настроить автоматическое удаление старых логов',
            'Добавить уведомления о подозрительной активности'
        ]
    }
    
    return APIResponse(True, compliance_results).to_dict()

@app.route('/api/security/assess', methods=['POST'])
@require_api_key
def security_assessment():
    """Оценка безопасности облачной инфраструктуры"""
    data = request.get_json()
    credential_id = data.get('credential_id')
    
    # Заглушка для демонстрации
    assessment_results = {
        'overall_risk_score': 0.3,  # 0.0 - 1.0
        'risk_level': 'medium',
        'vulnerabilities': [
            {
                'type': 'configuration',
                'severity': 'medium',
                'description': 'Публичный S3 bucket без шифрования',
                'resource_id': 'bucket-public-data',
                'remediation': 'Включить шифрование и ограничить доступ'
            },
            {
                'type': 'access_control',
                'severity': 'low',
                'description': 'Слишком широкие права IAM роли',
                'resource_id': 'role-developer',
                'remediation': 'Применить принцип минимальных привилегий'
            }
        ],
        'security_score_breakdown': {
            'encryption': 85,
            'access_control': 75,
            'network_security': 90,
            'logging_monitoring': 80,
            'backup_recovery': 70
        },
        'assessed_at': datetime.now().isoformat()
    }
    
    return APIResponse(True, assessment_results).to_dict()

if __name__ == '__main__':
    # Демо данные
    demo_credential_id = cloud_api.add_credentials(
        provider="yandex",
        name="Yandex Cloud Production",
        access_key="demo_access_key",
        secret_key="demo_secret_key",
        region="ru-central1-a"
    )
    
    print(f"Создан демо credential ID: {demo_credential_id}")
    print("Cloud Integration API запущен на http://localhost:5001")
    print("\nПримеры использования:")
    print("curl -H 'X-API-Key: demo_key' http://localhost:5001/api/health")
    print("curl -H 'X-API-Key: demo_key' http://localhost:5001/api/providers")
    
    app.run(debug=True, host='0.0.0.0', port=5001)
