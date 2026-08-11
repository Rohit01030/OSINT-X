"""
Redis Cache Helper with In-Memory Fallback.

Provides high-performance key-value caching layer with graceful fallback when Redis is offline.
"""
import logging
import json
import time
from typing import Any, Optional
import redis

from core.config import settings

logger = logging.getLogger(__name__)


class CacheManager:
    def __init__(self, redis_url: str = None):
        self.redis_url = redis_url or settings.REDIS_URL
        self._redis_client = None
        self._memory_cache = {}

    def get_client(self):
        if self._redis_client is None:
            try:
                client = redis.Redis.from_url(self.redis_url, socket_timeout=1.5)
                client.ping()
                self._redis_client = client
            except Exception as e:
                logger.info("Redis unavailable (%s). Operating with in-memory cache fallback.", e)
                self._redis_client = False
        return self._redis_client if self._redis_client else None

    def set(self, key: str, value: Any, expire_seconds: int = 300) -> bool:
        """Sets cache key with expiration."""
        client = self.get_client()
        serialized = json.dumps(value)
        if client:
            try:
                client.setex(key, expire_seconds, serialized)
                return True
            except Exception:
                pass
        
        # Fallback to in-memory cache
        self._memory_cache[key] = {
            "val": serialized,
            "exp": time.time() + expire_seconds
        }
        return True

    def get(self, key: str) -> Optional[Any]:
        """Retrieves cached value by key."""
        client = self.get_client()
        if client:
            try:
                data = client.get(key)
                if data:
                    return json.loads(data.decode("utf-8"))
            except Exception:
                pass

        # Fallback in-memory query
        item = self._memory_cache.get(key)
        if item:
            if time.time() < item["exp"]:
                return json.loads(item["val"])
            else:
                del self._memory_cache[key]
        return None

    def delete(self, key: str) -> bool:
        """Deletes cache key."""
        client = self.get_client()
        if client:
            try:
                client.delete(key)
            except Exception:
                pass
        self._memory_cache.pop(key, None)
        return True


cache = CacheManager()
