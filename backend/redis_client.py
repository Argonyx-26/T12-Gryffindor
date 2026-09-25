"""
Gryfffindor Sentinel — Redis Real-Time State & Fallback Module (Phase 3C)

Provides real-time caching, active incident state tracking, and Pub/Sub alert distribution.
Gracefully degrades to in-memory fallback if Redis is unavailable.
"""

import json
import logging
from typing import Any, Dict, List, Optional
import redis

from backend.config import settings

logger = logging.getLogger("sentinel.redis")


class SentinelRedisClient:
    """Redis client for active state caching with transparent in-memory fallback."""

    def __init__(self, redis_url: str = settings.REDIS_URL):
        self.redis_url = redis_url
        self.client: Optional[redis.Redis] = None
        self.is_connected: bool = False
        self._fallback_active_incidents: Dict[str, Dict[str, Any]] = {}
        self._connect()

    def _connect(self):
        try:
            self.client = redis.Redis.from_url(self.redis_url, decode_responses=True, socket_timeout=0.5)
            self.client.ping()
            self.is_connected = True
            logger.info("✅ Successfully connected to Redis server at %s", self.redis_url)
        except Exception as e:
            self.is_connected = False
            self.client = None
            logger.warning("⚠️ Redis connection unavailable (%s). Operating in degraded in-memory fallback mode.", e)

    def check_connection(self) -> bool:
        if not self.is_connected or not self.client:
            return False
        try:
            return self.client.ping()
        except Exception:
            self.is_connected = False
            return False

    def set_active_incident(self, incident_id: str, incident_dict: Dict[str, Any]) -> bool:
        """Cache an active incident in Redis (or in-memory fallback)."""
        data_str = json.dumps(incident_dict)
        if self.is_connected and self.client:
            try:
                self.client.hset("gryffindor:active_incidents", incident_id, data_str)
                return True
            except Exception as e:
                logger.warning("⚠️ Failed to write incident to Redis: %s", e)
                self.is_connected = False

        # Fallback to in-memory dictionary
        self._fallback_active_incidents[incident_id] = incident_dict
        return True

    def get_active_incidents(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve all active incidents from Redis (or in-memory fallback)."""
        if self.is_connected and self.client:
            try:
                raw_hash = self.client.hgetall("gryffindor:active_incidents")
                res = {}
                for k, v in raw_hash.items():
                    res[k] = json.loads(v)
                return res
            except Exception as e:
                logger.warning("⚠️ Failed to read active incidents from Redis: %s", e)
                self.is_connected = False

        return dict(self._fallback_active_incidents)

    def remove_active_incident(self, incident_id: str) -> bool:
        """Remove an incident from active cache when resolved or closed."""
        if self.is_connected and self.client:
            try:
                self.client.hdel("gryffindor:active_incidents", incident_id)
            except Exception:
                self.is_connected = False

        if incident_id in self._fallback_active_incidents:
            del self._fallback_active_incidents[incident_id]
        return True

    def publish_alert(self, channel: str, message_dict: Dict[str, Any]) -> bool:
        """Publish real-time alert payload to Redis channel."""
        if self.is_connected and self.client:
            try:
                self.client.publish(channel, json.dumps(message_dict))
                return True
            except Exception as e:
                logger.warning("⚠️ Failed to publish to Redis channel: %s", e)
                self.is_connected = False
        return False

    def clear(self):
        """Clear active caches."""
        if self.is_connected and self.client:
            try:
                self.client.delete("gryffindor:active_incidents")
            except Exception:
                pass
        self._fallback_active_incidents.clear()


REDIS_CLIENT = SentinelRedisClient()
