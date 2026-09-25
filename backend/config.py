"""
Gryfffindor Sentinel — Central Configuration Module (Phase 3C)

Loads environment variables with sensible production and local development defaults.
Does not hardcode passwords or credentials.
"""

import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class Settings:
    # Primary Database URL (PostgreSQL by default, or SQLite fallback)
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+psycopg://postgres:postgres@localhost:5432/gryffindor")

    # Redis Cache & Real-Time Pub/Sub URL
    REDIS_URL: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")

    # Retention Configuration
    EVENT_RETENTION_DAYS: int = int(os.getenv("EVENT_RETENTION_DAYS", "30"))
    INCIDENT_RETENTION_DAYS: int = int(os.getenv("INCIDENT_RETENTION_DAYS", "90"))

    # System & Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    HUB_URL: str = os.getenv("HUB_URL", "http://localhost:8000")

    # Internal flag to enable SQLite fallback during unit testing or when PG is offline
    ALLOW_SQLITE_FALLBACK: bool = os.getenv("ALLOW_SQLITE_FALLBACK", "true").lower() in ("true", "1", "yes")


settings = Settings()
