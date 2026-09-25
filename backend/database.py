"""
Gryfffindor Sentinel — Database Engine & Session Management (Phase 3C)

Provides SQLAlchemy 2.x session factory, engine configuration, connection pooling,
transaction context managers, health checks, and SQLite fallback logic.
"""

import logging
from contextlib import contextmanager
from typing import Generator
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, Session

from backend.config import settings
from backend.db_models import Base

logger = logging.getLogger("sentinel.database")


def create_sentinel_engine():
    """
    Creates and returns an engine based on settings.DATABASE_URL.
    Falls back to SQLite if PostgreSQL connection fails and fallback is enabled.
    """
    db_url = settings.DATABASE_URL

    if "sqlite" in db_url:
        engine = create_engine(
            db_url,
            connect_args={"check_same_thread": False},
            echo=False,
        )
        logger.info("ℹ️ Using SQLite Database Engine: %s", db_url)
        return engine

    try:
        # Try connecting to PostgreSQL
        engine = create_engine(
            db_url,
            connect_args={"connect_timeout": 1},
            pool_size=10,
            max_overflow=20,
            pool_timeout=5,
            pool_recycle=1800,
            echo=False,
        )
        # Test connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        logger.info("✅ Successfully connected to PostgreSQL Database Engine.")
        return engine
    except Exception as e:
        logger.warning("⚠️ PostgreSQL connection failed (%s).", e)
        if settings.ALLOW_SQLITE_FALLBACK:
            fallback_url = "sqlite:///./gryffindor.db"
            logger.info("🔄 Falling back to local SQLite database: %s", fallback_url)
            return create_engine(
                fallback_url,
                connect_args={"check_same_thread": False},
                echo=False,
            )
        else:
            raise e


engine = create_sentinel_engine()
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db():
    """Create all database tables defined in Base.metadata."""
    try:
        Base.metadata.create_all(bind=engine)
        logger.info("✅ Database tables verified / created successfully.")
    except Exception as e:
        logger.error("❌ Failed to initialize database tables: %s", e)


def check_db_connection() -> bool:
    """Checks if the database is accessible."""
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


def get_db() -> Generator[Session, None, None]:
    """FastAPI Dependency for database sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@contextmanager
def db_session() -> Generator[Session, None, None]:
    """Context manager for standalone database operations with auto-commit/rollback."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
