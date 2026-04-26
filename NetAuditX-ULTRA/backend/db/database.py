"""Database connection layer and session management."""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session, sessionmaker

from backend.config import get_settings
from backend.db.models import Base
from backend.utils.logger import get_logger

log = get_logger("netauditx.db")


def _build_engine() -> Engine:
    settings = get_settings()
    url = settings.database_url
    connect_args: dict = {}
    if url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
    engine = create_engine(
        url,
        echo=False,
        future=True,
        pool_pre_ping=True,
        connect_args=connect_args,
    )
    return engine


engine: Engine = _build_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False, future=True)


_DEVICE_COLUMN_MIGRATIONS = {
    "mac_address":      "VARCHAR(40)",
    "hostname":         "VARCHAR(255)",
    "last_latency_ms":  "DOUBLE PRECISION",
    "discovered_at":    "TIMESTAMP WITH TIME ZONE",
    "discovery_source": "VARCHAR(40)",
}


def _apply_lightweight_migrations() -> None:
    """Add missing columns to existing tables (idempotent ALTER TABLE).

    SQLAlchemy's `create_all` only creates *new* tables — it does not add
    columns to tables that already exist. We add the new device-discovery
    columns here so upgrades from v1.x don't crash.
    """
    inspector = inspect(engine)
    if "devices" not in inspector.get_table_names():
        return  # Fresh DB — create_all already covers it.

    existing = {c["name"] for c in inspector.get_columns("devices")}
    is_sqlite = engine.url.get_backend_name().startswith("sqlite")

    with engine.begin() as conn:
        for col, ddl in _DEVICE_COLUMN_MIGRATIONS.items():
            if col in existing:
                continue
            type_sql = "TIMESTAMP" if (is_sqlite and "TIMESTAMP" in ddl) else (
                "FLOAT" if (is_sqlite and "DOUBLE PRECISION" in ddl) else ddl
            )
            log.info("Adding missing column devices.%s (%s)", col, type_sql)
            conn.execute(text(f"ALTER TABLE devices ADD COLUMN {col} {type_sql}"))


def init_db() -> None:
    """Create all tables and apply lightweight migrations. Idempotent."""
    log.info("Initializing database schema at %s", engine.url)
    Base.metadata.create_all(engine)
    try:
        _apply_lightweight_migrations()
    except Exception as exc:  # noqa: BLE001
        log.warning("Lightweight migrations skipped (%s)", exc)


@contextmanager
def session_scope() -> Iterator[Session]:
    """Transactional scope around a series of operations."""
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_db() -> Iterator[Session]:
    """FastAPI dependency for request-scoped DB sessions."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
