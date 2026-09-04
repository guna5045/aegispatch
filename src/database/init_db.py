"""Database initialization and health-check routines for Aegis Patch."""

from __future__ import annotations

import logging
from typing import Optional

from sqlalchemy import Engine, text

from src.database.base import Base
from src.database.config import ensure_sqlite_dir_exists, resolve_database_url
from src.database.engine import get_engine
import src.database.models  # noqa: F401 - Register all models with Base.metadata

logger = logging.getLogger("aegis_patch.database.init")


def init_db(engine: Optional[Engine] = None, database_url: Optional[str] = None) -> None:
    """Initialize the Aegis Patch database schema idempotently.

    Ensures the filesystem directory exists for SQLite file targets and registers
    all schema metadata via Base.metadata.create_all. Calling this function multiple
    times is completely safe and idempotent.

    Args:
        engine: Optional SQLAlchemy Engine. If None, resolves from database_url or default.
        database_url: Optional database connection URL if creating a dedicated engine.
    """
    target_engine = engine if engine is not None else get_engine(database_url=database_url)

    # Ensure parent directory exists for file-backed SQLite database
    url_str = str(target_engine.url)
    resolved_url = resolve_database_url(url_str)
    ensure_sqlite_dir_exists(resolved_url)

    logger.info(f"Initializing database schema on: {resolved_url}")
    # Create all registered tables idempotently (in Phase 5A, Base has 0 tables, which is expected)
    Base.metadata.create_all(bind=target_engine)
    logger.info("Database schema initialization complete.")


def check_db_health(engine: Optional[Engine] = None) -> bool:
    """Perform a deterministic connectivity and query health check (SELECT 1).

    Args:
        engine: Optional SQLAlchemy Engine to check. If None, uses default engine.

    Returns:
        True if the database is accessible and executes SELECT 1 successfully; False otherwise.
    """
    target_engine = engine if engine is not None else get_engine()
    try:
        with target_engine.connect() as conn:
            result = conn.execute(text("SELECT 1")).scalar()
            is_healthy = result == 1
            if is_healthy:
                logger.debug("Database health check passed (SELECT 1 -> 1).")
            else:
                logger.warning(f"Database health check returned unexpected scalar: {result}")
            return is_healthy
    except Exception as exc:
        logger.error(f"Database health check failed: {exc}", exc_info=True)
        return False
