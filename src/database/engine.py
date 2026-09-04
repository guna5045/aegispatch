"""SQLAlchemy database engine factory and connection management for Aegis Patch."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from sqlalchemy import Engine, create_engine
from sqlalchemy.pool import StaticPool

from config.settings import settings
from src.database.config import ensure_sqlite_dir_exists, resolve_database_url

logger = logging.getLogger("aegis_patch.database.engine")

# Singleton default engine cache
_default_engine: Optional[Engine] = None


def create_db_engine(
    database_url: Optional[str] = None,
    echo: Optional[bool] = None,
    **kwargs: Any,
) -> Engine:
    """Create a new SQLAlchemy Engine configured for Aegis Patch.

    Args:
        database_url: Optional database connection URL. If None, uses settings.database_url.
        echo: Whether SQLAlchemy should log SQL statements. If None, uses settings.database_echo.
        **kwargs: Additional keyword arguments passed directly to SQLAlchemy create_engine.

    Returns:
        SQLAlchemy Engine instance.
    """
    raw_url = database_url if database_url is not None else settings.database_url
    resolved_url = resolve_database_url(raw_url)
    should_echo = echo if echo is not None else settings.database_echo

    engine_kwargs: Dict[str, Any] = {"echo": should_echo}

    # SQLite-specific connection arguments
    if resolved_url.startswith("sqlite"):
        # Ensure parent directory exists for file-backed databases
        ensure_sqlite_dir_exists(resolved_url)

        # check_same_thread=False:
        # SQLite's default driver check restricts connection usage to the thread that created it.
        # Streamlit and concurrent backend services operate across multi-threaded worker pools;
        # setting check_same_thread=False is essential to permit safe concurrent access across threads.
        connect_args = kwargs.pop("connect_args", {})
        connect_args.setdefault("check_same_thread", False)
        engine_kwargs["connect_args"] = connect_args

        # In-memory SQLite: use StaticPool to preserve tables across connections within tests
        if ":memory:" in resolved_url or resolved_url == "sqlite://":
            engine_kwargs.setdefault("poolclass", StaticPool)
        else:
            engine_kwargs.setdefault("pool_pre_ping", True)

    engine_kwargs.update(kwargs)

    logger.debug(f"Creating database engine for URL: {resolved_url} (echo={should_echo})")
    return create_engine(resolved_url, **engine_kwargs)


def get_engine(
    database_url: Optional[str] = None,
    echo: Optional[bool] = None,
    **kwargs: Any,
) -> Engine:
    """Get the cached default Engine, or create a new dedicated Engine if custom parameters are provided.

    When called with default parameters (None), returns a shared singleton engine instance.
    When called with a specific database_url or kwargs, creates and returns a dedicated engine.
    """
    global _default_engine

    # If custom parameters are specified, return an isolated engine
    if database_url is not None or echo is not None or kwargs:
        return create_db_engine(database_url=database_url, echo=echo, **kwargs)

    # Return or instantiate singleton default engine
    if _default_engine is None:
        _default_engine = create_db_engine()

    return _default_engine


def reset_engine() -> None:
    """Dispose and clear the cached default engine (primarily used in test fixtures)."""
    global _default_engine
    if _default_engine is not None:
        _default_engine.dispose()
        _default_engine = None
        logger.debug("Default database engine disposed and reset.")
