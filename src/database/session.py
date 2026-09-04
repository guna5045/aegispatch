"""Database session management and lifecycle context managers for Aegis Patch."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Generator, Optional

from sqlalchemy import Engine
from sqlalchemy.orm import Session, sessionmaker

from src.database.engine import get_engine

logger = logging.getLogger("aegis_patch.database.session")


def get_session_maker(engine: Optional[Engine] = None) -> sessionmaker[Session]:
    """Create a configured sessionmaker bound to the provided or default Engine.

    Configured with:
      - autoflush=False: Prevents premature flushes before explicit commits.
      - autocommit=False: Enforces explicit transaction boundaries.
      - expire_on_commit=False: Keeps attributes accessible on objects after commit.
    """
    bind_engine = engine if engine is not None else get_engine()
    return sessionmaker(
        bind=bind_engine,
        autoflush=False,
        autocommit=False,
        expire_on_commit=False,
    )


# Default session factory bound to the default singleton engine
SessionLocal = get_session_maker()


@contextmanager
def get_session(engine: Optional[Engine] = None) -> Generator[Session, None, None]:
    """Provide a transactional database session scope with automatic commit, rollback, and cleanup.

    Usage:
        with get_session() as session:
            # perform database operations
            session.execute(...)
            # auto-commits on clean exit

        # If an exception occurs, transaction is rolled back automatically
        # and the exception is re-raised. Session is guaranteed closed in all cases.

    Args:
        engine: Optional Engine to bind to. If None, uses default engine.

    Yields:
        Active SQLAlchemy Session.
    """
    factory = get_session_maker(engine) if engine is not None else SessionLocal
    session: Session = factory()
    try:
        yield session
        session.commit()
    except Exception as exc:
        session.rollback()
        logger.error(f"Database session rolled back due to error: {exc}", exc_info=False)
        raise
    finally:
        session.close()
