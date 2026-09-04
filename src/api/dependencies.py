"""FastAPI dependency injection providers for Aegis Patch backend."""

from __future__ import annotations

from typing import Generator
from sqlalchemy.orm import Session

from src.database.session import SessionLocal


def get_db() -> Generator[Session, None, None]:
    """Provide a scoped database session for FastAPI request lifecycles.

    Yields:
        Active SQLAlchemy Session.
    """
    session: Session = SessionLocal()
    try:
        yield session
    finally:
        session.close()
