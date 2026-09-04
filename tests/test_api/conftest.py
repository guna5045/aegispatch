"""Pytest fixtures for isolated API integration tests."""

from __future__ import annotations

from typing import Generator
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.main import create_app
from src.database.base import Base
from src.database.engine import create_db_engine, reset_engine
from src.database.init_db import init_db
from src.database.ingestion.benchmark_ingestion import ingest_benchmark
from src.database.session import get_session_maker


@pytest.fixture(scope="session")
def engine():
    """Create a persistent in-memory SQLite database for the API test session."""
    db_engine = create_db_engine("sqlite:///:memory:", echo=False)
    with db_engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON;"))
        conn.commit()

    init_db(engine=db_engine)

    maker = get_session_maker(db_engine)
    with maker() as session:
        ingest_benchmark(session=session)
        session.commit()

    yield db_engine
    db_engine.dispose()
    reset_engine()


@pytest.fixture
def db_session(engine) -> Generator[Session, None, None]:
    """Provide a transactional session for test inspections."""
    maker = get_session_maker(engine)
    session = maker()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client(engine) -> Generator[TestClient, None, None]:
    """FastAPI TestClient with overridden get_db dependency pointing to in-memory DB."""
    app = create_app()
    maker = get_session_maker(engine)

    def override_get_db() -> Generator[Session, None, None]:
        session = maker()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as test_client:
        yield test_client

    app.dependency_overrides.clear()
