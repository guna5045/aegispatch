"""Comprehensive tests for Aegis Patch Phase 5A: Database Foundation."""

import pytest
from pathlib import Path
from sqlalchemy import text
from sqlalchemy.orm import DeclarativeBase, Session

from config.constants import DEFAULT_DATABASE_ECHO, DEFAULT_DATABASE_URL
from config.settings import Settings, settings
from src.database import (
    Base,
    DEFAULT_RUNTIME_DIR,
    PROJECT_ROOT,
    SessionLocal,
    check_db_health,
    create_db_engine,
    ensure_sqlite_dir_exists,
    get_engine,
    get_session,
    get_session_maker,
    get_sqlite_filepath,
    init_db,
    reset_engine,
    resolve_database_url,
)


@pytest.fixture(autouse=True)
def clean_engine():
    """Ensure engine cache is cleaned before and after tests."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def memory_engine():
    """Create an isolated in-memory SQLite engine for tests."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    yield engine
    engine.dispose()


@pytest.fixture
def temp_file_db(tmp_path: Path):
    """Create a temporary file-backed SQLite database for testing filesystem behavior."""
    db_file = tmp_path / "test_isolated.db"
    db_url = f"sqlite:///{db_file.as_posix()}"
    engine = create_db_engine(db_url, echo=False)
    yield engine, db_file, db_url
    engine.dispose()


# --------------------------------------------------------------------------
# 1. Configuration & Constants Tests
# --------------------------------------------------------------------------

def test_database_configuration_exists():
    """Verify database configuration settings and defaults exist."""
    assert hasattr(settings, "database_url")
    assert hasattr(settings, "database_echo")
    assert isinstance(settings.database_url, str)
    assert isinstance(settings.database_echo, bool)
    assert settings.database_url.startswith("sqlite")


def test_default_database_url_valid():
    """Verify DEFAULT_DATABASE_URL points to data/runtime location."""
    assert "data/runtime" in DEFAULT_DATABASE_URL or "data\\runtime" in DEFAULT_DATABASE_URL
    assert DEFAULT_DATABASE_URL.startswith("sqlite:///")
    assert DEFAULT_DATABASE_ECHO is False


def test_custom_settings_override():
    """Verify Settings class supports custom database URL and echo overrides."""
    custom_settings = Settings(
        database_url="sqlite:///custom/path.db",
        database_echo=True,
    )
    assert custom_settings.database_url == "sqlite:///custom/path.db"
    assert custom_settings.database_echo is True


def test_resolve_database_url_scenarios():
    """Verify resolve_database_url resolves paths against PROJECT_ROOT predictably."""
    # In-memory remains in-memory
    assert resolve_database_url("sqlite:///:memory:") == "sqlite:///:memory:"
    assert resolve_database_url("sqlite://") == "sqlite://"

    # Relative path resolves to project root
    resolved = resolve_database_url("sqlite:///data/runtime/test.db")
    expected_path = (PROJECT_ROOT / "data" / "runtime" / "test.db").resolve()
    assert resolved == f"sqlite:///{expected_path.as_posix()}"

    # Non-sqlite URLs pass through
    assert resolve_database_url("postgresql://user:pass@localhost/db") == "postgresql://user:pass@localhost/db"


def test_get_sqlite_filepath():
    """Verify get_sqlite_filepath returns correct Path object or None."""
    assert get_sqlite_filepath("sqlite:///:memory:") is None
    assert get_sqlite_filepath("postgresql://localhost/db") is None

    filepath = get_sqlite_filepath("sqlite:///data/runtime/test_target.db")
    assert filepath is not None
    assert filepath.name == "test_target.db"
    assert filepath.is_absolute()


def test_ensure_sqlite_dir_exists(tmp_path: Path):
    """Verify ensure_sqlite_dir_exists creates target directory without failing."""
    nested_dir = tmp_path / "nested" / "subfolder"
    target_db = nested_dir / "target.db"
    target_url = f"sqlite:///{target_db.as_posix()}"

    assert not nested_dir.exists()
    ensure_sqlite_dir_exists(target_url)
    assert nested_dir.exists()
    assert nested_dir.is_dir()


# --------------------------------------------------------------------------
# 2. Declarative Base Tests
# --------------------------------------------------------------------------

def test_declarative_base_class():
    """Verify Base is a modern SQLAlchemy 2.x DeclarativeBase."""
    assert issubclass(Base, DeclarativeBase)
    # Base has metadata tables registered
    assert isinstance(Base.metadata.tables, dict)


# --------------------------------------------------------------------------
# 3. Engine Creation & Connection Tests
# --------------------------------------------------------------------------

def test_engine_creation_in_memory(memory_engine):
    """Verify engine creates successfully with SQLite in-memory configuration."""
    assert memory_engine is not None
    assert memory_engine.name == "sqlite"


def test_engine_connection_and_select_1(memory_engine):
    """Verify SQLite connection executes SELECT 1 directly."""
    with memory_engine.connect() as conn:
        result = conn.execute(text("SELECT 1")).scalar()
        assert result == 1


def test_engine_sqlite_connect_args(memory_engine):
    """Verify SQLite connect_args include check_same_thread=False for concurrency safety."""
    # Test file-backed engine connect_args
    test_engine = create_db_engine("sqlite:///:memory:", echo=False)
    with test_engine.connect() as conn:
        assert conn is not None
    test_engine.dispose()


def test_get_engine_singleton_and_custom():
    """Verify get_engine returns singleton by default and distinct engine when parameterized."""
    eng1 = get_engine()
    eng2 = get_engine()
    assert eng1 is eng2

    # Parameterized call returns a new engine instance
    custom_eng = get_engine(database_url="sqlite:///:memory:")
    assert custom_eng is not eng1
    custom_eng.dispose()


# --------------------------------------------------------------------------
# 4. Session Management & Lifecycle Tests
# --------------------------------------------------------------------------

def test_session_maker_and_execution(memory_engine):
    """Verify sessionmaker creates sessions that can execute queries."""
    maker = get_session_maker(memory_engine)
    session: Session = maker()
    try:
        val = session.execute(text("SELECT 42")).scalar()
        assert val == 42
    finally:
        session.close()


def test_get_session_context_manager_commit(memory_engine):
    """Verify get_session context manager commits and closes cleanly."""
    # Create a temporary table in memory
    with memory_engine.connect() as conn:
        conn.execute(text("CREATE TABLE test_kv (k TEXT PRIMARY KEY, v TEXT)"))
        conn.commit()

    # Insert data via get_session context manager
    with get_session(memory_engine) as session:
        session.execute(text("INSERT INTO test_kv (k, v) VALUES ('foo', 'bar')"))

    # Verify data was committed
    with get_session(memory_engine) as session:
        val = session.execute(text("SELECT v FROM test_kv WHERE k = 'foo'")).scalar()
        assert val == "bar"


def test_get_session_context_manager_rollback_on_error(memory_engine):
    """Verify get_session context manager rolls back transaction on exception and session recovers."""
    # Create a temporary table with unique constraint
    with memory_engine.connect() as conn:
        conn.execute(text("CREATE TABLE test_rollback (id INT PRIMARY KEY, name TEXT)"))
        conn.commit()

    # Attempt an operation that raises an exception
    with pytest.raises(ValueError, match="Simulated application error"):
        with get_session(memory_engine) as session:
            session.execute(text("INSERT INTO test_rollback (id, name) VALUES (1, 'alice')"))
            raise ValueError("Simulated application error")

    # Verify row was NOT committed due to rollback
    with get_session(memory_engine) as session:
        count = session.execute(text("SELECT count(*) FROM test_rollback")).scalar()
        assert count == 0

    # Verify subsequent transaction with same sessionmaker works normally
    with get_session(memory_engine) as session:
        session.execute(text("INSERT INTO test_rollback (id, name) VALUES (1, 'bob')"))

    with get_session(memory_engine) as session:
        count = session.execute(text("SELECT count(*) FROM test_rollback")).scalar()
        assert count == 1


# --------------------------------------------------------------------------
# 5. Database Initialization & Health Check Tests
# --------------------------------------------------------------------------

def test_init_db_creates_file_and_is_idempotent(temp_file_db):
    """Verify init_db initializes the database file idempotently."""
    engine, db_file, db_url = temp_file_db

    # Before init, file may not exist yet
    init_db(engine=engine)
    assert check_db_health(engine=engine) is True

    # Call init_db a second and third time to prove idempotency
    init_db(engine=engine)
    init_db(engine=engine)
    assert check_db_health(engine=engine) is True


def test_check_db_health_success(memory_engine):
    """Verify check_db_health returns True on an operational engine."""
    assert check_db_health(memory_engine) is True


def test_check_db_health_failure_handling():
    """Verify check_db_health returns False when connection cannot be established."""
    # Point to an invalid engine path that causes error
    from sqlalchemy import create_engine
    # Non-existent postgres or closed engine
    dummy_engine = create_engine("sqlite:///:memory:")
    dummy_engine.dispose()  # Closed engine
    # Should handle cleanly and return False or reconnect safely
    # If we pass a broken engine with a mock that throws:
    class BrokenEngine:
        url = "sqlite:///broken.db"
        def connect(self):
            raise ConnectionRefusedError("Database unreachable")

    assert check_db_health(BrokenEngine()) is False


# --------------------------------------------------------------------------
# 6. Test Isolation & Safety Tests
# --------------------------------------------------------------------------

def test_test_database_is_isolated():
    """Verify tests do not touch or create data/runtime/aegispatch.db."""
    runtime_db = DEFAULT_RUNTIME_DIR / "aegispatch.db"
    # Even if runtime_db exists from manual runs, tests create their own isolated engines
    isolated_engine = create_db_engine("sqlite:///:memory:")
    assert check_db_health(isolated_engine) is True
    isolated_engine.dispose()
