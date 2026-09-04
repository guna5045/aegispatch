"""Database configuration and filesystem path resolution for Aegis Patch."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from config.settings import settings

logger = logging.getLogger("aegis_patch.database.config")

# Project root directory: src/database/config.py -> parent(database) -> parent(src) -> parent(project_root)
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DEFAULT_RUNTIME_DIR = PROJECT_ROOT / "data" / "runtime"


def resolve_database_url(url: Optional[str] = None) -> str:
    """Resolve a database URL against the project root if it is a relative SQLite path.

    Supports:
      - 'sqlite:///:memory:' -> returns unchanged
      - 'sqlite://' -> returns unchanged
      - 'sqlite:///data/runtime/aegispatch.db' -> resolves to absolute project path
      - Non-sqlite URLs -> returns unchanged
    """
    raw_url = url if url is not None else settings.database_url

    if not raw_url.startswith("sqlite:///"):
        return raw_url

    if raw_url in ("sqlite:///:memory:", "sqlite://"):
        return raw_url

    # Strip prefix to get path component
    path_component = raw_url[len("sqlite:///"):]
    candidate_path = Path(path_component)

    if not candidate_path.is_absolute():
        resolved_path = (PROJECT_ROOT / candidate_path).resolve()
    else:
        resolved_path = candidate_path.resolve()

    return f"sqlite:///{resolved_path.as_posix()}"


def get_sqlite_filepath(url: Optional[str] = None) -> Optional[Path]:
    """Extract the Path object for a file-backed SQLite database URL, or None for in-memory/non-sqlite."""
    resolved_url = resolve_database_url(url)
    if not resolved_url.startswith("sqlite:///"):
        return None

    if resolved_url in ("sqlite:///:memory:", "sqlite://"):
        return None

    path_str = resolved_url[len("sqlite:///"):]
    return Path(path_str)


def ensure_sqlite_dir_exists(url: Optional[str] = None) -> None:
    """Ensure the target parent directory exists for file-backed SQLite databases."""
    filepath = get_sqlite_filepath(url)
    if filepath is not None and filepath.parent:
        filepath.parent.mkdir(parents=True, exist_ok=True)
        logger.debug(f"Ensured database directory exists: {filepath.parent}")
