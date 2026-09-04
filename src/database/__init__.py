"""Aegis Patch Database Package.

Provides modern SQLAlchemy 2.x declarative base, engine management,
session factories, idempotent schema initialization, health checks,
and core application persistence ORM models.
"""

from src.database.base import Base
from src.database.config import (
    DEFAULT_RUNTIME_DIR,
    PROJECT_ROOT,
    ensure_sqlite_dir_exists,
    get_sqlite_filepath,
    resolve_database_url,
)
from src.database.engine import (
    create_db_engine,
    get_engine,
    reset_engine,
)
from src.database.init_db import (
    check_db_health,
    init_db,
)
from src.database.models import (
    Asset,
    PatchPlan,
    PatchPlanItem,
    PolicyDocument,
    RiskAssessment,
    SecurityControl,
    ThreatIntelligenceObservation,
    VulnerabilityFinding,
)
from src.database.repositories import (
    AssetRepository,
    ControlRepository,
    PatchPlanRepository,
    PolicyRepository,
    RiskAssessmentRepository,
    ThreatIntelligenceRepository,
    VulnerabilityRepository,
)
from src.database.ingestion import (
    IngestionSummary,
    ingest_benchmark,
    run_benchmark_ingestion,
)
from src.database.session import (
    SessionLocal,
    get_session,
    get_session_maker,
)

__all__ = [
    # Infrastructure & Utilities
    "Base",
    "PROJECT_ROOT",
    "DEFAULT_RUNTIME_DIR",
    "resolve_database_url",
    "get_sqlite_filepath",
    "ensure_sqlite_dir_exists",
    "create_db_engine",
    "get_engine",
    "reset_engine",
    "SessionLocal",
    "get_session",
    "get_session_maker",
    "init_db",
    "check_db_health",
    # ORM Models (Phase 5B)
    "Asset",
    "SecurityControl",
    "VulnerabilityFinding",
    "ThreatIntelligenceObservation",
    "RiskAssessment",
    "PatchPlan",
    "PatchPlanItem",
    "PolicyDocument",
    # Repositories (Phase 5C)
    "AssetRepository",
    "ControlRepository",
    "PatchPlanRepository",
    "PolicyRepository",
    "RiskAssessmentRepository",
    "ThreatIntelligenceRepository",
    "VulnerabilityRepository",
    # Ingestion Pipeline (Phase 5D)
    "IngestionSummary",
    "ingest_benchmark",
    "run_benchmark_ingestion",
]
