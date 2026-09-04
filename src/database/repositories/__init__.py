"""Aegis Patch Data Access Repositories.

Provides explicit, typed repository classes over SQLAlchemy ORM models.
All repositories receive an active SQLAlchemy Session and manage persistence operations.
"""

from src.database.repositories.asset_repository import AssetRepository
from src.database.repositories.control_repository import ControlRepository
from src.database.repositories.patch_plan_repository import PatchPlanRepository
from src.database.repositories.policy_repository import PolicyRepository
from src.database.repositories.risk_repository import RiskAssessmentRepository
from src.database.repositories.threat_repository import ThreatIntelligenceRepository
from src.database.repositories.vulnerability_repository import VulnerabilityRepository

__all__ = [
    "AssetRepository",
    "ControlRepository",
    "PatchPlanRepository",
    "PolicyRepository",
    "RiskAssessmentRepository",
    "ThreatIntelligenceRepository",
    "VulnerabilityRepository",
]
