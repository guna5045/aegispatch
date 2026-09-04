"""SQLAlchemy ORM models package for Aegis Patch.

Exports all core application persistence models and registers them with Base.metadata.
"""

from src.database.models.asset import Asset
from src.database.models.control import SecurityControl
from src.database.models.patch_plan import PatchPlan, PatchPlanItem
from src.database.models.policy import PolicyDocument
from src.database.models.risk import RiskAssessment
from src.database.models.threat import ThreatIntelligenceObservation
from src.database.models.vulnerability import VulnerabilityFinding

__all__ = [
    "Asset",
    "SecurityControl",
    "VulnerabilityFinding",
    "ThreatIntelligenceObservation",
    "RiskAssessment",
    "PatchPlan",
    "PatchPlanItem",
    "PolicyDocument",
]
