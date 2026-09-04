"""API request and response schemas for Aegis Patch."""

from src.api.schemas.assets import AssetDetail, AssetRead, ControlRead
from src.api.schemas.common import (
    ErrorDetail,
    ErrorResponse,
    HealthResponse,
    PaginatedResponse,
    PaginationMeta,
    RootInfoResponse,
)
from src.api.schemas.patch_plans import (
    PatchPlanCreate,
    PatchPlanItemCreate,
    PatchPlanItemRead,
    PatchPlanRead,
    PatchPlanUpdate,
)
from src.api.schemas.policies import PolicyDetail, PolicyRead
from src.api.schemas.risk import RiskAssessmentRead
from src.api.schemas.threat import ThreatObservationRead
from src.api.schemas.vulnerabilities import FindingDetail, FindingRead

__all__ = [
    # Common
    "ErrorDetail",
    "ErrorResponse",
    "PaginationMeta",
    "PaginatedResponse",
    "HealthResponse",
    "RootInfoResponse",
    # Assets
    "AssetRead",
    "AssetDetail",
    "ControlRead",
    # Vulnerabilities
    "FindingRead",
    "FindingDetail",
    # Risk
    "RiskAssessmentRead",
    # Patch Plans
    "PatchPlanCreate",
    "PatchPlanUpdate",
    "PatchPlanRead",
    "PatchPlanItemCreate",
    "PatchPlanItemRead",
    "PolicyRead",
    "PolicyDetail",
    "ThreatObservationRead",
]
