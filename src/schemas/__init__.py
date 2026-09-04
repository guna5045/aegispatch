"""Public export of AegisPatch foundational domain schemas and enums."""

from src.schemas.asset import (
    Asset,
    AssetCriticality,
    AssetType,
    BusinessTier,
    CompensatingControl,
    ControlStatus,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
    PatchWindow,
)
from src.schemas.context import (
    AssetContext,
    PolicyCitation,
)
from src.schemas.plan import (
    ApprovalState,
    PatchAction,
    PatchCandidate,
    PatchPlan,
    RollbackPlan,
)
from src.schemas.risk import (
    ControlAdjustment,
    RemediationDecision,
    RiskAssessment,
    RiskTier,
)
from src.schemas.state import (
    AegisPatchState,
    AuditEvent,
    WorkflowStatus,
)
from src.schemas.threat import (
    ThreatConfidence,
    ThreatEvidence,
)
from src.schemas.verification import (
    CheckType,
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
)
from src.schemas.vulnerability import (
    VulnerabilityFinding,
    VulnerabilityReference,
    VulnerabilitySeverity,
)

__all__ = [
    # Vulnerability
    "VulnerabilityFinding",
    "VulnerabilityReference",
    "VulnerabilitySeverity",
    # Asset
    "Asset",
    "AssetType",
    "BusinessTier",
    "AssetCriticality",
    "NetworkExposure",
    "DataSensitivity",
    "EnvironmentType",
    "ControlStatus",
    "PatchWindow",
    "CompensatingControl",
    # Threat
    "ThreatEvidence",
    "ThreatConfidence",
    # Context
    "AssetContext",
    "PolicyCitation",
    # Risk
    "RiskAssessment",
    "RiskTier",
    "RemediationDecision",
    "ControlAdjustment",
    # Plan
    "PatchPlan",
    "PatchAction",
    "PatchCandidate",
    "RollbackPlan",
    "ApprovalState",
    # Verification
    "VerificationResult",
    "VerificationCheck",
    "VerificationStatus",
    "CheckType",
    # State
    "AegisPatchState",
    "AuditEvent",
    "WorkflowStatus",
]
