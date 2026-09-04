"""Patch planning and remediation data models."""

from enum import Enum
from typing import List, Optional
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from src.schemas.risk import RiskTier


class ApprovalState(str, Enum):
    """Human-in-the-loop review and approval status."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


class RollbackPlan(BaseModel):
    """Safe recovery and rollback instructions in case of patch failure."""

    model_config = ConfigDict(extra="forbid")

    procedure_description: str = Field(
        ...,
        min_length=1,
        description="Step-by-step description of the safe rollback procedure",
    )
    backup_required: bool = Field(
        default=True,
        description="Indicates whether state or configuration snapshot backup is required before patching",
    )
    estimated_rollback_minutes: int = Field(
        ...,
        ge=0,
        description="Estimated time in minutes required to execute the rollback",
    )


class PatchCandidate(BaseModel):
    """Candidate vulnerability remediation item evaluated for inclusion in a patch plan."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: str = Field(..., min_length=1, description="Unique candidate identifier")
    finding_id: str = Field(..., min_length=1, description="Target finding identifier")
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Associated CVE ID")
    asset_id: str = Field(..., min_length=1, description="Target asset identifier")
    risk_tier: RiskTier = Field(..., description="Calculated environmental risk tier")
    expected_risk_reduction: float = Field(
        ...,
        ge=0.0,
        description="Expected reduction in environmental risk score upon applying patch",
    )
    estimated_cost_hours: float = Field(
        ...,
        ge=0.0,
        description="Estimated operational engineering hours required to test and deploy patch",
    )
    dependencies: List[str] = Field(
        default_factory=list,
        description="List of prerequisite candidate IDs or package dependencies",
    )


class PatchAction(BaseModel):
    """Specific ordered remediation action scheduled within a patch plan."""

    model_config = ConfigDict(extra="forbid")

    action_id: str = Field(..., min_length=1, description="Unique patch action identifier")
    candidate_id: str = Field(..., min_length=1, description="Source candidate identifier")
    finding_id: str = Field(..., min_length=1, description="Target finding identifier")
    asset_id: str = Field(..., min_length=1, description="Target asset identifier")
    target_package: str = Field(..., min_length=1, description="Software package or component to patch")
    installed_version: str = Field(..., min_length=1, description="Current version")
    target_version: str = Field(..., min_length=1, description="Target patched version")
    sequence_order: int = Field(..., ge=1, description="Execution sequence index (1-based)")
    dependencies: List[str] = Field(
        default_factory=list,
        description="IDs of prerequisite actions that must be completed first",
    )
    rollback_plan: RollbackPlan = Field(..., description="Associated rollback and recovery plan")
    approval_state: ApprovalState = Field(
        default=ApprovalState.PENDING,
        description="Approval state of this individual action",
    )


class PatchPlan(BaseModel):
    """Holistic remediation plan scheduling patch actions within operational capacity constraints."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(..., min_length=1, description="Unique patch plan identifier")
    actions: List[PatchAction] = Field(
        default_factory=list,
        description="Ordered list of recommended patch actions",
    )
    candidates: List[PatchCandidate] = Field(
        default_factory=list,
        description="All candidates evaluated during plan synthesis",
    )
    total_expected_risk_reduction: float = Field(
        ...,
        ge=0.0,
        description="Total projected cumulative risk reduction score",
    )
    total_estimated_cost_hours: float = Field(
        ...,
        ge=0.0,
        description="Total required operational engineering hours across all actions",
    )
    capacity_limit_hours: Optional[float] = Field(
        None,
        ge=0.0,
        description="Engineering maintenance window capacity constraint in hours",
    )
    approval_status: ApprovalState = Field(
        default=ApprovalState.PENDING,
        description="Overall human-in-the-loop approval state for the plan",
    )
    created_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when this plan was generated",
    )
    notes: Optional[str] = Field(
        None,
        description="Planner notes or scheduling justifications",
    )
