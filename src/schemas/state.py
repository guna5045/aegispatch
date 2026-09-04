"""Shared workflow state model for multi-agent orchestration."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from src.schemas.context import AssetContext
from src.schemas.plan import PatchPlan
from src.schemas.risk import RiskAssessment
from src.schemas.threat import ThreatEvidence
from src.schemas.verification import VerificationResult
from src.schemas.vulnerability import VulnerabilityFinding


class WorkflowStatus(str, Enum):
    """Execution lifecycle status of an AegisPatch analysis run."""

    NOT_STARTED = "NOT_STARTED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"


class AuditEvent(BaseModel):
    """Structured audit trail log record of agent activity within an analysis run."""

    model_config = ConfigDict(extra="forbid")

    event_id: str = Field(..., min_length=1, description="Unique audit event identifier")
    agent_name: str = Field(..., min_length=1, description="Originating agent name")
    event_type: str = Field(..., min_length=1, description="Type or category of action performed")
    message: str = Field(..., min_length=1, description="Descriptive summary of the event")
    details: Dict[str, str] = Field(
        default_factory=dict,
        description="Structured key-value metadata regarding the event",
    )
    timestamp: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when this event occurred",
    )


class AegisPatchState(BaseModel):
    """Shared state container coordinating multi-agent analysis and artifact synthesis."""

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., min_length=1, description="Unique analysis pipeline run identifier")
    workflow_status: WorkflowStatus = Field(
        default=WorkflowStatus.NOT_STARTED,
        description="Current high-level execution state",
    )
    input_vulnerabilities: List[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Raw or ingested vulnerability findings presented as input",
    )
    normalized_vulnerabilities: List[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Vulnerabilities validated and normalized by ingestion agent",
    )
    asset_contexts: Dict[str, AssetContext] = Field(
        default_factory=dict,
        description="Asset and environmental context records mapped by finding_id or asset_id",
    )
    threat_evidence: Dict[str, ThreatEvidence] = Field(
        default_factory=dict,
        description="Threat intelligence signals mapped by CVE ID",
    )
    risk_assessments: Dict[str, RiskAssessment] = Field(
        default_factory=dict,
        description="Completed risk assessment records mapped by finding_id",
    )
    patch_plan: Optional[PatchPlan] = Field(
        None,
        description="Generated remediation plan and schedule",
    )
    verification_result: Optional[VerificationResult] = Field(
        None,
        description="Audit and critic assessment results of the proposed plan",
    )
    current_agent: Optional[str] = Field(
        None,
        description="Currently active agent or processing step",
    )
    completed_agents: List[str] = Field(
        default_factory=list,
        description="Ordered list of agents that have successfully finished execution",
    )
    errors: List[str] = Field(
        default_factory=list,
        description="Fatal or blocking error messages encountered during run",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Non-blocking warning messages recorded during execution",
    )
    audit_trail: List[AuditEvent] = Field(
        default_factory=list,
        description="Chronological log of agent transitions and state updates",
    )
    created_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when the run was initiated",
    )
    updated_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when the state was last modified",
    )
