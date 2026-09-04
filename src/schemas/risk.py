"""Risk assessment data contracts representing evaluated risk results and their inputs."""

from enum import Enum
from typing import Dict, List
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field
from src.schemas.context import AssetContext
from src.schemas.threat import ThreatEvidence


class RiskTier(str, Enum):
    """AegisPatch environmental risk severity tiers."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class RemediationDecision(str, Enum):
    """Operational triage decision recommendations."""

    IMMEDIATE_PATCH = "IMMEDIATE_PATCH"
    SCHEDULED_PATCH = "SCHEDULED_PATCH"
    MITIGATE = "MITIGATE"
    ACCEPT_RISK = "ACCEPT_RISK"
    MONITOR = "MONITOR"


class ControlAdjustment(BaseModel):
    """Structured adjustment applied to risk calculations based on compensating controls."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., min_length=1, description="Identifier of the mitigating control")
    name: str = Field(..., min_length=1, description="Control name")
    adjustment_factor: float = Field(
        ...,
        description="Quantified adjustment impact value applied during risk assessment",
    )
    description: str = Field(..., description="Justification for the score adjustment")


class RiskAssessment(BaseModel):
    """Evaluated risk assessment capturing input evidence and calculated environmental risk tier."""

    model_config = ConfigDict(extra="forbid")

    assessment_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this risk assessment record",
    )
    finding_id: str = Field(..., min_length=1, description="Evaluated vulnerability finding identifier")
    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Associated CVE ID")
    asset_id: str = Field(..., min_length=1, description="Target asset identifier")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="Base CVSS score of the finding")
    cvss_contribution: float = Field(
        ...,
        ge=0.0,
        description="Quantified CVSS contribution to the final risk score",
    )
    threat_evidence: ThreatEvidence = Field(..., description="Threat intelligence signals used in assessment")
    environmental_context: AssetContext = Field(..., description="Asset environmental context used in assessment")
    control_adjustments: List[ControlAdjustment] = Field(
        default_factory=list,
        description="Applied compensating control score adjustments",
    )
    environmental_risk_score: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Composite environmental risk score calculated between 0.0 and 100.0",
    )
    risk_tier: RiskTier = Field(..., description="Assigned risk priority tier")
    decision: RemediationDecision = Field(..., description="Recommended triage decision")
    explanation: str = Field(..., min_length=1, description="Natural language explanation of risk rating rationale")
    supporting_evidence: List[str] = Field(
        default_factory=list,
        description="List of specific factual statements and evidence citations backing this assessment",
    )
    calculation_metadata: Dict[str, str] = Field(
        default_factory=dict,
        description="Engine version, algorithm name, or parameter metadata used during calculation",
    )
    assessed_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when this assessment was computed",
    )
