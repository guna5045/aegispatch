"""Verification and critic assessment data models."""

from enum import Enum
from typing import List, Optional
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class VerificationStatus(str, Enum):
    """Overall outcome of the verification and critic assessment."""

    PASSED = "PASSED"
    FAILED = "FAILED"
    WARNING = "WARNING"
    REQUIRES_REPLANNING = "REQUIRES_REPLANNING"


class CheckType(str, Enum):
    """Category of validation check executed by verification tooling."""

    EVIDENCE_VALIDATION = "EVIDENCE_VALIDATION"
    CALCULATION_VALIDATION = "CALCULATION_VALIDATION"
    CONSTRAINT_VALIDATION = "CONSTRAINT_VALIDATION"
    FACTUAL_CONSISTENCY = "FACTUAL_CONSISTENCY"


class VerificationCheck(BaseModel):
    """Individual rule check performed against pipeline decisions or outputs."""

    model_config = ConfigDict(extra="forbid")

    check_id: str = Field(..., min_length=1, description="Unique check rule identifier")
    check_name: str = Field(..., min_length=1, description="Human-readable title of check")
    check_type: CheckType = Field(..., description="Category of the validation check")
    passed: bool = Field(..., description="True if verification condition was satisfied")
    message: str = Field(..., min_length=1, description="Result explanation or error message")
    details: Optional[str] = Field(None, description="Detailed diagnostic or error trace information")


class VerificationResult(BaseModel):
    """Aggregated verification report evaluating plan integrity, factual basis, and constraints."""

    model_config = ConfigDict(extra="forbid")

    verification_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this verification report",
    )
    status: VerificationStatus = Field(..., description="Overall verification outcome")
    checks_performed: List[VerificationCheck] = Field(
        default_factory=list,
        description="All individual checks executed during audit",
    )
    failed_checks: List[VerificationCheck] = Field(
        default_factory=list,
        description="Subset of checks that failed validation",
    )
    warnings: List[str] = Field(
        default_factory=list,
        description="Non-blocking warning messages identified during verification",
    )
    evidence_citations_valid: bool = Field(
        ...,
        description="True if all policy and threat citations resolve to authentic records",
    )
    calculations_valid: bool = Field(
        ...,
        description="True if arithmetic calculations match deterministic formulas",
    )
    constraints_valid: bool = Field(
        ...,
        description="True if capacity, window, and dependency constraints are strictly honored",
    )
    factual_support_valid: bool = Field(
        ...,
        description="True if claims are factually grounded without unsupported assertions",
    )
    requires_replanning: bool = Field(
        ...,
        description="True if planner agent must re-synthesize the patch plan",
    )
    summary: str = Field(..., min_length=1, description="Executive summary of verification findings")
    verified_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when verification was completed",
    )
