"""AegisPatch deterministic decision mapping from Environmental Risk Score (ERS) to project decision bands.

NOTICE:
These decision bands (ACT, ATTEND, PLAN, TRACK) and thresholds are transparent
decision bands defined specifically for the AegisPatch benchmark demonstration.
They are NOT official CISA, NIST, ISO, or SSVC thresholds.
All thresholds are centralized here for maintainability and calibration.
"""

from enum import Enum
from typing import Dict, Union
from pydantic import BaseModel, ConfigDict, Field
from src.schemas.risk import RemediationDecision, RiskTier

# ==============================================================================
# 1. AegisPatch Benchmark Decision Bands
# ==============================================================================


class AegisDecision(str, Enum):
    """AegisPatch project decision bands for Environmental Risk Scores.

    Transparent decision bands defined specifically for the AegisPatch benchmark:
    - ACT: Immediate remediation should be prioritized.
    - ATTEND: High-priority remediation requiring active security-team attention.
    - PLAN: Remediation should be planned and scheduled according to available capacity
            and organizational policy.
    - TRACK: Lower current environmental risk; continue monitoring and address through
             normal maintenance where appropriate.
    """

    ACT = "ACT"
    ATTEND = "ATTEND"
    PLAN = "PLAN"
    TRACK = "TRACK"


# ==============================================================================
# 2. Centralized Decision Thresholds and Bounds
# ==============================================================================

DECISION_THRESHOLD_ACT: float = 85.0
DECISION_THRESHOLD_ATTEND: float = 65.0
DECISION_THRESHOLD_PLAN: float = 40.0
DECISION_THRESHOLD_TRACK: float = 0.0

ERS_MIN_SCORE: float = 0.0
ERS_MAX_SCORE: float = 100.0

# Natural language operational definitions per benchmark specification
DECISION_MEANINGS: Dict[AegisDecision, str] = {
    AegisDecision.ACT: "Immediate remediation should be prioritized.",
    AegisDecision.ATTEND: "High-priority remediation requiring active security-team attention.",
    AegisDecision.PLAN: "Remediation should be planned and scheduled according to available capacity and organizational policy.",
    AegisDecision.TRACK: "Lower current environmental risk; continue monitoring and address through normal maintenance where appropriate.",
}

# Mapping AegisPatch decision bands to Phase 1 RiskTier
DECISION_TO_RISK_TIER: Dict[AegisDecision, RiskTier] = {
    AegisDecision.ACT: RiskTier.CRITICAL,
    AegisDecision.ATTEND: RiskTier.HIGH,
    AegisDecision.PLAN: RiskTier.MEDIUM,
    AegisDecision.TRACK: RiskTier.LOW,
}

# Mapping AegisPatch decision bands to Phase 1 RemediationDecision defaults
DECISION_TO_REMEDIATION: Dict[AegisDecision, RemediationDecision] = {
    AegisDecision.ACT: RemediationDecision.IMMEDIATE_PATCH,
    AegisDecision.ATTEND: RemediationDecision.SCHEDULED_PATCH,
    AegisDecision.PLAN: RemediationDecision.SCHEDULED_PATCH,
    AegisDecision.TRACK: RemediationDecision.MONITOR,
}


# ==============================================================================
# 3. Decision Mapping Details Model
# ==============================================================================


class DecisionResult(BaseModel):
    """Structured container detailing the deterministic decision and its Phase 1 alignment."""

    model_config = ConfigDict(extra="forbid")

    ers: float = Field(..., ge=0.0, le=100.0, description="Evaluated Environmental Risk Score")
    decision: AegisDecision = Field(..., description="AegisPatch project decision band")
    risk_tier: RiskTier = Field(..., description="Corresponding Phase 1 RiskTier severity equivalent")
    remediation_decision: RemediationDecision = Field(
        ..., description="Corresponding Phase 1 RemediationDecision recommendation"
    )
    meaning: str = Field(..., description="Operational definition of the decision")
    rationale: str = Field(..., description="Natural language explanation of risk rating rationale")


# ==============================================================================
# 4. Deterministic Mapping Functions
# ==============================================================================


def map_ers_to_decision(ers: Union[float, int]) -> AegisDecision:
    """Convert a validated Environmental Risk Score (ERS) into an AegisPatch project decision.

    Decision Bands:
        - 85.0 <= ERS <= 100.0 -> ACT
        - 65.0 <= ERS < 85.0   -> ATTEND
        - 40.0 <= ERS < 65.0   -> PLAN
        - 0.0  <= ERS < 40.0   -> TRACK

    Args:
        ers: Environmental Risk Score between 0.0 and 100.0 inclusive.

    Returns:
        AegisDecision enum value (ACT, ATTEND, PLAN, or TRACK).

    Raises:
        TypeError: If ers is not a numeric type.
        ValueError: If ers is less than 0.0 or greater than 100.0.
    """
    if ers is None or not isinstance(ers, (int, float)):
        raise TypeError(f"ERS must be a numeric float or int, got: {type(ers).__name__}")

    # Handle float representation precision edge cases (e.g., NaN or inf)
    if not (ers == ers):  # NaN check
        raise ValueError("ERS cannot be NaN.")

    if ers < ERS_MIN_SCORE or ers > ERS_MAX_SCORE:
        raise ValueError(
            f"Invalid Environmental Risk Score: {ers}. "
            f"ERS must be between {ERS_MIN_SCORE} and {ERS_MAX_SCORE}."
        )

    if ers >= DECISION_THRESHOLD_ACT:
        return AegisDecision.ACT
    if ers >= DECISION_THRESHOLD_ATTEND:
        return AegisDecision.ATTEND
    if ers >= DECISION_THRESHOLD_PLAN:
        return AegisDecision.PLAN
    return AegisDecision.TRACK


def map_ers_to_risk_tier(ers: Union[float, int]) -> RiskTier:
    """Map a validated Environmental Risk Score (ERS) to the Phase 1 RiskTier enum."""
    decision = map_ers_to_decision(ers)
    return DECISION_TO_RISK_TIER[decision]


def map_ers_to_remediation_decision(
    ers: Union[float, int],
    has_compensating_controls: bool = False,
) -> RemediationDecision:
    """Map a validated Environmental Risk Score (ERS) to the Phase 1 RemediationDecision enum.

    When an asset in the PLAN band possesses active compensating controls,
    the operational decision may recommend MITIGATE rather than SCHEDULED_PATCH.
    """
    decision = map_ers_to_decision(ers)
    if decision == AegisDecision.PLAN and has_compensating_controls:
        return RemediationDecision.MITIGATE
    return DECISION_TO_REMEDIATION[decision]


def get_decision_details(
    ers: Union[float, int],
    has_compensating_controls: bool = False,
) -> DecisionResult:
    """Produce a full decision mapping result connecting ERS to Phase 1 domain contracts.

    Args:
        ers: Evaluated Environmental Risk Score (0.0 to 100.0).
        has_compensating_controls: Whether active compensating controls are in place.

    Returns:
        DecisionResult containing decision, risk tier, remediation decision, meaning, and rationale.
    """
    decision = map_ers_to_decision(ers)
    risk_tier = DECISION_TO_RISK_TIER[decision]
    remediation_decision = map_ers_to_remediation_decision(
        ers, has_compensating_controls=has_compensating_controls
    )
    meaning = DECISION_MEANINGS[decision]
    rationale = (
        f"Environmental Risk Score {ers:.1f} evaluated to decision {decision.value} "
        f"({risk_tier.value} tier). {meaning}"
    )

    return DecisionResult(
        ers=round(float(ers), 2),
        decision=decision,
        risk_tier=risk_tier,
        remediation_decision=remediation_decision,
        meaning=meaning,
        rationale=rationale,
    )
