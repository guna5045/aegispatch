"""AegisPatch risk calculation model configuration and deterministic enum mappings.

NOTICE:
These numeric values, weights, and category mappings represent the internal
AegisPatch heuristic risk model designed for the benchmark demonstration.
They are NOT official CISA, NIST, or SSVC mathematical standards.
All values are centralized here to allow calibration without modifying the calculation engine.
"""

from typing import Dict
from src.schemas.asset import (
    AssetCriticality,
    ControlStatus,
    DataSensitivity,
    NetworkExposure,
)
from src.schemas.risk import RemediationDecision, RiskTier

# ==============================================================================
# 1. Base Score Multipliers and Component Weights
# ==============================================================================

# Scale factor converting CVSS (0.0 - 10.0) to 0.0 - 100.0
CVSS_BASE_SCALE: float = 10.0

# Top-level weighted risk contribution factors (sum to 1.00)
WEIGHT_BASE_CVSS: float = 0.25
WEIGHT_THREAT: float = 0.40
WEIGHT_ENVIRONMENTAL: float = 0.35

# Environmental subcomponent weights (sum to 1.00)
WEIGHT_ENV_CRITICALITY: float = 0.50
WEIGHT_ENV_EXPOSURE: float = 0.30
WEIGHT_ENV_SENSITIVITY: float = 0.20

# Threat component parameters (when not listed on CISA KEV)
THREAT_SCORE_KEV: float = 100.0
THREAT_WEIGHT_EPSS: float = 80.0
THREAT_WEIGHT_POC: float = 20.0

# ==============================================================================
# 2. Environmental Factor Numerical Mappings (0.0 to 100.0)
# ==============================================================================

# Asset Criticality Mapping
# Rationale: Higher operational criticality linearly elevates the business consequence.
CRITICALITY_SCORES: Dict[AssetCriticality, float] = {
    AssetCriticality.CRITICAL: 100.0,
    AssetCriticality.HIGH: 75.0,
    AssetCriticality.MEDIUM: 50.0,
    AssetCriticality.LOW: 25.0,
}

# Network Exposure Mapping
# Rationale: Direct unauthenticated public ingress exponentially increases opportunity for probe/attack.
EXPOSURE_SCORES: Dict[NetworkExposure, float] = {
    NetworkExposure.INTERNET_FACING: 100.0,
    NetworkExposure.DMZ: 70.0,
    NetworkExposure.INTERNAL: 40.0,
    NetworkExposure.AIR_GAPPED: 10.0,
}

# Data Sensitivity Mapping
# Rationale: Regulated/PCI/identity data breaches incur severe regulatory and customer harm.
SENSITIVITY_SCORES: Dict[DataSensitivity, float] = {
    DataSensitivity.RESTRICTED: 100.0,
    DataSensitivity.CONFIDENTIAL: 70.0,
    DataSensitivity.INTERNAL: 40.0,
    DataSensitivity.PUBLIC: 10.0,
}

# ==============================================================================
# 3. Compensating Control Discounts and Bounds
# ==============================================================================

# Reduction factors applied by active controls
# Combined control multiplier: M_control = clamp(1.0 - sum(discounts), min=0.60, max=1.00)
CONTROL_DISCOUNTS: Dict[str, float] = {
    "WAF": 0.15,               # Layer 7 inspection / virtual patching
    "EDR": 0.10,               # Kernel behavioral detection & containment
    "MICROSEGMENTATION": 0.10, # Strict network isolation / mTLS
    "SANDBOX": 0.10,           # Ephemeral unprivileged namespaces / sandboxing
    "SANDBOXING": 0.10,        # Ephemeral unprivileged namespaces
    "AIR GAP": 0.20,           # Hardware optical diode / physical detachment
    "AIR_GAP": 0.20,           # Hardware optical diode / physical detachment
    "MFA": 0.05,               # Hardware token session requirement
    "ENCRYPTION": 0.05,        # Column/storage transparent encryption
}

# Fallback default discount for unrecognized active controls (0.0 to prevent invented discounts)
DEFAULT_ACTIVE_CONTROL_DISCOUNT: float = 0.0

# Strict boundaries for the compensating-control multiplier
CONTROL_MULTIPLIER_MIN: float = 0.60
CONTROL_MULTIPLIER_MAX: float = 1.00

# Required control status for discount eligibility
ELIGIBLE_CONTROL_STATUS = ControlStatus.ACTIVE

# ==============================================================================
# 4. Risk Tiers and Decision Thresholds
# ==============================================================================

from src.tools.decision_mapping import (
    DECISION_THRESHOLD_ACT,
    DECISION_THRESHOLD_ATTEND,
    DECISION_THRESHOLD_PLAN,
    DECISION_THRESHOLD_TRACK,
    map_ers_to_remediation_decision,
    map_ers_to_risk_tier,
)

# Threshold aliases mapping final ERS (0.0 to 100.0) into RiskTier
TIER_THRESHOLD_CRITICAL: float = DECISION_THRESHOLD_ACT
TIER_THRESHOLD_HIGH: float = DECISION_THRESHOLD_ATTEND
TIER_THRESHOLD_MEDIUM: float = DECISION_THRESHOLD_PLAN
TIER_THRESHOLD_LOW: float = DECISION_THRESHOLD_TRACK


def determine_risk_tier(ers: float) -> RiskTier:
    """Classify an Environmental Risk Score into an explicit RiskTier."""
    return map_ers_to_risk_tier(ers)


def determine_remediation_decision(
    ers: float,
    is_internet_facing: bool = False,
    is_actively_exploited: bool = False,
    has_active_controls: bool = False,
) -> RemediationDecision:
    """Recommend an initial remediation decision based on calculated risk and environmental factors.

    Delegates to the centralized Phase 3B decision mapping logic to prevent duplication.
    """
    return map_ers_to_remediation_decision(ers, has_compensating_controls=has_active_controls)
