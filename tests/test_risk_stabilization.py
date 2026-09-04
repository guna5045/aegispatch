"""Focused stabilization and regression verification tests for AegisPatch Phase 3C."""

from datetime import datetime, timezone
import pytest
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
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.threat import ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools import (
    CONTROL_MULTIPLIER_MAX,
    CONTROL_MULTIPLIER_MIN,
    DECISION_THRESHOLD_ACT,
    DECISION_THRESHOLD_ATTEND,
    DECISION_THRESHOLD_PLAN,
    DECISION_THRESHOLD_TRACK,
    TIER_THRESHOLD_CRITICAL,
    TIER_THRESHOLD_HIGH,
    TIER_THRESHOLD_LOW,
    TIER_THRESHOLD_MEDIUM,
    AegisDecision,
    calculate_control_multiplier,
    calculate_ers,
    calculate_threat_score,
    determine_remediation_decision,
    determine_risk_tier,
    evaluate_risk,
    map_ers_to_decision,
    map_ers_to_remediation_decision,
    map_ers_to_risk_tier,
)


@pytest.fixture
def sample_asset() -> Asset:
    return Asset(
        asset_id="ASSET-STAB-01",
        hostname="stab-node.aegis.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.MISSION_CRITICAL,
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        environment=EnvironmentType.PRODUCTION,
        owner_team="SecOps",
        patch_window=PatchWindow(day_of_week="Sunday", start_time_utc="02:00", duration_hours=3.0),
        compensating_controls=[],
    )


@pytest.fixture
def sample_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="FINDING-STAB-01",
        cve_id="CVE-2023-38545",
        title="curl buffer overflow",
        description="Heap buffer overflow in SOCKS5 handshake",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1",
        fixed_version="8.4.0",
        asset_id="ASSET-STAB-01",
        source="synthetic_benchmark",
    )


# ==============================================================================
# 1. Determinism (Same inputs -> Exact same result)
# ==============================================================================


def test_stabilization_identical_inputs_identical_results(sample_finding, sample_asset):
    """Verify that identical inputs produce 100% identical RiskAssessment objects."""
    eval_time = datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc)
    threat = ThreatEvidence(
        evidence_id="TH-STAB-01",
        cve_id=sample_finding.cve_id,
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
        threat_source="CISA KEV",
        retrieved_at=eval_time,
    )

    result_1 = evaluate_risk(
        sample_finding,
        sample_asset,
        threat,
        assessment_id="RSK-DET-01",
        assessed_at=eval_time,
    )
    result_2 = evaluate_risk(
        sample_finding,
        sample_asset,
        threat,
        assessment_id="RSK-DET-01",
        assessed_at=eval_time,
    )

    assert result_1 == result_2
    assert result_1.model_dump() == result_2.model_dump()


# ==============================================================================
# 2. Full Calculation Metadata Availability
# ==============================================================================


def test_stabilization_full_calculation_metadata(sample_finding, sample_asset):
    """Verify that all required diagnostic scores and factors are recorded in calculation_metadata."""
    assessment = evaluate_risk(sample_finding, sample_asset, threat=None)
    meta = assessment.calculation_metadata

    required_keys = [
        "engine",
        "base_score",
        "threat_score",
        "environmental_score",
        "unmitigated_risk",
        "weighted_risk",
        "control_multiplier",
        "final_ers",
        "aegis_decision",
        "risk_tier",
        "remediation_decision",
    ]

    for key in required_keys:
        assert key in meta, f"Missing required calculation metadata key: {key}"
        assert isinstance(meta[key], str)
        assert len(meta[key]) > 0

    assert meta["engine"] == "aegis_ers_deterministic_v1"
    assert float(meta["final_ers"]) == assessment.environmental_risk_score
    assert meta["aegis_decision"] in [d.value for d in AegisDecision]
    assert meta["risk_tier"] == assessment.risk_tier.value
    assert meta["remediation_decision"] == assessment.decision.value


# ==============================================================================
# 3. Missing Information Distinguishability
# ==============================================================================


def test_stabilization_missing_epss_distinguishable_from_zero():
    """Verify that missing EPSS is explicitly distinguished from confirmed EPSS = 0.0."""
    now = datetime.now(timezone.utc)

    # Case A: Missing EPSS intelligence
    threat_missing = ThreatEvidence(
        evidence_id="TH-MISSING",
        cve_id="CVE-2024-0001",
        is_cisa_kev=False,
        epss_score=None,
        public_poc_available=False,
        threat_source="NVD",
        retrieved_at=now,
    )
    score_missing, details_missing = calculate_threat_score(threat_missing)
    assert score_missing == 0.0
    assert details_missing["epss_available"] is False
    assert details_missing["epss_score"] is None
    assert details_missing["epss_contribution"] == 0.0

    # Case B: Confirmed EPSS intelligence with score 0.0
    threat_zero = ThreatEvidence(
        evidence_id="TH-ZERO",
        cve_id="CVE-2024-0002",
        is_cisa_kev=False,
        epss_score=0.0,
        public_poc_available=False,
        threat_source="FIRST EPSS",
        retrieved_at=now,
    )
    score_zero, details_zero = calculate_threat_score(threat_zero)
    assert score_zero == 0.0
    assert details_zero["epss_available"] is True
    assert details_zero["epss_score"] == 0.0
    assert details_zero["epss_contribution"] == 0.0

    # Distinguishability assertion: state must not be confounded
    assert details_missing["epss_available"] != details_zero["epss_available"]
    assert details_missing["epss_score"] != details_zero["epss_score"]


def test_stabilization_missing_poc_no_fabrication():
    """Verify that unconfirmed PoC does not fabricate a positive finding."""
    now = datetime.now(timezone.utc)
    threat = ThreatEvidence(
        evidence_id="TH-NO-POC",
        cve_id="CVE-2024-0003",
        is_cisa_kev=False,
        epss_score=0.5,
        public_poc_available=False,
        threat_source="FIRST EPSS",
        retrieved_at=now,
    )
    score, details = calculate_threat_score(threat)
    assert details["public_poc_available"] is False
    assert details["poc_contribution"] == 0.0
    # Only EPSS contributes: 0.5 * 80.0 = 40.0
    assert score == 40.0


# ==============================================================================
# 4. Compensating Control Handling
# ==============================================================================


def test_stabilization_no_controls_multiplier_is_one():
    """Assets with no controls must evaluate to a multiplier of exactly 1.0."""
    multiplier, adjustments = calculate_control_multiplier([])
    assert multiplier == 1.0
    assert len(adjustments) == 0


def test_stabilization_unrecognized_controls_receive_zero_discount():
    """Unrecognized / unrelated controls must receive 0.0 discount and NOT reduce risk."""
    unrelated_controls = [
        CompensatingControl(
            control_id="CTL-UNRELATED-01",
            name="Physical Security Guard",
            description="24/7 security guard at data center entrance",
            status=ControlStatus.ACTIVE,
        ),
        CompensatingControl(
            control_id="CTL-UNRELATED-02",
            name="Backup Power Generator",
            description="Diesel backup generator for power outages",
            status=ControlStatus.ACTIVE,
        ),
    ]

    multiplier, adjustments = calculate_control_multiplier(unrelated_controls)
    assert multiplier == 1.0
    assert len(adjustments) == 0


def test_stabilization_recognized_controls_reduce_risk():
    """Recognized controls (e.g. WAF, EDR) must apply discounts and reduce risk."""
    recognized_controls = [
        CompensatingControl(
            control_id="CTL-WAF-01",
            name="Cloudflare Enterprise WAF",
            description="Layer 7 inspection and managed rulesets",
            status=ControlStatus.ACTIVE,
        ),
        CompensatingControl(
            control_id="CTL-EDR-01",
            name="CrowdStrike Falcon Enterprise EDR",
            description="Kernel behavioral monitoring and containment",
            status=ControlStatus.ACTIVE,
        ),
    ]

    multiplier, adjustments = calculate_control_multiplier(recognized_controls)
    # WAF: 0.15, EDR: 0.10 -> total 0.25 -> multiplier 0.75
    assert multiplier == 0.75
    assert len(adjustments) == 2


def test_stabilization_multiplier_bounds():
    """Multiplier must never fall below 0.60 or exceed 1.00."""
    excessive_controls = [
        CompensatingControl(control_id="C1", name="AIR GAP", description="Air Gap", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C2", name="WAF", description="WAF", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C3", name="EDR", description="EDR", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C4", name="MICROSEGMENTATION", description="mTLS", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C5", name="SANDBOX", description="Sandbox", status=ControlStatus.ACTIVE),
    ]
    multiplier, _ = calculate_control_multiplier(excessive_controls)
    assert multiplier == CONTROL_MULTIPLIER_MIN
    assert multiplier == 0.60

    # Ensure bounds cannot exceed 1.0
    clamped_max = calculate_ers(weighted_risk=50.0, control_multiplier=1.25)
    assert clamped_max == 50.0  # control_multiplier clamped to 1.00


# ==============================================================================
# 5. Boundary Robustness
# ==============================================================================


def test_stabilization_ers_bounds():
    """Verify ERS remains strictly bounded within [0.0, 100.0]."""
    assert calculate_ers(0.0, 1.0) == 0.0
    assert calculate_ers(100.0, 1.0) == 100.0
    assert calculate_ers(150.0, 1.0) == 100.0  # Overshoot clamped
    assert calculate_ers(-10.0, 1.0) == 0.0   # Undershoot clamped


# ==============================================================================
# 6. Duplication Removal & Single Source of Truth
# ==============================================================================


def test_stabilization_consolidated_thresholds():
    """Verify that risk_config threshold constants are unified with decision_mapping."""
    assert TIER_THRESHOLD_CRITICAL == DECISION_THRESHOLD_ACT == 85.0
    assert TIER_THRESHOLD_HIGH == DECISION_THRESHOLD_ATTEND == 65.0
    assert TIER_THRESHOLD_MEDIUM == DECISION_THRESHOLD_PLAN == 40.0
    assert TIER_THRESHOLD_LOW == DECISION_THRESHOLD_TRACK == 0.0


def test_stabilization_consolidated_decision_helpers():
    """Verify that determine_risk_tier and determine_remediation_decision are consistent."""
    for score in [10.0, 39.99, 40.0, 55.0, 64.99, 65.0, 75.0, 84.99, 85.0, 95.0]:
        tier = determine_risk_tier(score)
        expected_tier = map_ers_to_risk_tier(score)
        assert tier == expected_tier

        # Default remediation decision consistency
        decision = determine_remediation_decision(score)
        expected_decision = map_ers_to_remediation_decision(score)
        assert decision == expected_decision

        # Control-mitigated consistency in PLAN band
        decision_with_ctrl = determine_remediation_decision(score, has_active_controls=True)
        expected_ctrl = map_ers_to_remediation_decision(score, has_compensating_controls=True)
        assert decision_with_ctrl == expected_ctrl
