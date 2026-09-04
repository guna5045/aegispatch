"""Unit tests for AegisPatch Phase 3B: Risk Level and Remediation Decision Mapping."""

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
from src.schemas.risk import (
    RemediationDecision,
    RiskAssessment,
    RiskTier,
)
from src.schemas.threat import ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools import (
    DECISION_MEANINGS,
    DECISION_THRESHOLD_ACT,
    DECISION_THRESHOLD_ATTEND,
    DECISION_THRESHOLD_PLAN,
    DECISION_THRESHOLD_TRACK,
    AegisDecision,
    DecisionResult,
    evaluate_risk,
    get_decision_details,
    map_ers_to_decision,
    map_ers_to_remediation_decision,
    map_ers_to_risk_tier,
)

# ==============================================================================
# 1. Decision Band Boundary and Value Tests (Tests 1–8)
# ==============================================================================


def test_ers_0_maps_to_track():
    """1. ERS = 0 -> TRACK."""
    decision = map_ers_to_decision(0.0)
    assert decision == AegisDecision.TRACK
    assert decision == "TRACK"
    assert decision.value == "TRACK"


def test_ers_39_99_maps_to_track():
    """2. ERS = 39.99 -> TRACK."""
    decision = map_ers_to_decision(39.99)
    assert decision == AegisDecision.TRACK
    assert decision == "TRACK"

    # Micro-boundary check
    assert map_ers_to_decision(39.9999) == AegisDecision.TRACK


def test_ers_40_maps_to_plan():
    """3. ERS = 40 -> PLAN."""
    decision = map_ers_to_decision(40.0)
    assert decision == AegisDecision.PLAN
    assert decision == "PLAN"
    assert decision.value == "PLAN"

    # Micro-boundary check just above threshold
    assert map_ers_to_decision(40.0001) == AegisDecision.PLAN


def test_ers_64_99_maps_to_plan():
    """4. ERS = 64.99 -> PLAN."""
    decision = map_ers_to_decision(64.99)
    assert decision == AegisDecision.PLAN
    assert decision == "PLAN"

    # Micro-boundary check
    assert map_ers_to_decision(64.9999) == AegisDecision.PLAN


def test_ers_65_maps_to_attend():
    """5. ERS = 65 -> ATTEND."""
    decision = map_ers_to_decision(65.0)
    assert decision == AegisDecision.ATTEND
    assert decision == "ATTEND"
    assert decision.value == "ATTEND"

    # Micro-boundary check just above threshold
    assert map_ers_to_decision(65.0001) == AegisDecision.ATTEND


def test_ers_84_99_maps_to_attend():
    """6. ERS = 84.99 -> ATTEND."""
    decision = map_ers_to_decision(84.99)
    assert decision == AegisDecision.ATTEND
    assert decision == "ATTEND"

    # Micro-boundary check
    assert map_ers_to_decision(84.9999) == AegisDecision.ATTEND


def test_ers_85_maps_to_act():
    """7. ERS = 85 -> ACT."""
    decision = map_ers_to_decision(85.0)
    assert decision == AegisDecision.ACT
    assert decision == "ACT"
    assert decision.value == "ACT"

    # Micro-boundary check just above threshold
    assert map_ers_to_decision(85.0001) == AegisDecision.ACT


def test_ers_100_maps_to_act():
    """8. ERS = 100 -> ACT."""
    decision = map_ers_to_decision(100.0)
    assert decision == AegisDecision.ACT
    assert decision == "ACT"
    assert decision.value == "ACT"


# ==============================================================================
# 2. Out-of-Bounds & Invalid Input Rejection (Tests 9–10)
# ==============================================================================


def test_negative_ers_rejected():
    """9. Values below 0 are rejected."""
    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(-0.01)

    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(-1.0)

    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(-100.0)


def test_above_100_ers_rejected():
    """10. Values above 100 are rejected."""
    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(100.01)

    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(101.0)

    with pytest.raises(ValueError, match="ERS must be between 0.0 and 100.0"):
        map_ers_to_decision(250.0)


def test_invalid_type_rejected():
    """Non-numeric inputs and NaN are rejected."""
    with pytest.raises(TypeError, match="ERS must be a numeric float or int"):
        map_ers_to_decision(None)  # type: ignore

    with pytest.raises(TypeError, match="ERS must be a numeric float or int"):
        map_ers_to_decision("85.0")  # type: ignore

    with pytest.raises(ValueError, match="ERS cannot be NaN"):
        map_ers_to_decision(float("nan"))


# ==============================================================================
# 3. Determinism & Reachability Tests (Tests 11–12)
# ==============================================================================


def test_decision_determinism():
    """11. Same ERS always produces the same decision."""
    test_scores = [0.0, 15.5, 39.99, 40.0, 58.2, 64.99, 65.0, 72.3, 84.99, 85.0, 91.4, 100.0]

    for score in test_scores:
        first_eval = map_ers_to_decision(score)
        for _ in range(20):
            assert map_ers_to_decision(score) == first_eval


def test_all_four_decision_bands_reachable():
    """12. All four decision bands are reachable."""
    sample_scores = {
        AegisDecision.TRACK: 20.0,
        AegisDecision.PLAN: 50.0,
        AegisDecision.ATTEND: 75.0,
        AegisDecision.ACT: 90.0,
    }

    observed_decisions = {map_ers_to_decision(score) for score in sample_scores.values()}
    assert observed_decisions == {
        AegisDecision.TRACK,
        AegisDecision.PLAN,
        AegisDecision.ATTEND,
        AegisDecision.ACT,
    }
    assert len(observed_decisions) == 4


# ==============================================================================
# 4. Phase 1 Domain Model Integration Tests
# ==============================================================================


def test_phase1_risk_tier_mapping():
    """Verify that ERS maps correctly to Phase 1 RiskTier enum."""
    assert map_ers_to_risk_tier(91.4) == RiskTier.CRITICAL
    assert map_ers_to_risk_tier(85.0) == RiskTier.CRITICAL
    assert map_ers_to_risk_tier(72.0) == RiskTier.HIGH
    assert map_ers_to_risk_tier(65.0) == RiskTier.HIGH
    assert map_ers_to_risk_tier(58.2) == RiskTier.MEDIUM
    assert map_ers_to_risk_tier(40.0) == RiskTier.MEDIUM
    assert map_ers_to_risk_tier(25.0) == RiskTier.LOW
    assert map_ers_to_risk_tier(0.0) == RiskTier.LOW


def test_phase1_remediation_decision_mapping():
    """Verify that ERS maps correctly to Phase 1 RemediationDecision enum."""
    assert map_ers_to_remediation_decision(91.4) == RemediationDecision.IMMEDIATE_PATCH
    assert map_ers_to_remediation_decision(72.0) == RemediationDecision.SCHEDULED_PATCH
    # Without compensating controls -> SCHEDULED_PATCH
    assert map_ers_to_remediation_decision(50.0, has_compensating_controls=False) == RemediationDecision.SCHEDULED_PATCH
    # With compensating controls in PLAN band -> MITIGATE
    assert map_ers_to_remediation_decision(50.0, has_compensating_controls=True) == RemediationDecision.MITIGATE
    assert map_ers_to_remediation_decision(20.0) == RemediationDecision.MONITOR


def test_get_decision_details_structure():
    """Verify detailed decision structure matches benchmark specification."""
    # Test ACT example from prompt
    act_details = get_decision_details(91.4)
    assert isinstance(act_details, DecisionResult)
    assert act_details.ers == 91.4
    assert act_details.decision == AegisDecision.ACT
    assert act_details.risk_tier == RiskTier.CRITICAL
    assert act_details.remediation_decision == RemediationDecision.IMMEDIATE_PATCH
    assert act_details.meaning == DECISION_MEANINGS[AegisDecision.ACT]
    assert "Immediate remediation should be prioritized." in act_details.meaning
    assert "91.4" in act_details.rationale

    # Test PLAN example from prompt
    plan_details = get_decision_details(58.2)
    assert isinstance(plan_details, DecisionResult)
    assert plan_details.ers == 58.2
    assert plan_details.decision == AegisDecision.PLAN
    assert plan_details.risk_tier == RiskTier.MEDIUM
    assert plan_details.remediation_decision == RemediationDecision.SCHEDULED_PATCH
    assert "Remediation should be planned and scheduled" in plan_details.meaning


def test_decision_meanings_completeness():
    """Verify that all four decision meanings exist and have non-empty definitions."""
    for decision in AegisDecision:
        meaning = DECISION_MEANINGS[decision]
        assert isinstance(meaning, str)
        assert len(meaning) > 10


def test_evaluate_risk_end_to_end_incorporates_decision():
    """Verify that evaluate_risk() records Aegis decision band and Phase 1 models cohesively."""
    finding = VulnerabilityFinding(
        finding_id="FINDING-TEST-B",
        cve_id="CVE-2023-38545",
        title="curl buffer overflow",
        description="Heap buffer overflow in SOCKS5 handshake",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1",
        fixed_version="8.4.0",
        asset_id="ASSET-TEST-B",
        source="synthetic_benchmark",
    )
    asset = Asset(
        asset_id="ASSET-TEST-B",
        hostname="act-target.aegis.internal",
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
    threat = ThreatEvidence(
        evidence_id="TH-TEST-B",
        cve_id="CVE-2023-38545",
        is_cisa_kev=True,
        epss_score=0.95,
        public_poc_available=True,
        threat_source="CISA KEV",
        retrieved_at=datetime.now(timezone.utc),
    )

    assessment: RiskAssessment = evaluate_risk(finding=finding, asset=asset, threat=threat)

    # High severity inputs produce high ERS -> ACT
    assert assessment.environmental_risk_score >= DECISION_THRESHOLD_ACT
    assert assessment.risk_tier == RiskTier.CRITICAL
    assert assessment.decision == RemediationDecision.IMMEDIATE_PATCH
    assert assessment.calculation_metadata["aegis_decision"] == "ACT"
    assert "ACT" in assessment.explanation
    assert any("AegisPatch decision band: ACT" in ev for ev in assessment.supporting_evidence)
