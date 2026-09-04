"""Focused unit tests for the AegisPatch deterministic environmental risk engine."""

from datetime import datetime, timezone
import pytest
from src.schemas import (
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
    ThreatConfidence,
    ThreatEvidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
)
from src.tools import (
    CONTROL_MULTIPLIER_MAX,
    CONTROL_MULTIPLIER_MIN,
    CRITICALITY_SCORES,
    EXPOSURE_SCORES,
    SENSITIVITY_SCORES,
    calculate_base_score,
    calculate_control_multiplier,
    calculate_environmental_score,
    calculate_ers,
    calculate_threat_score,
    calculate_weighted_risk,
    evaluate_risk,
)


@pytest.fixture
def base_asset() -> Asset:
    return Asset(
        asset_id="ASSET-TEST-01",
        hostname="test-node.aegis.internal",
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
def base_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="FINDING-TEST-01",
        cve_id="CVE-2023-38545",
        title="curl buffer overflow",
        description="Heap buffer overflow in SOCKS5 handshake",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1",
        fixed_version="8.4.0",
        asset_id="ASSET-TEST-01",
        source="synthetic_benchmark",
    )


# ==============================================================================
# 1. CVSS Conversion Test
# ==============================================================================

def test_cvss_conversion():
    assert calculate_base_score(0.0) == 0.0
    assert calculate_base_score(5.0) == 50.0
    assert calculate_base_score(9.8) == 98.0
    assert calculate_base_score(10.0) == 100.0

    with pytest.raises(ValueError):
        calculate_base_score(-0.1)

    with pytest.raises(ValueError):
        calculate_base_score(10.1)


# ==============================================================================
# 2. Threat Score Calculation Test
# ==============================================================================

def test_threat_score_calculation():
    now = datetime.now(timezone.utc)
    threat = ThreatEvidence(
        evidence_id="TH-01",
        cve_id="CVE-2023-38545",
        is_cisa_kev=False,
        epss_score=0.50,
        public_poc_available=True,
        threat_source="FIRST EPSS",
        retrieved_at=now,
    )
    # T = (0.50 * 80) + (1.0 * 20) = 40 + 20 = 60.0
    score, details = calculate_threat_score(threat)
    assert score == 60.0
    assert details["threat_status"] == "EPSS_AND_POC_EVALUATED"
    assert details["epss_contribution"] == 40.0
    assert details["poc_contribution"] == 20.0


# ==============================================================================
# 3. Environmental Score Calculation Test
# ==============================================================================

def test_environmental_score_calculation(base_asset):
    # base_asset has CRITICAL (100.0), INTERNET_FACING (100.0), RESTRICTED (100.0)
    # E = (100 * 0.50) + (100 * 0.30) + (100 * 0.20) = 100.0
    score, details = calculate_environmental_score(base_asset)
    assert score == 100.0

    # Low-value isolated asset
    low_asset = Asset(
        asset_id="ASSET-LOW",
        hostname="low.aegis.internal",
        asset_type=AssetType.CONTAINER,
        business_tier=BusinessTier.NON_CRITICAL,
        criticality=AssetCriticality.LOW,        # 25.0
        network_exposure=NetworkExposure.AIR_GAPPED, # 10.0
        data_sensitivity=DataSensitivity.PUBLIC,     # 10.0
        environment=EnvironmentType.TESTING,
        owner_team="Dev",
        patch_window=PatchWindow(day_of_week="Daily", start_time_utc="04:00", duration_hours=2.0),
    )
    # E = (25 * 0.50) + (10 * 0.30) + (10 * 0.20) = 12.5 + 3.0 + 2.0 = 17.5
    low_score, _ = calculate_environmental_score(low_asset)
    assert low_score == 17.5


# ==============================================================================
# 4. Weighted Risk Calculation Test
# ==============================================================================

def test_weighted_risk_calculation():
    # R = (0.25 * B) + (0.40 * T) + (0.35 * E)
    # B = 80.0, T = 50.0, E = 60.0
    # R = (0.25 * 80) + (0.40 * 50) + (0.35 * 60) = 20 + 20 + 21 = 61.0
    r = calculate_weighted_risk(base_score=80.0, threat_score=50.0, environmental_score=60.0)
    assert r == 61.0


# ==============================================================================
# 5. Control Multiplier Application Test
# ==============================================================================

def test_control_multiplier_application():
    controls = [
        CompensatingControl(
            control_id="CTL-WAF-01",
            name="Cloudflare WAF",
            description="Layer 7 WAF virtual patching",
            status=ControlStatus.ACTIVE,
        ),
        CompensatingControl(
            control_id="CTL-EDR-01",
            name="CrowdStrike EDR",
            description="Kernel behavioral EDR containment",
            status=ControlStatus.ACTIVE,
        ),
    ]
    # WAF discount = 0.15, EDR discount = 0.10. Total discount = 0.25. Multiplier = 0.75
    multiplier, adjustments = calculate_control_multiplier(controls)
    assert multiplier == 0.75
    assert len(adjustments) == 2
    assert adjustments[0].adjustment_factor == -0.15
    assert adjustments[1].adjustment_factor == -0.10


# ==============================================================================
# 6. ERS 0–100 Bounds Test
# ==============================================================================

def test_ers_bounds():
    # Maximum theoretical bounds
    max_ers = calculate_ers(weighted_risk=100.0, control_multiplier=1.0)
    assert max_ers == 100.0

    # Overshoot protection
    overshoot_ers = calculate_ers(weighted_risk=120.0, control_multiplier=1.0)
    assert overshoot_ers == 100.0

    # Minimum theoretical bounds
    min_ers = calculate_ers(weighted_risk=0.0, control_multiplier=0.60)
    assert min_ers == 0.0


# ==============================================================================
# 7. Missing EPSS Handling Test
# ==============================================================================

def test_missing_epss_handling():
    now = datetime.now(timezone.utc)
    threat_none_epss = ThreatEvidence(
        evidence_id="TH-NONE",
        cve_id="CVE-2024-9999",
        is_cisa_kev=False,
        epss_score=None,  # Missing EPSS
        public_poc_available=True,
        threat_source="NVD",
        retrieved_at=now,
    )
    score, details = calculate_threat_score(threat_none_epss)
    assert details["epss_available"] is False
    assert details["epss_contribution"] == 0.0
    assert details["poc_contribution"] == 20.0
    # Total threat is only from PoC = 20.0
    assert score == 20.0


# ==============================================================================
# 8. Missing PoC Handling Test
# ==============================================================================

def test_missing_poc_handling():
    now = datetime.now(timezone.utc)
    threat_no_poc = ThreatEvidence(
        evidence_id="TH-NO-POC",
        cve_id="CVE-2024-8888",
        is_cisa_kev=False,
        epss_score=0.25,
        public_poc_available=False,
        threat_source="FIRST EPSS",
        retrieved_at=now,
    )
    score, details = calculate_threat_score(threat_no_poc)
    assert details["poc_contribution"] == 0.0
    assert score == 20.0  # 0.25 * 80.0 = 20.0


# ==============================================================================
# 9. CISA KEV Handling Test
# ==============================================================================

def test_cisa_kev_handling():
    now = datetime.now(timezone.utc)
    threat_kev = ThreatEvidence(
        evidence_id="TH-KEV",
        cve_id="CVE-2021-44228",
        is_cisa_kev=True,
        epss_score=0.10,  # Should be overridden by KEV
        public_poc_available=False,
        threat_source="CISA KEV",
        retrieved_at=now,
    )
    score, details = calculate_threat_score(threat_kev)
    assert score == 100.0
    assert details["threat_status"] == "CISA_KEV_CONFIRMED"


# ==============================================================================
# 10. No-Control Case Test
# ==============================================================================

def test_no_control_case(base_asset, base_finding):
    # base_asset has no controls
    assessment = evaluate_risk(finding=base_finding, asset=base_asset, threat=None)
    assert assessment.calculation_metadata["control_multiplier"] == "1.0"
    assert len(assessment.control_adjustments) == 0


# ==============================================================================
# 11. Recognized Compensating-Control Case Test
# ==============================================================================

def test_recognized_compensating_control_case(base_asset, base_finding):
    base_asset.compensating_controls = [
        CompensatingControl(
            control_id="CTL-WAF-01",
            name="Cloudflare WAF",
            description="Layer 7 inspection ruleset",
            status=ControlStatus.ACTIVE,
        )
    ]
    assessment = evaluate_risk(finding=base_finding, asset=base_asset, threat=None)
    # WAF discount = 0.15 -> multiplier = 0.85
    assert assessment.calculation_metadata["control_multiplier"] == "0.85"
    assert len(assessment.control_adjustments) == 1
    assert assessment.control_adjustments[0].adjustment_factor == -0.15


# ==============================================================================
# 12. Determinism Test
# ==============================================================================

def test_calculation_determinism(base_asset, base_finding):
    now = datetime.now(timezone.utc)
    threat = ThreatEvidence(
        evidence_id="TH-DET",
        cve_id=base_finding.cve_id,
        is_cisa_kev=False,
        epss_score=0.75,
        public_poc_available=True,
        threat_source="FIRST EPSS",
        retrieved_at=now,
    )

    result_1 = evaluate_risk(base_finding, base_asset, threat)
    result_2 = evaluate_risk(base_finding, base_asset, threat)

    assert result_1.environmental_risk_score == result_2.environmental_risk_score
    assert result_1.risk_tier == result_2.risk_tier
    assert result_1.decision == result_2.decision
    assert result_1.calculation_metadata == result_2.calculation_metadata


# ==============================================================================
# 13. Invalid Multiplier Protection Test
# ==============================================================================

def test_invalid_multiplier_protection():
    # If controls attempt to reduce below 0.60, multiplier clamps at 0.60
    many_controls = [
        CompensatingControl(control_id="C1", name="WAF", description="WAF", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C2", name="AIR_GAP", description="AIR_GAP", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C3", name="EDR", description="EDR", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C4", name="MICROSEGMENTATION", description="MICROSEGMENTATION", status=ControlStatus.ACTIVE),
        CompensatingControl(control_id="C5", name="SANDBOXING", description="SANDBOXING", status=ControlStatus.ACTIVE),
    ]
    # Sum of discounts: 0.15 + 0.20 + 0.10 + 0.10 + 0.10 = 0.65 -> raw = 0.35 -> clamped to 0.60
    multiplier, _ = calculate_control_multiplier(many_controls)
    assert multiplier == CONTROL_MULTIPLIER_MIN
    assert multiplier == 0.60

    # Inactive controls must NOT reduce multiplier
    inactive_controls = [
        CompensatingControl(control_id="C1", name="WAF", description="WAF", status=ControlStatus.INACTIVE),
    ]
    inactive_mult, adj = calculate_control_multiplier(inactive_controls)
    assert inactive_mult == 1.0
    assert len(adj) == 0


# ==============================================================================
# 14. Boundary Values Test
# ==============================================================================

def test_boundary_values():
    # Absolute minimum inputs
    min_base = calculate_base_score(0.0)
    min_threat, _ = calculate_threat_score(None)
    min_r = calculate_weighted_risk(min_base, min_threat, 0.0)
    min_ers = calculate_ers(min_r, CONTROL_MULTIPLIER_MAX)
    assert min_ers == 0.0

    # Absolute maximum inputs
    max_base = calculate_base_score(10.0)
    now = datetime.now(timezone.utc)
    max_threat, _ = calculate_threat_score(
        ThreatEvidence(
            evidence_id="TH-MAX",
            cve_id="CVE-2024-0001",
            is_cisa_kev=True,
            epss_score=1.0,
            public_poc_available=True,
            threat_source="KEV",
            retrieved_at=now,
        )
    )
    max_r = calculate_weighted_risk(max_base, max_threat, 100.0)
    max_ers = calculate_ers(max_r, CONTROL_MULTIPLIER_MAX)
    assert max_ers == 100.0
