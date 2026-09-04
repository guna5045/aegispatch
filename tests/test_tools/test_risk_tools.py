"""Tests for Phase 7 risk tools: calculate_environmental_risk and map_ssvc_decision."""

import pytest
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    BusinessTier,
    EnvironmentType,
    NetworkExposure,
)
from src.schemas.risk import RiskTier
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.decision_mapping import AegisDecision
from src.tools.risk_engine import evaluate_risk
from src.tools.risk_tools import (
    calculate_environmental_risk,
    map_ssvc_decision,
)
from src.tools.schemas import (
    CalculateEnvironmentalRiskInput,
    MapSsvcDecisionInput,
    SideEffectClass,
    ToolStatus,
)


@pytest.fixture
def sample_finding():
    return VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow",
        description="Heap overflow in SOCKS5 proxy handshake.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-001",
        source="synthetic_benchmark",
    )


@pytest.fixture
def sample_asset():
    from src.schemas.asset import AssetType, CompensatingControl, ControlStatus, DataSensitivity
    return Asset(
        asset_id="ASSET-001",
        hostname="gw-prod-01",
        asset_type=AssetType.SERVER,
        environment=EnvironmentType.PRODUCTION,
        criticality=AssetCriticality.CRITICAL,
        business_tier=BusinessTier.MISSION_CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        owner_team="SecOps",
        compensating_controls=[
            CompensatingControl(
                control_id="CTRL-01",
                name="WAF",
                description="Cloud WAF",
                status=ControlStatus.ACTIVE,
            )
        ],
    )


def test_calculate_environmental_risk_delegation(sample_finding, sample_asset):
    """Verify tool output matches the authoritative Phase 3 evaluate_risk engine exactly."""
    inp = CalculateEnvironmentalRiskInput(
        finding=sample_finding,
        asset=sample_asset,
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
    )
    out = calculate_environmental_risk(inp)

    # Authoritative reference
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    threat = ThreatEvidence(
        evidence_id="EV-001",
        cve_id=sample_finding.cve_id,
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
        threat_source="synthetic_benchmark",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )
    direct = evaluate_risk(
        finding=sample_finding,
        asset=sample_asset,
        threat=threat,
    )

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.COMPUTE_ONLY
    meta = direct.calculation_metadata
    assert out.base_score == float(meta["base_score"])
    assert out.threat_score == float(meta["threat_score"])
    assert out.environmental_score == float(meta["environmental_score"])
    assert out.raw_risk_score == float(meta["weighted_risk"])
    assert out.control_multiplier == float(meta["control_multiplier"])
    assert out.environmental_risk_score == direct.environmental_risk_score
    assert out.risk_tier == direct.risk_tier
    assert out.decision.value == meta["aegis_decision"]
    assert out.decision == AegisDecision(meta["aegis_decision"])


def test_map_ssvc_decision_act():
    inp = MapSsvcDecisionInput(ers_score=92.0, has_compensating_controls=False)
    out = map_ssvc_decision(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.decision == AegisDecision.ACT
    assert out.risk_tier == RiskTier.CRITICAL


def test_map_ssvc_decision_attend():
    inp = MapSsvcDecisionInput(ers_score=75.0, has_compensating_controls=False)
    out = map_ssvc_decision(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.decision == AegisDecision.ATTEND
    assert out.risk_tier == RiskTier.HIGH


def test_map_ssvc_decision_plan():
    inp = MapSsvcDecisionInput(ers_score=55.0, has_compensating_controls=False)
    out = map_ssvc_decision(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.decision == AegisDecision.PLAN
    assert out.risk_tier == RiskTier.MEDIUM


def test_map_ssvc_decision_track():
    inp = MapSsvcDecisionInput(ers_score=25.0, has_compensating_controls=False)
    out = map_ssvc_decision(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.decision == AegisDecision.TRACK
    assert out.risk_tier == RiskTier.LOW
