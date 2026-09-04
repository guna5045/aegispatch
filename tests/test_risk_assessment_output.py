"""Focused tests for AegisPatch Phase 3D: Complete Risk Assessment Output."""

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
    AegisDecision,
    evaluate_risk,
    generate_risk_explanation,
    map_ers_to_decision,
    map_ers_to_remediation_decision,
    map_ers_to_risk_tier,
)


@pytest.fixture
def target_asset() -> Asset:
    return Asset(
        asset_id="ASSET-PAY-01",
        hostname="payment-server-prod.aegis.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.MISSION_CRITICAL,
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        environment=EnvironmentType.PRODUCTION,
        owner_team="Payments Engineering",
        patch_window=PatchWindow(day_of_week="Sunday", start_time_utc="02:00", duration_hours=3.0),
        compensating_controls=[],
    )


@pytest.fixture
def target_finding() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="FINDING-PAY-01",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 heap buffer overflow",
        description="Heap buffer overflow in SOCKS5 proxy handshake",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1",
        fixed_version="8.4.0",
        asset_id="ASSET-PAY-01",
        source="synthetic_benchmark",
    )


@pytest.fixture
def target_threat() -> ThreatEvidence:
    return ThreatEvidence(
        evidence_id="TH-PAY-01",
        cve_id="CVE-2023-38545",
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
        threat_source="CISA KEV",
        retrieved_at=datetime.now(timezone.utc),
    )


# ==============================================================================
# 1. Complete RiskAssessment Generation & Contract Adherence
# ==============================================================================


def test_complete_risk_assessment_produced(target_finding, target_asset, target_threat):
    """1. Verify that a complete, valid Phase 1 RiskAssessment is produced."""
    assessment = evaluate_risk(
        finding=target_finding,
        asset=target_asset,
        threat=target_threat,
        assessment_id="RSK-COMPLETE-01",
    )

    assert isinstance(assessment, RiskAssessment)
    assert assessment.assessment_id == "RSK-COMPLETE-01"
    assert assessment.finding_id == target_finding.finding_id
    assert assessment.cve_id == target_finding.cve_id
    assert assessment.asset_id == target_asset.asset_id
    assert assessment.cvss_score == 9.8
    assert assessment.environmental_risk_score > 0.0
    assert assessment.risk_tier in [RiskTier.CRITICAL, RiskTier.HIGH, RiskTier.MEDIUM, RiskTier.LOW]
    assert assessment.decision in [
        RemediationDecision.IMMEDIATE_PATCH,
        RemediationDecision.SCHEDULED_PATCH,
        RemediationDecision.MITIGATE,
        RemediationDecision.MONITOR,
    ]
    assert len(assessment.explanation) > 50
    assert len(assessment.supporting_evidence) >= 5
    assert len(assessment.calculation_metadata) >= 10


# ==============================================================================
# 2. Traceability & Identity Preservation
# ==============================================================================


def test_vulnerability_identity_preserved(target_finding, target_asset, target_threat):
    """2. Verify that vulnerability identity fields are preserved exactly."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    assert assessment.finding_id == "FINDING-PAY-01"
    assert assessment.cve_id == "CVE-2023-38545"
    assert assessment.cvss_score == 9.8
    assert assessment.environmental_context.finding_id == "FINDING-PAY-01"


def test_asset_identity_preserved(target_finding, target_asset, target_threat):
    """3. Verify that asset identity fields are preserved exactly."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    assert assessment.asset_id == "ASSET-PAY-01"
    assert assessment.environmental_context.asset_id == "ASSET-PAY-01"
    assert "payment-server-prod.aegis.internal" in assessment.explanation


def test_ers_preserved(target_finding, target_asset, target_threat):
    """4. Verify that calculated ERS is bounded and preserved."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    assert 0.0 <= assessment.environmental_risk_score <= 100.0
    assert float(assessment.calculation_metadata["final_ers"]) == assessment.environmental_risk_score


# ==============================================================================
# 3. Decision Band Consistency
# ==============================================================================


def test_risk_tier_matches_ers(target_finding, target_asset, target_threat):
    """5. Verify that risk tier matches calculated ERS."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    expected_tier = map_ers_to_risk_tier(assessment.environmental_risk_score)
    assert assessment.risk_tier == expected_tier


def test_aegis_decision_matches_ers(target_finding, target_asset, target_threat):
    """6. Verify that Aegis decision band matches calculated ERS."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    expected_decision = map_ers_to_decision(assessment.environmental_risk_score)
    assert assessment.calculation_metadata["aegis_decision"] == expected_decision.value


def test_remediation_decision_matches_decision(target_finding, target_asset, target_threat):
    """7. Verify that remediation decision matches the decision band and controls."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    has_controls = len(assessment.control_adjustments) > 0
    expected_remediation = map_ers_to_remediation_decision(
        assessment.environmental_risk_score, has_compensating_controls=has_controls
    )
    assert assessment.decision == expected_remediation


# ==============================================================================
# 4. Calculation Metadata Completeness
# ==============================================================================


def test_calculation_metadata_diagnostic_values(target_finding, target_asset, target_threat):
    """8. Verify that calculation_metadata provides complete diagnostic transparency."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    meta = assessment.calculation_metadata

    expected_keys = [
        "engine",
        "base_score",
        "cvss_score",
        "threat_score",
        "environmental_score",
        "unmitigated_risk",
        "weighted_risk",
        "control_multiplier",
        "final_ers",
        "aegis_decision",
        "risk_tier",
        "remediation_decision",
        "epss_available",
        "epss_score",
        "is_cisa_kev",
        "public_poc_available",
        "active_controls_count",
    ]

    for key in expected_keys:
        assert key in meta, f"Metadata key '{key}' missing."
        assert isinstance(meta[key], str)

    assert meta["engine"] == "aegis_ers_deterministic_v1"
    assert meta["is_cisa_kev"] == "true"
    assert meta["public_poc_available"] == "true"
    assert meta["epss_available"] == "true"
    assert meta["epss_score"] == "0.92"


# ==============================================================================
# 5. Supporting Evidence Factual Integrity
# ==============================================================================


def test_supporting_evidence_no_fabrication(target_finding, target_asset, target_threat):
    """9. Verify supporting evidence contains only supplied/calculated facts without external invention."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    evidence = assessment.supporting_evidence

    # Must contain factual statements about CVSS, KEV, criticality, exposure, data sensitivity, scores
    assert any("Base CVSS score 9.8" in ev for ev in evidence)
    assert any("CISA KEV" in ev for ev in evidence)
    assert any("Asset criticality: CRITICAL" in ev for ev in evidence)
    assert any("Network exposure: INTERNET_FACING" in ev for ev in evidence)
    assert any("Data sensitivity: RESTRICTED" in ev for ev in evidence)
    assert any("Final Environmental Risk Score" in ev for ev in evidence)

    # Must NOT invent fake standards, NIST SP 800-XX, or RAG policies yet
    for ev in evidence:
        assert "NIST SP" not in ev
        assert "ISO 27001" not in ev
        assert "POL-SEC" not in ev  # No RAG policy citations until future phase


# ==============================================================================
# 6. Missing Information Handling
# ==============================================================================


def test_missing_epss_representation(target_finding, target_asset):
    """10. Verify that missing EPSS is transparently distinguished in explanation and metadata."""
    threat_no_epss = ThreatEvidence(
        evidence_id="TH-NO-EPSS",
        cve_id=target_finding.cve_id,
        is_cisa_kev=False,
        epss_score=None,
        public_poc_available=True,
        threat_source="NVD",
        retrieved_at=datetime.now(timezone.utc),
    )
    assessment = evaluate_risk(target_finding, target_asset, threat_no_epss)

    assert assessment.calculation_metadata["epss_available"] == "false"
    assert assessment.calculation_metadata["epss_score"] == "none"
    assert "EPSS score unavailable" in assessment.explanation
    assert any("EPSS exploit probability unavailable / unindexed" in ev for ev in assessment.supporting_evidence)


def test_missing_threat_evidence_handled(target_finding, target_asset):
    """11. Verify that completely absent threat evidence defaults to 0.0 and does not invent signals."""
    assessment = evaluate_risk(target_finding, target_asset, threat=None)

    assert assessment.calculation_metadata["threat_score"] == "0.0"
    assert assessment.calculation_metadata["is_cisa_kev"] == "false"
    assert assessment.calculation_metadata["public_poc_available"] == "false"
    assert assessment.calculation_metadata["epss_available"] == "false"
    assert "External threat intelligence was absent" in assessment.explanation
    assert any("Threat intelligence: Absent" in ev for ev in assessment.supporting_evidence)


# ==============================================================================
# 7. Compensating Control Cases
# ==============================================================================


def test_no_control_case_represented(target_finding, target_asset):
    """12. Verify no-control case is accurately documented in metadata and explanation."""
    target_asset.compensating_controls = []
    assessment = evaluate_risk(target_finding, target_asset, threat=None)

    assert assessment.calculation_metadata["control_multiplier"] == "1.0"
    assert assessment.calculation_metadata["active_controls_count"] == "0"
    assert len(assessment.control_adjustments) == 0
    assert "No active compensating controls were applied" in assessment.explanation


def test_recognized_control_case_contains_adjustment(target_finding, target_asset):
    """13. Verify recognized controls produce explicit ControlAdjustment records."""
    target_asset.compensating_controls = [
        CompensatingControl(
            control_id="CTL-WAF-01",
            name="Cloudflare Enterprise WAF",
            description="Layer 7 inspection ruleset",
            status=ControlStatus.ACTIVE,
        )
    ]
    assessment = evaluate_risk(target_finding, target_asset, threat=None)

    assert len(assessment.control_adjustments) == 1
    adj = assessment.control_adjustments[0]
    assert adj.control_id == "CTL-WAF-01"
    assert adj.name == "Cloudflare Enterprise WAF"
    assert adj.adjustment_factor == -0.15
    assert assessment.calculation_metadata["control_multiplier"] == "0.85"
    assert "Cloudflare Enterprise WAF" in assessment.explanation


def test_unknown_control_no_fabricated_discount(target_finding, target_asset):
    """14. Verify unknown / unrelated controls do not receive invented discounts."""
    target_asset.compensating_controls = [
        CompensatingControl(
            control_id="CTL-UNRELATED",
            name="Physical Security Gate",
            description="Motorized vehicle barrier",
            status=ControlStatus.ACTIVE,
        )
    ]
    assessment = evaluate_risk(target_finding, target_asset, threat=None)

    assert len(assessment.control_adjustments) == 0
    assert assessment.calculation_metadata["control_multiplier"] == "1.0"
    assert assessment.calculation_metadata["active_controls_count"] == "0"


# ==============================================================================
# 8. Determinism and Explanation Integrity
# ==============================================================================


def test_explanation_consistent_with_calculation(target_finding, target_asset, target_threat):
    """15. Verify that explanation naturally reflects the calculated values."""
    assessment = evaluate_risk(target_finding, target_asset, target_threat)
    exp = assessment.explanation

    # Must mention CVE, hostname, decision, tier, CVSS, and recommendation
    assert target_finding.cve_id in exp
    assert target_asset.hostname in exp
    assert assessment.calculation_metadata["aegis_decision"] in exp
    assert assessment.risk_tier.value in exp
    assert f"CVSS score {target_finding.cvss_score:.1f}" in exp
    assert assessment.decision.value in exp



def test_assessment_determinism_excluding_supplied_timestamp(target_finding, target_asset, target_threat):
    """16. Verify that identical inputs with explicit timestamp produce identical outputs."""
    fixed_time = datetime(2026, 9, 4, 15, 0, 0, tzinfo=timezone.utc)

    res1 = evaluate_risk(target_finding, target_asset, target_threat, assessed_at=fixed_time)
    res2 = evaluate_risk(target_finding, target_asset, target_threat, assessed_at=fixed_time)

    assert res1 == res2
    assert res1.model_dump() == res2.model_dump()


def test_asset_id_mismatch_validation(target_finding, target_asset):
    """17. Verify that evaluating a finding against the wrong asset is rejected."""
    mismatched_asset = Asset(
        asset_id="ASSET-OTHER-99",
        hostname="other.aegis.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.NON_CRITICAL,
        criticality=AssetCriticality.LOW,
        network_exposure=NetworkExposure.AIR_GAPPED,
        data_sensitivity=DataSensitivity.PUBLIC,
        environment=EnvironmentType.DEVELOPMENT,
        owner_team="Dev",
        patch_window=PatchWindow(day_of_week="Sunday", start_time_utc="00:00", duration_hours=1.0),
    )

    with pytest.raises(ValueError, match="Asset ID mismatch"):
        evaluate_risk(target_finding, mismatched_asset)
