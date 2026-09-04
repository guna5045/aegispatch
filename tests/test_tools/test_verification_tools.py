"""Tests for Phase 7 verification tools: verify_score_derivation, detect_hallucinated_claims, and validate_plan_constraints."""

import pytest
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    BusinessTier,
    EnvironmentType,
    NetworkExposure,
)
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import (
    ClaimVerificationStatus,
    DetectHallucinatedClaimsInput,
    PlanConstraintItem,
    SecurityClaim,
    SideEffectClass,
    ToolStatus,
    ValidatePlanConstraintsInput,
    VerifyScoreDerivationInput,
)
from src.tools.verification_tools import (
    detect_hallucinated_claims,
    validate_plan_constraints,
    verify_score_derivation,
)


@pytest.fixture
def sample_finding_and_asset():
    from src.schemas.asset import AssetType, CompensatingControl, ControlStatus, DataSensitivity
    f = VulnerabilityFinding(
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
    a = Asset(
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
    return f, a


def test_verify_score_derivation_valid(sample_finding_and_asset):
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    f, a = sample_finding_and_asset
    threat = ThreatEvidence(
        evidence_id="EV-001",
        cve_id=f.cve_id,
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
        threat_source="synthetic_benchmark",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )
    assessment = evaluate_risk(
        finding=f,
        asset=a,
        threat=threat,
    )

    meta = assessment.calculation_metadata
    inp = VerifyScoreDerivationInput(
        finding=f,
        asset=a,
        claimed_base_score=float(meta["base_score"]),
        claimed_threat_score=float(meta["threat_score"]),
        claimed_environmental_score=float(meta["environmental_score"]),
        claimed_control_multiplier=float(meta["control_multiplier"]),
        claimed_ers=assessment.environmental_risk_score,
        claimed_decision=meta.get("aegis_decision", assessment.decision.value),
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
    )
    out = verify_score_derivation(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.COMPUTE_ONLY
    assert out.is_verified is True
    assert len(out.mismatches) == 0


def test_verify_score_derivation_tampered(sample_finding_and_asset):
    """Detects tampered or hallucinated score derivations."""
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    f, a = sample_finding_and_asset
    threat = ThreatEvidence(
        evidence_id="EV-001",
        cve_id=f.cve_id,
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
        threat_source="synthetic_benchmark",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )
    assessment = evaluate_risk(
        finding=f,
        asset=a,
        threat=threat,
    )
    meta = assessment.calculation_metadata

    inp = VerifyScoreDerivationInput(
        finding=f,
        asset=a,
        claimed_base_score=float(meta["base_score"]),
        claimed_threat_score=float(meta["threat_score"]),
        claimed_environmental_score=float(meta["environmental_score"]),
        claimed_control_multiplier=float(meta["control_multiplier"]),
        claimed_ers=25.0,  # Fabricated low score
        claimed_decision="TRACK",  # Fabricated wrong decision band
        is_cisa_kev=True,
        epss_score=0.92,
        public_poc_available=True,
    )
    out = verify_score_derivation(inp)

    assert out.status == ToolStatus.VERIFICATION_FAILED
    assert out.is_verified is False
    assert len(out.mismatches) >= 2
    mismatch_fields = {m.field for m in out.mismatches}
    assert "environmental_risk_score" in mismatch_fields
    assert "decision" in mismatch_fields


def test_detect_hallucinated_claims():
    evidence = {
        "CVE-2023-38545": {
            "is_cisa_kev": True,
            "cvss_score": 9.8,
            "epss_score": 0.92,
        },
        "ASSET-001": {
            "network_exposure": "INTERNET_FACING",
            "criticality": "CRITICAL",
        },
    }
    claims = [
        SecurityClaim(
            claim_id="CLM-01",
            claim_type="CISA_KEV_STATUS",
            statement="CVE-2023-38545 is listed in CISA KEV",
            entity_id="CVE-2023-38545",
            claimed_value=True,
        ),
        SecurityClaim(
            claim_id="CLM-02",
            claim_type="CVSS_SCORE",
            statement="CVE-2023-38545 has CVSS 9.8",
            entity_id="CVE-2023-38545",
            claimed_value=9.8,
        ),
        SecurityClaim(
            claim_id="CLM-03",
            claim_type="CISA_KEV_STATUS",
            statement="CVE-2024-9999 is listed in CISA KEV",  # Entity missing
            entity_id="CVE-2024-9999",
            claimed_value=True,
        ),
        SecurityClaim(
            claim_id="CLM-04",
            claim_type="CVSS_SCORE",
            statement="CVE-2023-38545 has CVSS 4.0",  # Value conflicts
            entity_id="CVE-2023-38545",
            claimed_value=4.0,
        ),
    ]

    inp = DetectHallucinatedClaimsInput(claims=claims, evidence_records=evidence)
    out = detect_hallucinated_claims(inp)

    assert out.status == ToolStatus.VERIFICATION_FAILED
    assert out.all_claims_supported is False
    assert out.unsupported_count == 2
    assert out.results[0].status == ClaimVerificationStatus.SUPPORTED
    assert out.results[1].status == ClaimVerificationStatus.SUPPORTED
    assert out.results[2].status == ClaimVerificationStatus.UNSUPPORTED
    assert out.results[3].status == ClaimVerificationStatus.UNSUPPORTED


def test_validate_plan_constraints_valid():
    items = [
        PlanConstraintItem(
            finding_id="FINDING-001",
            sequence_order=1,
            estimated_hours=2.5,
            has_rollback_plan=True,
        ),
        PlanConstraintItem(
            finding_id="FINDING-002",
            sequence_order=2,
            estimated_hours=2.5,
            has_rollback_plan=True,
        ),
    ]
    inp = ValidatePlanConstraintsInput(
        plan_id="PLAN-2026-001",
        capacity_limit_hours=16.0,
        items=items,
        known_finding_ids=["FINDING-001", "FINDING-002", "FINDING-003"],
    )
    out = validate_plan_constraints(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.is_valid is True
    assert len(out.violations) == 0
    assert out.total_estimated_hours == 5.0


def test_validate_plan_constraints_capacity_exceeded():
    items = [
        PlanConstraintItem(
            finding_id="FINDING-001",
            sequence_order=1,
            estimated_hours=10.0,
            has_rollback_plan=True,
        ),
        PlanConstraintItem(
            finding_id="FINDING-002",
            sequence_order=2,
            estimated_hours=8.0,
            has_rollback_plan=True,
        ),
    ]
    inp = ValidatePlanConstraintsInput(
        plan_id="PLAN-2026-002",
        capacity_limit_hours=16.0,
        items=items,
        known_finding_ids=["FINDING-001", "FINDING-002"],
    )
    out = validate_plan_constraints(inp)

    assert out.status == ToolStatus.CONSTRAINT_VIOLATION
    assert out.is_valid is False
    assert any(v.rule_name == "CAPACITY_LIMIT_EXCEEDED" for v in out.violations)


def test_validate_plan_constraints_missing_rollback_and_duplicate():
    items = [
        PlanConstraintItem(
            finding_id="FINDING-001",
            sequence_order=1,
            estimated_hours=2.0,
            has_rollback_plan=False,  # Violation: no rollback
        ),
        PlanConstraintItem(
            finding_id="FINDING-001",  # Violation: duplicate
            sequence_order=2,
            estimated_hours=2.0,
            has_rollback_plan=True,
        ),
    ]
    inp = ValidatePlanConstraintsInput(
        plan_id="PLAN-2026-003",
        capacity_limit_hours=16.0,
        items=items,
        known_finding_ids=["FINDING-001"],
    )
    out = validate_plan_constraints(inp)

    assert out.status == ToolStatus.CONSTRAINT_VIOLATION
    assert out.is_valid is False
    rule_names = {v.rule_name for v in out.violations}
    assert "ROLLBACK_PLAN_REQUIRED" in rule_names
    assert "UNIQUE_FINDINGS" in rule_names
