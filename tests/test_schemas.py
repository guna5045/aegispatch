"""Comprehensive tests for AegisPatch foundational Pydantic data schemas."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.schemas import (
    AegisPatchState,
    ApprovalState,
    Asset,
    AssetContext,
    AssetCriticality,
    AssetType,
    AuditEvent,
    BusinessTier,
    CheckType,
    CompensatingControl,
    ControlAdjustment,
    ControlStatus,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
    PatchAction,
    PatchCandidate,
    PatchPlan,
    PatchWindow,
    PolicyCitation,
    RemediationDecision,
    RiskAssessment,
    RiskTier,
    RollbackPlan,
    ThreatConfidence,
    ThreatEvidence,
    VerificationCheck,
    VerificationResult,
    VerificationStatus,
    VulnerabilityFinding,
    VulnerabilityReference,
    VulnerabilitySeverity,
    WorkflowStatus,
)


def sample_vulnerability() -> VulnerabilityFinding:
    return VulnerabilityFinding(
        finding_id="VULN-001",
        cve_id="CVE-2024-38077",
        title="Remote Desktop Licensing Service RCE",
        description="A remote code execution vulnerability exists in Windows Remote Desktop Licensing Service.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="librdlsvc",
        installed_version="1.0.4",
        fixed_version="1.0.5",
        asset_id="SRV-PROD-01",
        source="Trivy-Scanner",
        references=[
            VulnerabilityReference(
                url="https://nvd.nist.gov/vuln/detail/CVE-2024-38077",
                source="NVD",
                description="Official NVD record",
            )
        ],
        raw_evidence={"raw_rule_id": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    )


def sample_asset() -> Asset:
    return Asset(
        asset_id="SRV-PROD-01",
        hostname="prod-auth-node-01.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.MISSION_CRITICAL,
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        environment=EnvironmentType.PRODUCTION,
        owner_team="Identity & Access",
        patch_window=PatchWindow(
            day_of_week="Sunday",
            start_time_utc="03:00",
            duration_hours=4.0,
            timezone="UTC",
        ),
        compensating_controls=[
            CompensatingControl(
                control_id="CTL-WAF-01",
                name="Cloudflare Enterprise WAF",
                description="Virtual patching rule active for known CVE payloads",
                status=ControlStatus.ACTIVE,
            )
        ],
        metadata={"cloud_provider": "AWS", "region": "us-east-1"},
    )


def sample_threat() -> ThreatEvidence:
    now = datetime.now(timezone.utc)
    return ThreatEvidence(
        evidence_id="THREAT-001",
        cve_id="CVE-2024-38077",
        is_cisa_kev=True,
        cisa_kev_date_added=now,
        epss_score=0.885,
        epss_percentile=0.972,
        public_poc_available=True,
        threat_source="CISA KEV & FIRST EPSS",
        retrieved_at=now,
        confidence=ThreatConfidence.HIGH,
        reference_urls=["https://www.cisa.gov/known-exploited-vulnerabilities-catalog"],
        notes="Active exploitation detected in wild targeting unauthenticated instances.",
    )


def sample_context() -> AssetContext:
    return AssetContext(
        context_id="CTX-001",
        asset_id="SRV-PROD-01",
        finding_id="VULN-001",
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        business_tier=BusinessTier.MISSION_CRITICAL,
        environment=EnvironmentType.PRODUCTION,
        applicable_controls=[
            CompensatingControl(
                control_id="CTL-WAF-01",
                name="Cloudflare Enterprise WAF",
                description="Virtual patching rule active for known CVE payloads",
                status=ControlStatus.ACTIVE,
            )
        ],
        policy_citations=[
            PolicyCitation(
                policy_id="SEC-POL-04",
                policy_name="Enterprise Vulnerability Management Policy",
                section="Section 4.1",
                requirement_summary="Internet-facing critical CVEs with active exploits must be remediated within 48 hours.",
                reference_uri="policies/sec_pol_04.md",
            )
        ],
        context_summary="High exposure internet-facing asset processing restricted auth credentials.",
    )


# ==============================================================================
# 1. Vulnerability Schema Tests
# ==============================================================================

def test_valid_vulnerability_creation():
    vuln = sample_vulnerability()
    assert vuln.finding_id == "VULN-001"
    assert vuln.cve_id == "CVE-2024-38077"
    assert vuln.cvss_score == 9.8
    assert vuln.severity == VulnerabilitySeverity.CRITICAL
    assert len(vuln.references) == 1
    assert vuln.references[0].source == "NVD"


def test_invalid_cvss_score_rejection():
    # Score above 10.0
    with pytest.raises(ValidationError) as exc_info:
        VulnerabilityFinding(
            finding_id="VULN-002",
            cve_id="CVE-2024-38077",
            title="Test",
            description="Test",
            cvss_score=10.5,
            severity=VulnerabilitySeverity.HIGH,
            affected_package="test",
            installed_version="1.0",
            asset_id="A1",
            source="test",
        )
    assert "cvss_score" in str(exc_info.value)

    # Score below 0.0
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            finding_id="VULN-002",
            cve_id="CVE-2024-38077",
            title="Test",
            description="Test",
            cvss_score=-1.0,
            severity=VulnerabilitySeverity.LOW,
            affected_package="test",
            installed_version="1.0",
            asset_id="A1",
            source="test",
        )


def test_invalid_cve_pattern_rejection():
    # Invalid CVE ID pattern
    with pytest.raises(ValidationError) as exc_info:
        VulnerabilityFinding(
            finding_id="VULN-003",
            cve_id="INVALID-CVE-2024",
            title="Test",
            description="Test",
            cvss_score=7.5,
            severity=VulnerabilitySeverity.HIGH,
            affected_package="test",
            installed_version="1.0",
            asset_id="A1",
            source="test",
        )
    assert "cve_id" in str(exc_info.value)


def test_invalid_severity_enum_rejection():
    with pytest.raises(ValidationError):
        VulnerabilityFinding(
            finding_id="VULN-004",
            cve_id="CVE-2024-1234",
            title="Test",
            description="Test",
            cvss_score=5.0,
            severity="SUPER_CRITICAL",  # Invalid enum value
            affected_package="test",
            installed_version="1.0",
            asset_id="A1",
            source="test",
        )


# ==============================================================================
# 2. Asset Schema Tests
# ==============================================================================

def test_valid_asset_creation():
    asset = sample_asset()
    assert asset.asset_id == "SRV-PROD-01"
    assert asset.asset_type == AssetType.SERVER
    assert asset.criticality == AssetCriticality.CRITICAL
    assert asset.network_exposure == NetworkExposure.INTERNET_FACING
    assert asset.patch_window is not None
    assert asset.patch_window.start_time_utc == "03:00"
    assert len(asset.compensating_controls) == 1


def test_invalid_asset_enum_values():
    with pytest.raises(ValidationError):
        Asset(
            asset_id="A-01",
            hostname="host1",
            asset_type="MAINFRAME_UNKNOWN",  # Invalid
            business_tier=BusinessTier.MISSION_CRITICAL,
            criticality=AssetCriticality.HIGH,
            network_exposure=NetworkExposure.INTERNAL,
            data_sensitivity=DataSensitivity.INTERNAL,
            environment=EnvironmentType.PRODUCTION,
            owner_team="Security",
        )


def test_invalid_patch_window_format():
    with pytest.raises(ValidationError):
        PatchWindow(
            day_of_week="Sunday",
            start_time_utc="25:99",  # Invalid 24h format
            duration_hours=2.0,
        )


# ==============================================================================
# 3. Threat Evidence Tests
# ==============================================================================

def test_valid_threat_evidence():
    threat = sample_threat()
    assert threat.is_cisa_kev is True
    assert threat.epss_score == 0.885
    assert threat.public_poc_available is True
    assert threat.retrieved_at.tzinfo is not None


def test_epss_score_valid_values_and_bounds():
    now = datetime.now(timezone.utc)
    base_kwargs = {
        "evidence_id": "TH-01",
        "cve_id": "CVE-2024-1234",
        "threat_source": "EPSS",
        "retrieved_at": now,
    }

    # 1. A valid numeric EPSS score is accepted
    threat_valid = ThreatEvidence(**base_kwargs, epss_score=0.45)
    assert threat_valid.epss_score == 0.45

    # 2. EPSS score 0.0 is accepted
    threat_zero = ThreatEvidence(**base_kwargs, epss_score=0.0)
    assert threat_zero.epss_score == 0.0

    # 3. EPSS score 1.0 is accepted
    threat_one = ThreatEvidence(**base_kwargs, epss_score=1.0)
    assert threat_one.epss_score == 1.0

    # 4. None is accepted (explicit None and omitted default)
    threat_none = ThreatEvidence(**base_kwargs, epss_score=None)
    assert threat_none.epss_score is None

    threat_omitted = ThreatEvidence(**base_kwargs)
    assert threat_omitted.epss_score is None

    # 5. A value below 0.0 is rejected
    with pytest.raises(ValidationError) as exc_below:
        ThreatEvidence(**base_kwargs, epss_score=-0.01)
    assert "epss_score" in str(exc_below.value)

    # 6. A value above 1.0 is rejected
    with pytest.raises(ValidationError) as exc_above:
        ThreatEvidence(**base_kwargs, epss_score=1.01)
    assert "epss_score" in str(exc_above.value)


def test_naive_datetime_rejection_for_threat():
    naive_now = datetime.now()  # timezone-naive
    with pytest.raises(ValidationError):
        ThreatEvidence(
            evidence_id="TH-02",
            cve_id="CVE-2024-1234",
            epss_score=0.5,
            threat_source="EPSS",
            retrieved_at=naive_now,
        )


# ==============================================================================
# 4. Environmental Context Tests
# ==============================================================================

def test_valid_asset_context():
    ctx = sample_context()
    assert ctx.context_id == "CTX-001"
    assert len(ctx.policy_citations) == 1
    assert ctx.policy_citations[0].policy_id == "SEC-POL-04"
    assert ctx.criticality == AssetCriticality.CRITICAL


# ==============================================================================
# 5. Risk Assessment Schema Tests
# ==============================================================================

def test_valid_risk_assessment():
    now = datetime.now(timezone.utc)
    assessment = RiskAssessment(
        assessment_id="RSK-001",
        finding_id="VULN-001",
        cve_id="CVE-2024-38077",
        asset_id="SRV-PROD-01",
        cvss_score=9.8,
        cvss_contribution=35.0,
        threat_evidence=sample_threat(),
        environmental_context=sample_context(),
        control_adjustments=[
            ControlAdjustment(
                control_id="CTL-WAF-01",
                name="WAF Virtual Patch",
                adjustment_factor=-10.0,
                description="Active WAF mitigation dampens immediate exploitability",
            )
        ],
        environmental_risk_score=92.5,
        risk_tier=RiskTier.CRITICAL,
        decision=RemediationDecision.IMMEDIATE_PATCH,
        explanation="Critical RCE in internet-facing production asset listed on CISA KEV.",
        supporting_evidence=[
            "CISA KEV active exploitation confirmed",
            "Asset is internet-facing and hosts restricted identity tokens",
        ],
        calculation_metadata={"engine": "aegis_deterministic_v1"},
        assessed_at=now,
    )
    assert assessment.environmental_risk_score == 92.5
    assert assessment.risk_tier == RiskTier.CRITICAL
    assert assessment.decision == RemediationDecision.IMMEDIATE_PATCH
    assert assessment.assessed_at.tzinfo is not None


def test_invalid_risk_score_bounds():
    now = datetime.now(timezone.utc)
    with pytest.raises(ValidationError):
        RiskAssessment(
            assessment_id="RSK-002",
            finding_id="VULN-001",
            cve_id="CVE-2024-38077",
            asset_id="SRV-PROD-01",
            cvss_score=9.8,
            cvss_contribution=35.0,
            threat_evidence=sample_threat(),
            environmental_context=sample_context(),
            environmental_risk_score=105.0,  # Exceeds max 100.0
            risk_tier=RiskTier.CRITICAL,
            decision=RemediationDecision.IMMEDIATE_PATCH,
            explanation="Invalid score test",
            assessed_at=now,
        )


# ==============================================================================
# 6. Patch Plan Schema Tests
# ==============================================================================

def test_valid_patch_plan():
    now = datetime.now(timezone.utc)
    candidate = PatchCandidate(
        candidate_id="CAND-001",
        finding_id="VULN-001",
        cve_id="CVE-2024-38077",
        asset_id="SRV-PROD-01",
        risk_tier=RiskTier.CRITICAL,
        expected_risk_reduction=65.0,
        estimated_cost_hours=2.5,
    )

    action = PatchAction(
        action_id="ACT-001",
        candidate_id="CAND-001",
        finding_id="VULN-001",
        asset_id="SRV-PROD-01",
        target_package="librdlsvc",
        installed_version="1.0.4",
        target_version="1.0.5",
        sequence_order=1,
        dependencies=[],
        rollback_plan=RollbackPlan(
            procedure_description="Roll back VM snapshot and re-bind network adapter",
            backup_required=True,
            estimated_rollback_minutes=15,
        ),
        approval_state=ApprovalState.PENDING,
    )

    plan = PatchPlan(
        plan_id="PLAN-2026-09-04-01",
        actions=[action],
        candidates=[candidate],
        total_expected_risk_reduction=65.0,
        total_estimated_cost_hours=2.5,
        capacity_limit_hours=8.0,
        approval_status=ApprovalState.PENDING,
        created_at=now,
        notes="Urgent scheduled patch for upcoming maintenance window.",
    )

    assert plan.plan_id == "PLAN-2026-09-04-01"
    assert len(plan.actions) == 1
    assert plan.actions[0].rollback_plan.estimated_rollback_minutes == 15
    assert plan.approval_status == ApprovalState.PENDING


# ==============================================================================
# 7. Verification Schema Tests
# ==============================================================================

def test_valid_verification_result():
    now = datetime.now(timezone.utc)
    check1 = VerificationCheck(
        check_id="CHK-01",
        check_name="Verify CISA KEV Citation",
        check_type=CheckType.EVIDENCE_VALIDATION,
        passed=True,
        message="CVE-2024-38077 verified against active CISA KEV records",
    )
    check2 = VerificationCheck(
        check_id="CHK-02",
        check_name="Verify Capacity Constraint",
        check_type=CheckType.CONSTRAINT_VALIDATION,
        passed=True,
        message="Planned 2.5 hours does not exceed 8.0 hour capacity limit",
    )

    verification = VerificationResult(
        verification_id="VRF-001",
        status=VerificationStatus.PASSED,
        checks_performed=[check1, check2],
        failed_checks=[],
        warnings=[],
        evidence_citations_valid=True,
        calculations_valid=True,
        constraints_valid=True,
        factual_support_valid=True,
        requires_replanning=False,
        summary="All deterministic and policy checks satisfied.",
        verified_at=now,
    )

    assert verification.status == VerificationStatus.PASSED
    assert len(verification.checks_performed) == 2
    assert verification.requires_replanning is False


# ==============================================================================
# 8. Shared Workflow State Tests
# ==============================================================================

def test_valid_shared_state():
    now = datetime.now(timezone.utc)
    state = AegisPatchState(
        run_id="RUN-9001",
        workflow_status=WorkflowStatus.IN_PROGRESS,
        input_vulnerabilities=[sample_vulnerability()],
        normalized_vulnerabilities=[sample_vulnerability()],
        asset_contexts={"VULN-001": sample_context()},
        threat_evidence={"CVE-2024-38077": sample_threat()},
        current_agent="RiskPrioritizationAgent",
        completed_agents=["IngestionAgent", "ContextEnrichmentAgent", "ThreatIntelAgent"],
        audit_trail=[
            AuditEvent(
                event_id="EVT-01",
                agent_name="IngestionAgent",
                event_type="NORMALIZATION_COMPLETE",
                message="Normalized 1 vulnerability finding.",
                details={"finding_count": "1"},
                timestamp=now,
            )
        ],
        created_at=now,
        updated_at=now,
    )

    assert state.run_id == "RUN-9001"
    assert state.workflow_status == WorkflowStatus.IN_PROGRESS
    assert len(state.completed_agents) == 3
    assert "CVE-2024-38077" in state.threat_evidence


# ==============================================================================
# 9. JSON Serialization / Deserialization Round-Trip Test
# ==============================================================================

def test_json_roundtrip_all_models():
    now = datetime.now(timezone.utc)

    # Test Vulnerability
    vuln = sample_vulnerability()
    json_data = vuln.model_dump_json()
    reconstructed_vuln = VulnerabilityFinding.model_validate_json(json_data)
    assert vuln == reconstructed_vuln

    # Test Asset
    asset = sample_asset()
    asset_json = asset.model_dump_json()
    reconstructed_asset = Asset.model_validate_json(asset_json)
    assert asset == reconstructed_asset

    # Test State
    state = AegisPatchState(
        run_id="RUN-ROUNDTRIP",
        workflow_status=WorkflowStatus.NOT_STARTED,
        input_vulnerabilities=[vuln],
        created_at=now,
        updated_at=now,
    )
    state_json = state.model_dump_json()
    reconstructed_state = AegisPatchState.model_validate_json(state_json)
    assert state == reconstructed_state


# ==============================================================================
# 10. Required Fields Validation Tests
# ==============================================================================

def test_missing_required_fields():
    # Missing required finding_id
    with pytest.raises(ValidationError) as exc_info:
        VulnerabilityFinding(
            cve_id="CVE-2024-1234",
            title="Title",
            description="Desc",
            cvss_score=5.0,
            severity=VulnerabilitySeverity.MEDIUM,
            affected_package="pkg",
            installed_version="1.0",
            asset_id="A1",
            source="src",
        )
    assert "finding_id" in str(exc_info.value)
