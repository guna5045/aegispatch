"""Comprehensive tests for Aegis Patch Phase 5B: Database Models."""

import pytest
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.database import (
    Asset,
    Base,
    PatchPlan,
    PatchPlanItem,
    PolicyDocument,
    RiskAssessment,
    SecurityControl,
    ThreatIntelligenceObservation,
    VulnerabilityFinding,
    create_db_engine,
    get_session_maker,
    init_db,
    reset_engine,
)


@pytest.fixture(autouse=True)
def clean_engine():
    """Ensure engine cache is cleaned before and after tests."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def db_session():
    """Create an isolated in-memory SQLite database session with full schema."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    # Enable SQLite foreign key constraint enforcement
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()

    Base.metadata.create_all(bind=engine)
    maker = get_session_maker(engine)
    session: Session = maker()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


# --------------------------------------------------------------------------
# 1. Table Registration & Schema Creation Tests
# --------------------------------------------------------------------------

def test_all_expected_tables_registered():
    """Verify that all 8 core application persistence models are registered in Base.metadata."""
    expected_tables = {
        "assets",
        "vulnerability_findings",
        "threat_intelligence_observations",
        "security_controls",
        "risk_assessments",
        "patch_plans",
        "patch_plan_items",
        "policy_documents",
    }
    registered_tables = set(Base.metadata.tables.keys())
    assert expected_tables.issubset(registered_tables), (
        f"Missing tables: {expected_tables - registered_tables}"
    )


def test_init_db_creates_all_tables():
    """Verify init_db() creates all registered tables in a fresh database."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    init_db(engine=engine)

    with engine.connect() as conn:
        result = conn.execute(
            text("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        )
        tables = [row[0] for row in result.fetchall()]

    assert "assets" in tables
    assert "vulnerability_findings" in tables
    assert "threat_intelligence_observations" in tables
    assert "security_controls" in tables
    assert "risk_assessments" in tables
    assert "patch_plans" in tables
    assert "patch_plan_items" in tables
    assert "policy_documents" in tables
    engine.dispose()


# --------------------------------------------------------------------------
# 2. Asset Model Tests
# --------------------------------------------------------------------------

def test_asset_creation_and_retrieval(db_session: Session):
    """Verify an enterprise asset can be inserted and retrieved with context."""
    asset = Asset(
        asset_id="ASSET-001",
        hostname="prod-payments-api.corp.internal",
        asset_type="APPLICATION",
        business_tier="MISSION_CRITICAL",
        criticality="CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="RESTRICTED",
        environment="PRODUCTION",
        description="Production payment gateway handling customer transactions",
        owner_team="SecOps Core",
        patch_window={"day_of_week": "Sunday", "start_time_utc": "02:00", "duration_hours": 4.0},
        asset_metadata={"cloud_provider": "AWS", "region": "us-east-1"},
    )
    db_session.add(asset)
    db_session.commit()

    retrieved = db_session.query(Asset).filter_by(asset_id="ASSET-001").first()
    assert retrieved is not None
    assert retrieved.hostname == "prod-payments-api.corp.internal"
    assert retrieved.criticality == "CRITICAL"
    assert retrieved.patch_window["day_of_week"] == "Sunday"
    assert retrieved.created_at is not None
    assert retrieved.updated_at is not None


def test_asset_uniqueness_constraint(db_session: Session):
    """Verify that duplicate asset_id raises an IntegrityError."""
    asset1 = Asset(
        asset_id="ASSET-DUP",
        hostname="host1.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="DEVELOPMENT",
    )
    asset2 = Asset(
        asset_id="ASSET-DUP",
        hostname="host2.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="DEVELOPMENT",
    )
    db_session.add(asset1)
    db_session.commit()

    db_session.add(asset2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --------------------------------------------------------------------------
# 3. VulnerabilityFinding Model Tests
# --------------------------------------------------------------------------

def test_vulnerability_finding_references_asset(db_session: Session):
    """Verify a finding can be associated with an asset and bidirectional relationship works."""
    asset = Asset(
        asset_id="ASSET-002",
        hostname="db-primary.corp.internal",
        asset_type="DATABASE",
        business_tier="BUSINESS_CRITICAL",
        criticality="HIGH",
        network_exposure="INTERNAL",
        data_sensitivity="CONFIDENTIAL",
        environment="PRODUCTION",
    )
    finding = VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-4863",
        title="Heap buffer overflow in libwebp",
        description="A heap buffer overflow vulnerability in libwebp allows code execution.",
        cvss_score=8.8,
        severity="HIGH",
        affected_package="libwebp",
        installed_version="1.2.0",
        fixed_version="1.3.2",
        asset_id="ASSET-002",
        source="Trivy",
        status="OPEN",
        references_data=[{"url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4863"}],
    )
    db_session.add_all([asset, finding])
    db_session.commit()

    retrieved_finding = db_session.query(VulnerabilityFinding).filter_by(finding_id="FINDING-001").first()
    assert retrieved_finding is not None
    assert retrieved_finding.asset.hostname == "db-primary.corp.internal"
    assert retrieved_finding.cvss_score == 8.8

    # Check parent asset's findings collection
    retrieved_asset = db_session.query(Asset).filter_by(asset_id="ASSET-002").first()
    assert len(retrieved_asset.findings) == 1
    assert retrieved_asset.findings[0].cve_id == "CVE-2023-4863"


def test_multiple_findings_on_single_asset(db_session: Session):
    """Verify multiple vulnerability findings can belong to one asset."""
    asset = Asset(
        asset_id="ASSET-MULTI",
        hostname="web-cluster-01.corp.internal",
        asset_type="SERVER",
        business_tier="STANDARD",
        criticality="MEDIUM",
        network_exposure="DMZ",
        data_sensitivity="INTERNAL",
        environment="STAGING",
    )
    f1 = VulnerabilityFinding(
        finding_id="FINDING-M1",
        cve_id="CVE-2021-44228",
        title="Log4Shell RCE",
        description="Remote code execution in Apache Log4j",
        cvss_score=10.0,
        severity="CRITICAL",
        affected_package="log4j-core",
        installed_version="2.14.1",
        asset_id="ASSET-MULTI",
        source="ScannerA",
    )
    f2 = VulnerabilityFinding(
        finding_id="FINDING-M2",
        cve_id="CVE-2022-22965",
        title="Spring4Shell RCE",
        description="Remote code execution in Spring Framework",
        cvss_score=9.8,
        severity="CRITICAL",
        affected_package="spring-beans",
        installed_version="5.3.17",
        asset_id="ASSET-MULTI",
        source="ScannerA",
    )
    db_session.add_all([asset, f1, f2])
    db_session.commit()

    retrieved = db_session.query(Asset).filter_by(asset_id="ASSET-MULTI").first()
    assert len(retrieved.findings) == 2


def test_finding_uniqueness_constraint(db_session: Session):
    """Verify duplicate finding_id raises an IntegrityError."""
    asset = Asset(
        asset_id="ASSET-U",
        hostname="host-u.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="DEVELOPMENT",
    )
    f1 = VulnerabilityFinding(
        finding_id="FINDING-DUP",
        cve_id="CVE-2023-1111",
        title="Test Vuln 1",
        description="Desc 1",
        cvss_score=5.0,
        severity="MEDIUM",
        affected_package="pkg",
        installed_version="1.0",
        asset_id="ASSET-U",
        source="Test",
    )
    f2 = VulnerabilityFinding(
        finding_id="FINDING-DUP",
        cve_id="CVE-2023-2222",
        title="Test Vuln 2",
        description="Desc 2",
        cvss_score=6.0,
        severity="MEDIUM",
        affected_package="pkg2",
        installed_version="2.0",
        asset_id="ASSET-U",
        source="Test",
    )
    db_session.add_all([asset, f1])
    db_session.commit()

    db_session.add(f2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_cvss_range_constraint(db_session: Session):
    """Verify CVSS score outside 0.0-10.0 raises an error."""
    asset = Asset(
        asset_id="ASSET-CVSS",
        hostname="host-cvss.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    bad_finding = VulnerabilityFinding(
        finding_id="FINDING-BAD-CVSS",
        cve_id="CVE-2023-9999",
        title="Invalid CVSS",
        description="Invalid score test",
        cvss_score=11.5,  # Exceeds max 10.0
        severity="CRITICAL",
        affected_package="pkg",
        installed_version="1.0",
        asset_id="ASSET-CVSS",
        source="Test",
    )
    db_session.add_all([asset, bad_finding])
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --------------------------------------------------------------------------
# 4. ThreatIntelligenceObservation Tests
# --------------------------------------------------------------------------

def test_threat_observation_creation_and_multiple_per_cve(db_session: Session):
    """Verify threat intelligence observations can be stored and multiple observations exist for one CVE."""
    t1 = ThreatIntelligenceObservation(
        observation_id="THREAT-001",
        cve_id="CVE-2023-4863",
        source="CISA KEV",
        is_cisa_kev=True,
        epss_score=0.92,
        epss_percentile=0.98,
        exploit_available=True,
        exploit_maturity="WEAPONIZED",
        confidence="HIGH",
        source_reference="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    )
    t2 = ThreatIntelligenceObservation(
        observation_id="THREAT-002",
        cve_id="CVE-2023-4863",
        source="FIRST EPSS",
        is_cisa_kev=False,
        epss_score=0.935,
        epss_percentile=0.985,
        exploit_available=True,
        exploit_maturity="POC",
        confidence="HIGH",
    )
    db_session.add_all([t1, t2])
    db_session.commit()

    records = db_session.query(ThreatIntelligenceObservation).filter_by(cve_id="CVE-2023-4863").all()
    assert len(records) == 2
    sources = {r.source for r in records}
    assert "CISA KEV" in sources
    assert "FIRST EPSS" in sources


def test_threat_epss_range_constraint(db_session: Session):
    """Verify EPSS score outside 0.0-1.0 raises an error."""
    bad_threat = ThreatIntelligenceObservation(
        cve_id="CVE-2024-0001",
        source="Bad Source",
        epss_score=1.5,  # Exceeds max 1.0
    )
    db_session.add(bad_threat)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --------------------------------------------------------------------------
# 5. SecurityControl Model Tests
# --------------------------------------------------------------------------

def test_multiple_controls_on_asset(db_session: Session):
    """Verify multiple security and compensating controls can be attached to an asset."""
    asset = Asset(
        asset_id="ASSET-SEC",
        hostname="gateway.corp.internal",
        asset_type="NETWORK_DEVICE",
        business_tier="BUSINESS_CRITICAL",
        criticality="HIGH",
        network_exposure="INTERNET_FACING",
        data_sensitivity="CONFIDENTIAL",
        environment="PRODUCTION",
    )
    c1 = SecurityControl(
        control_id="CTRL-WAF",
        asset_id="ASSET-SEC",
        name="Cloudflare Edge WAF",
        control_category="NETWORK",
        description="Inspects and filters incoming HTTP/S traffic against OWASP Top 10",
        status="ACTIVE",
        active=True,
        effectiveness_discount=0.20,
    )
    c2 = SecurityControl(
        control_id="CTRL-EDR",
        asset_id="ASSET-SEC",
        name="CrowdStrike Falcon Sensor",
        control_category="ENDPOINT",
        description="Endpoint detection and response agent with behavioral blocking",
        status="ACTIVE",
        active=True,
        effectiveness_discount=0.15,
    )
    db_session.add_all([asset, c1, c2])
    db_session.commit()

    retrieved = db_session.query(Asset).filter_by(asset_id="ASSET-SEC").first()
    assert len(retrieved.controls) == 2
    control_names = [c.name for c in retrieved.controls]
    assert "Cloudflare Edge WAF" in control_names
    assert "CrowdStrike Falcon Sensor" in control_names


# --------------------------------------------------------------------------
# 6. RiskAssessment Model Tests
# --------------------------------------------------------------------------

def test_risk_assessment_audit_traceability(db_session: Session):
    """Verify risk assessments preserve complete B, T, E, R, M_control, ERS mathematical breakdown."""
    asset = Asset(
        asset_id="ASSET-R",
        hostname="risk-target.local",
        asset_type="SERVER",
        business_tier="MISSION_CRITICAL",
        criticality="CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="RESTRICTED",
        environment="PRODUCTION",
    )
    finding = VulnerabilityFinding(
        finding_id="FINDING-R1",
        cve_id="CVE-2023-4863",
        title="WebP Overflow",
        description="Remote execution",
        cvss_score=8.8,
        severity="HIGH",
        affected_package="libwebp",
        installed_version="1.2.0",
        asset_id="ASSET-R",
        source="Scanner",
    )
    assessment = RiskAssessment(
        assessment_id="ASSESS-001",
        finding_id="FINDING-R1",
        cve_id="CVE-2023-4863",
        asset_id="ASSET-R",
        base_score=88.0,
        threat_score=85.0,
        environmental_score=90.0,
        raw_risk_score=87.7,
        control_multiplier=0.80,
        environmental_risk_score=70.16,
        risk_tier="CRITICAL",
        decision="ACT",
        remediation_decision="IMMEDIATE_PATCH",
        explanation="Elevated to ACT due to confirmed active exploitation in the wild and internet exposure.",
        supporting_evidence=["CISA KEV listed", "Internet-facing production host"],
        calculation_metadata={"engine": "DeterministicPhase3", "version": "1.0.0"},
        engine_version="1.0.0",
    )
    db_session.add_all([asset, finding, assessment])
    db_session.commit()

    retrieved = db_session.query(RiskAssessment).filter_by(assessment_id="ASSESS-001").first()
    assert retrieved is not None
    assert retrieved.environmental_risk_score == 70.16
    assert retrieved.base_score == 88.0
    assert retrieved.threat_score == 85.0
    assert retrieved.environmental_score == 90.0
    assert retrieved.control_multiplier == 0.80
    assert retrieved.decision == "ACT"
    assert retrieved.finding.title == "WebP Overflow"


def test_multiple_historical_risk_assessments_per_finding(db_session: Session):
    """Verify that a finding can have multiple historical risk assessments (finding_id is non-unique)."""
    asset = Asset(
        asset_id="ASSET-HIST",
        hostname="hist-host.local",
        asset_type="SERVER",
        business_tier="BUSINESS_CRITICAL",
        criticality="HIGH",
        network_exposure="INTERNAL",
        data_sensitivity="CONFIDENTIAL",
        environment="PRODUCTION",
    )
    finding = VulnerabilityFinding(
        finding_id="FINDING-HIST",
        cve_id="CVE-2023-1234",
        title="Test Vuln",
        description="Test",
        cvss_score=7.0,
        severity="HIGH",
        affected_package="pkg",
        installed_version="1.0",
        asset_id="ASSET-HIST",
        source="Scanner",
    )
    # Initial assessment: no controls active -> ERS 65.0
    a1 = RiskAssessment(
        assessment_id="ASSESS-HIST-1",
        finding_id="FINDING-HIST",
        cve_id="CVE-2023-1234",
        asset_id="ASSET-HIST",
        base_score=70.0,
        threat_score=60.0,
        environmental_score=65.0,
        raw_risk_score=65.0,
        control_multiplier=1.00,
        environmental_risk_score=65.0,
        risk_tier="HIGH",
        decision="ATTEND",
        explanation="Initial triage without controls",
    )
    # Subsequent assessment: compensating control deployed -> ERS 45.5
    a2 = RiskAssessment(
        assessment_id="ASSESS-HIST-2",
        finding_id="FINDING-HIST",
        cve_id="CVE-2023-1234",
        asset_id="ASSET-HIST",
        base_score=70.0,
        threat_score=60.0,
        environmental_score=65.0,
        raw_risk_score=65.0,
        control_multiplier=0.70,
        environmental_risk_score=45.5,
        risk_tier="MEDIUM",
        decision="PLAN",
        explanation="Re-evaluated with WAF control active",
    )
    db_session.add_all([asset, finding, a1, a2])
    db_session.commit()

    records = db_session.query(RiskAssessment).filter_by(finding_id="FINDING-HIST").all()
    assert len(records) == 2
    assert {r.decision for r in records} == {"ATTEND", "PLAN"}


# --------------------------------------------------------------------------
# 7. PatchPlan & PatchPlanItem Tests
# --------------------------------------------------------------------------

def test_patch_plan_with_items_and_ordering(db_session: Session):
    """Verify PatchPlan contains ordered PatchPlanItems with capacity constraints."""
    asset = Asset(
        asset_id="ASSET-P",
        hostname="plan-target.local",
        asset_type="SERVER",
        business_tier="MISSION_CRITICAL",
        criticality="CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="RESTRICTED",
        environment="PRODUCTION",
    )
    f1 = VulnerabilityFinding(
        finding_id="FINDING-P1",
        cve_id="CVE-2023-0001",
        title="Vulnerability 1",
        description="Desc 1",
        cvss_score=9.0,
        severity="CRITICAL",
        affected_package="pkg-a",
        installed_version="1.0",
        asset_id="ASSET-P",
        source="Scanner",
    )
    f2 = VulnerabilityFinding(
        finding_id="FINDING-P2",
        cve_id="CVE-2023-0002",
        title="Vulnerability 2",
        description="Desc 2",
        cvss_score=7.5,
        severity="HIGH",
        affected_package="pkg-b",
        installed_version="2.0",
        asset_id="ASSET-P",
        source="Scanner",
    )
    plan = PatchPlan(
        plan_id="PLAN-2026-001",
        title="Sprint 14 Emergency Production Remediation",
        status="APPROVED",
        capacity_hours=16.0,
        total_estimated_hours=6.5,
        expected_risk_reduction=152.4,
        notes="High-priority internet-facing CVEs scheduled within weekly window.",
    )
    item1 = PatchPlanItem(
        patch_plan_id="PLAN-2026-001",
        finding_id="FINDING-P1",
        sequence_order=1,
        estimated_hours=4.0,
        expected_risk_reduction=85.2,
        priority_decision="ACT",
        remediation_action="Upgrade pkg-a to version 1.1 with regression test pass",
        rollback_plan={"procedure_description": "Restore container image snapshot", "backup_required": True, "estimated_rollback_minutes": 15},
        status="SCHEDULED",
    )
    item2 = PatchPlanItem(
        patch_plan_id="PLAN-2026-001",
        finding_id="FINDING-P2",
        sequence_order=2,
        estimated_hours=2.5,
        expected_risk_reduction=67.2,
        priority_decision="ATTEND",
        remediation_action="Apply vendor patch for pkg-b",
        status="SCHEDULED",
    )
    db_session.add_all([asset, f1, f2, plan, item1, item2])
    db_session.commit()

    retrieved_plan = db_session.query(PatchPlan).filter_by(plan_id="PLAN-2026-001").first()
    assert retrieved_plan is not None
    assert len(retrieved_plan.items) == 2
    # Check that items are ordered by sequence_order
    assert retrieved_plan.items[0].sequence_order == 1
    assert retrieved_plan.items[0].finding_id == "FINDING-P1"
    assert retrieved_plan.items[1].sequence_order == 2
    assert retrieved_plan.items[1].finding_id == "FINDING-P2"


def test_patch_plan_item_unique_within_plan(db_session: Session):
    """Verify duplicate inclusion of the same finding within the same plan is rejected."""
    asset = Asset(
        asset_id="ASSET-P-DUP",
        hostname="pdup.local",
        asset_type="SERVER",
        business_tier="STANDARD",
        criticality="MEDIUM",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    finding = VulnerabilityFinding(
        finding_id="FINDING-PDUP",
        cve_id="CVE-2023-5555",
        title="Test",
        description="Test",
        cvss_score=5.0,
        severity="MEDIUM",
        affected_package="p",
        installed_version="1",
        asset_id="ASSET-P-DUP",
        source="Scanner",
    )
    plan = PatchPlan(
        plan_id="PLAN-DUP",
        title="Plan Dup Test",
        capacity_hours=10.0,
        total_estimated_hours=4.0,
        expected_risk_reduction=40.0,
    )
    item1 = PatchPlanItem(
        patch_plan_id="PLAN-DUP",
        finding_id="FINDING-PDUP",
        sequence_order=1,
        estimated_hours=2.0,
        expected_risk_reduction=20.0,
        priority_decision="PLAN",
        remediation_action="Action 1",
    )
    item2 = PatchPlanItem(
        patch_plan_id="PLAN-DUP",
        finding_id="FINDING-PDUP",  # Same finding in same plan
        sequence_order=2,
        estimated_hours=2.0,
        expected_risk_reduction=20.0,
        priority_decision="PLAN",
        remediation_action="Action 2",
    )
    db_session.add_all([asset, finding, plan, item1])
    db_session.commit()

    db_session.add(item2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# --------------------------------------------------------------------------
# 8. PolicyDocument Model Tests
# --------------------------------------------------------------------------

def test_policy_document_creation_and_retrieval(db_session: Session):
    """Verify organizational security policy metadata can be persisted and queried."""
    policy = PolicyDocument(
        policy_id="POL-SEC-04",
        title="Enterprise Vulnerability Remediation and Patch Management Policy",
        policy_type="VULNERABILITY_MANAGEMENT",
        version="2.4",
        status="ACTIVE",
        effective_date=datetime(2026, 1, 1, tzinfo=timezone.utc),
        source_path="data/policies/POL-SEC-04-patching.md",
        content_hash="sha256:abc123def456",
        policy_metadata={"governing_framework": "PCI-DSS v4.0", "sla_critical_hours": 48},
    )
    db_session.add(policy)
    db_session.commit()

    retrieved = db_session.query(PolicyDocument).filter_by(policy_id="POL-SEC-04").first()
    assert retrieved is not None
    assert retrieved.title == "Enterprise Vulnerability Remediation and Patch Management Policy"
    assert retrieved.version == "2.4"
    assert retrieved.policy_metadata["sla_critical_hours"] == 48


def test_policy_document_uniqueness(db_session: Session):
    """Verify duplicate policy_id raises IntegrityError."""
    p1 = PolicyDocument(
        policy_id="POL-DUP",
        title="Policy 1",
        policy_type="SECURITY",
        version="1.0",
    )
    p2 = PolicyDocument(
        policy_id="POL-DUP",
        title="Policy 2",
        policy_type="SECURITY",
        version="2.0",
    )
    db_session.add(p1)
    db_session.commit()

    db_session.add(p2)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()
