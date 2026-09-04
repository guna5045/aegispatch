"""Comprehensive unit and integration tests for Aegis Patch Phase 5C: Repositories."""

import pytest
from datetime import datetime, timezone
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from src.database import (
    Asset,
    AssetRepository,
    Base,
    ControlRepository,
    PatchPlan,
    PatchPlanItem,
    PatchPlanRepository,
    PolicyDocument,
    PolicyRepository,
    RiskAssessment,
    RiskAssessmentRepository,
    SecurityControl,
    ThreatIntelligenceObservation,
    ThreatIntelligenceRepository,
    VulnerabilityFinding,
    VulnerabilityRepository,
    create_db_engine,
    get_session_maker,
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
    """Create an isolated in-memory SQLite database session with full schema and foreign keys enabled."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
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
# 1. AssetRepository Tests
# --------------------------------------------------------------------------

def test_asset_repo_create_and_get(db_session: Session):
    """Verify AssetRepository creates and retrieves an asset by id, asset_id, and hostname."""
    repo = AssetRepository(db_session)
    asset = Asset(
        asset_id="ASSET-001",
        hostname="prod-payments-api.corp.internal",
        asset_type="APPLICATION",
        business_tier="MISSION_CRITICAL",
        criticality="CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="RESTRICTED",
        environment="PRODUCTION",
        description="Production payment gateway",
        owner_team="SecOps Core",
    )
    created = repo.create(asset)
    assert created.id is not None
    assert created.asset_id == "ASSET-001"

    # Fetch by asset_id
    by_asset_id = repo.get_by_asset_id("ASSET-001")
    assert by_asset_id is not None
    assert by_asset_id.hostname == "prod-payments-api.corp.internal"

    # Fetch by hostname
    by_hostname = repo.get_by_hostname("prod-payments-api.corp.internal")
    assert by_hostname is not None
    assert by_hostname.asset_id == "ASSET-001"

    # Fetch by primary key ID
    by_pk = repo.get_by_id(created.id)
    assert by_pk is not None
    assert by_pk.asset_id == "ASSET-001"


def test_asset_repo_list_and_filters(db_session: Session):
    """Verify AssetRepository lists assets with deterministic ordering and environment/criticality filters."""
    repo = AssetRepository(db_session)
    a1 = Asset(
        asset_id="ASSET-002",
        hostname="staging-app.corp.internal",
        asset_type="SERVER",
        business_tier="STANDARD",
        criticality="MEDIUM",
        network_exposure="INTERNAL",
        data_sensitivity="INTERNAL",
        environment="STAGING",
    )
    a2 = Asset(
        asset_id="ASSET-001",
        hostname="prod-db.corp.internal",
        asset_type="DATABASE",
        business_tier="MISSION_CRITICAL",
        criticality="CRITICAL",
        network_exposure="INTERNAL",
        data_sensitivity="RESTRICTED",
        environment="PRODUCTION",
    )
    repo.create(a1)
    repo.create(a2)

    # list_all should be sorted by asset_id ascending: ASSET-001, ASSET-002
    all_assets = repo.list_all()
    assert len(all_assets) == 2
    assert [a.asset_id for a in all_assets] == ["ASSET-001", "ASSET-002"]

    # Filter by environment
    prod_assets = repo.list_by_environment("PRODUCTION")
    assert len(prod_assets) == 1
    assert prod_assets[0].asset_id == "ASSET-001"

    # Filter by criticality
    crit_assets = repo.list_by_criticality("CRITICAL")
    assert len(crit_assets) == 1
    assert crit_assets[0].asset_id == "ASSET-001"


def test_asset_repo_update_and_delete(db_session: Session):
    """Verify AssetRepository updates and deletes an asset."""
    repo = AssetRepository(db_session)
    asset = Asset(
        asset_id="ASSET-DEL",
        hostname="to-delete.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    repo.create(asset)

    # Update
    asset.hostname = "updated-name.local"
    updated = repo.update(asset)
    assert updated.hostname == "updated-name.local"

    # Delete
    deleted = repo.delete(asset)
    assert deleted is True
    assert repo.get_by_asset_id("ASSET-DEL") is None


# --------------------------------------------------------------------------
# 2. VulnerabilityRepository Tests
# --------------------------------------------------------------------------

def test_vulnerability_repo_create_and_get(db_session: Session):
    """Verify VulnerabilityRepository creates and retrieves finding by finding_id and CVE."""
    asset_repo = AssetRepository(db_session)
    asset_repo.create(
        Asset(
            asset_id="ASSET-V1",
            hostname="host-v1.local",
            asset_type="SERVER",
            business_tier="BUSINESS_CRITICAL",
            criticality="HIGH",
            network_exposure="INTERNET_FACING",
            data_sensitivity="CONFIDENTIAL",
            environment="PRODUCTION",
        )
    )

    vuln_repo = VulnerabilityRepository(db_session)
    finding = VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-4863",
        title="Heap buffer overflow in libwebp",
        description="Arbitrary code execution in libwebp library",
        cvss_score=8.8,
        severity="HIGH",
        affected_package="libwebp",
        installed_version="1.2.0",
        fixed_version="1.3.2",
        asset_id="ASSET-V1",
        source="Trivy",
        status="OPEN",
    )
    created = vuln_repo.create(finding)
    assert created.id is not None
    assert created.finding_id == "FINDING-001"

    # Fetch by finding_id
    by_fid = vuln_repo.get_by_finding_id("FINDING-001")
    assert by_fid is not None
    assert by_fid.cve_id == "CVE-2023-4863"
    assert by_fid.cvss_score == 8.8

    # Fetch by CVE
    by_cve = vuln_repo.list_by_cve("CVE-2023-4863")
    assert len(by_cve) == 1
    assert by_cve[0].finding_id == "FINDING-001"


def test_vulnerability_repo_search_and_deterministic_order(db_session: Session):
    """Verify VulnerabilityRepository search across finding_id, CVE, title, package, and filters."""
    asset_repo = AssetRepository(db_session)
    asset_repo.create(
        Asset(
            asset_id="ASSET-V2",
            hostname="web-api.local",
            asset_type="SERVER",
            business_tier="STANDARD",
            criticality="MEDIUM",
            network_exposure="DMZ",
            data_sensitivity="INTERNAL",
            environment="STAGING",
        )
    )
    vuln_repo = VulnerabilityRepository(db_session)

    vuln_repo.create(
        VulnerabilityFinding(
            finding_id="FINDING-003",
            cve_id="CVE-2021-44228",
            title="Log4j RCE",
            description="Remote code execution in log4j",
            cvss_score=10.0,
            severity="CRITICAL",
            affected_package="log4j-core",
            installed_version="2.14.1",
            asset_id="ASSET-V2",
            source="Scanner",
            status="OPEN",
        )
    )
    vuln_repo.create(
        VulnerabilityFinding(
            finding_id="FINDING-002",
            cve_id="CVE-2022-22965",
            title="Spring4Shell RCE",
            description="Remote code execution in spring-beans",
            cvss_score=9.8,
            severity="CRITICAL",
            affected_package="spring-beans",
            installed_version="5.3.17",
            asset_id="ASSET-V2",
            source="Scanner",
            status="RESOLVED",
        )
    )

    # list_all should sort by finding_id asc: FINDING-002, FINDING-003
    all_findings = vuln_repo.list_all()
    assert [f.finding_id for f in all_findings] == ["FINDING-002", "FINDING-003"]

    # Search by package name
    search_pkg = vuln_repo.search(query="log4j")
    assert len(search_pkg) == 1
    assert search_pkg[0].finding_id == "FINDING-003"

    # Search by CVE substring
    search_cve = vuln_repo.search(query="22965")
    assert len(search_cve) == 1
    assert search_cve[0].finding_id == "FINDING-002"

    # Search with status filter
    search_open = vuln_repo.search(status="OPEN")
    assert len(search_open) == 1
    assert search_open[0].finding_id == "FINDING-003"

    # Search with severity filter
    search_crit = vuln_repo.search(severity="CRITICAL")
    assert len(search_crit) == 2


# --------------------------------------------------------------------------
# 3. ThreatIntelligenceRepository Tests
# --------------------------------------------------------------------------

def test_threat_repo_create_and_latest(db_session: Session):
    """Verify ThreatIntelligenceRepository retrieves latest observations with deterministic ordering."""
    repo = ThreatIntelligenceRepository(db_session)
    t1 = ThreatIntelligenceObservation(
        cve_id="CVE-2023-4863",
        source="CISA KEV",
        observed_at=datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc),
        is_cisa_kev=True,
        epss_score=0.90,
    )
    t2 = ThreatIntelligenceObservation(
        cve_id="CVE-2023-4863",
        source="FIRST EPSS",
        observed_at=datetime(2026, 1, 2, 12, 0, tzinfo=timezone.utc),
        is_cisa_kev=False,
        epss_score=0.95,
    )
    repo.create(t1)
    repo.create(t2)

    # list_by_cve should return newest first: t2, then t1
    all_obs = repo.list_by_cve("CVE-2023-4863")
    assert len(all_obs) == 2
    assert all_obs[0].source == "FIRST EPSS"
    assert all_obs[1].source == "CISA KEV"

    # get_latest_for_cve
    latest = repo.get_latest_for_cve("CVE-2023-4863")
    assert latest is not None
    assert latest.source == "FIRST EPSS"
    assert latest.epss_score == 0.95

    # get_latest_by_cve_and_source
    latest_kev = repo.get_latest_by_cve_and_source("CVE-2023-4863", "CISA KEV")
    assert latest_kev is not None
    assert latest_kev.is_cisa_kev is True


# --------------------------------------------------------------------------
# 4. ControlRepository Tests
# --------------------------------------------------------------------------

def test_control_repo_list_and_active_filter(db_session: Session):
    """Verify ControlRepository manages controls and filters active controls."""
    asset_repo = AssetRepository(db_session)
    asset_repo.create(
        Asset(
            asset_id="ASSET-C1",
            hostname="host-c1.local",
            asset_type="SERVER",
            business_tier="MISSION_CRITICAL",
            criticality="CRITICAL",
            network_exposure="INTERNET_FACING",
            data_sensitivity="RESTRICTED",
            environment="PRODUCTION",
        )
    )

    repo = ControlRepository(db_session)
    c1 = SecurityControl(
        control_id="CTRL-001",
        asset_id="ASSET-C1",
        name="WAF",
        description="Edge Web Application Firewall",
        status="ACTIVE",
        active=True,
    )
    c2 = SecurityControl(
        control_id="CTRL-002",
        asset_id="ASSET-C1",
        name="Legacy AV",
        description="Deprecated antivirus",
        status="INACTIVE",
        active=False,
    )
    repo.create(c1)
    repo.create(c2)

    # List all for asset
    all_ctrls = repo.list_by_asset("ASSET-C1")
    assert len(all_ctrls) == 2

    # List only active controls
    active_ctrls = repo.list_active_by_asset("ASSET-C1")
    assert len(active_ctrls) == 1
    assert active_ctrls[0].control_id == "CTRL-001"


# --------------------------------------------------------------------------
# 5. RiskAssessmentRepository Tests
# --------------------------------------------------------------------------

def test_risk_repo_historical_assessments_and_highest_risk(db_session: Session):
    """Verify RiskAssessmentRepository tracks historical evaluations and queries highest risk."""
    asset_repo = AssetRepository(db_session)
    asset_repo.create(
        Asset(
            asset_id="ASSET-R1",
            hostname="host-r1.local",
            asset_type="SERVER",
            business_tier="MISSION_CRITICAL",
            criticality="CRITICAL",
            network_exposure="INTERNET_FACING",
            data_sensitivity="RESTRICTED",
            environment="PRODUCTION",
        )
    )
    vuln_repo = VulnerabilityRepository(db_session)
    vuln_repo.create(
        VulnerabilityFinding(
            finding_id="FINDING-R1",
            cve_id="CVE-2023-4863",
            title="WebP Overflow",
            description="Desc",
            cvss_score=8.8,
            severity="HIGH",
            affected_package="libwebp",
            installed_version="1.2.0",
            asset_id="ASSET-R1",
            source="Scanner",
        )
    )

    risk_repo = RiskAssessmentRepository(db_session)
    # Historical assessment 1: Older
    a1 = RiskAssessment(
        assessment_id="ASSESS-001",
        finding_id="FINDING-R1",
        cve_id="CVE-2023-4863",
        asset_id="ASSET-R1",
        base_score=88.0,
        threat_score=70.0,
        environmental_score=80.0,
        raw_risk_score=80.2,
        control_multiplier=1.00,
        environmental_risk_score=80.20,
        risk_tier="CRITICAL",
        decision="ACT",
        explanation="Initial critical evaluation without controls",
        assessed_at=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
    )
    # Historical assessment 2: Newer, with control active -> lower ERS
    a2 = RiskAssessment(
        assessment_id="ASSESS-002",
        finding_id="FINDING-R1",
        cve_id="CVE-2023-4863",
        asset_id="ASSET-R1",
        base_score=88.0,
        threat_score=70.0,
        environmental_score=80.0,
        raw_risk_score=80.2,
        control_multiplier=0.70,
        environmental_risk_score=56.14,
        risk_tier="HIGH",
        decision="ATTEND",
        explanation="Re-evaluated with WAF active",
        assessed_at=datetime(2026, 1, 2, 10, 0, tzinfo=timezone.utc),
    )
    risk_repo.create(a1)
    risk_repo.create(a2)

    # list_by_finding should return newest first: a2, then a1
    history = risk_repo.list_by_finding("FINDING-R1")
    assert len(history) == 2
    assert history[0].assessment_id == "ASSESS-002"
    assert history[1].assessment_id == "ASSESS-001"

    # get_latest_for_finding
    latest = risk_repo.get_latest_for_finding("FINDING-R1")
    assert latest is not None
    assert latest.assessment_id == "ASSESS-002"
    assert latest.decision == "ATTEND"

    # list_highest_risk sorts by ERS desc
    highest = risk_repo.list_highest_risk(limit=5)
    assert len(highest) == 2
    assert highest[0].environmental_risk_score == 80.20
    assert highest[1].environmental_risk_score == 56.14


# --------------------------------------------------------------------------
# 6. PatchPlanRepository Tests
# --------------------------------------------------------------------------

def test_patch_plan_repo_items_and_sequence_ordering(db_session: Session):
    """Verify PatchPlanRepository handles plans, items, and sequence ordering."""
    asset_repo = AssetRepository(db_session)
    asset_repo.create(
        Asset(
            asset_id="ASSET-P1",
            hostname="host-p1.local",
            asset_type="SERVER",
            business_tier="BUSINESS_CRITICAL",
            criticality="HIGH",
            network_exposure="INTERNAL",
            data_sensitivity="CONFIDENTIAL",
            environment="PRODUCTION",
        )
    )
    vuln_repo = VulnerabilityRepository(db_session)
    vuln_repo.create(
        VulnerabilityFinding(
            finding_id="FINDING-P1",
            cve_id="CVE-2023-0001",
            title="Vuln 1",
            description="Desc 1",
            cvss_score=8.0,
            severity="HIGH",
            affected_package="p1",
            installed_version="1.0",
            asset_id="ASSET-P1",
            source="Test",
        )
    )
    vuln_repo.create(
        VulnerabilityFinding(
            finding_id="FINDING-P2",
            cve_id="CVE-2023-0002",
            title="Vuln 2",
            description="Desc 2",
            cvss_score=7.0,
            severity="HIGH",
            affected_package="p2",
            installed_version="2.0",
            asset_id="ASSET-P1",
            source="Test",
        )
    )

    plan_repo = PatchPlanRepository(db_session)
    plan = PatchPlan(
        plan_id="PLAN-001",
        title="Production Patch Sprint",
        status="DRAFT",
        capacity_hours=16.0,
        total_estimated_hours=6.0,
        expected_risk_reduction=145.0,
    )
    plan_repo.create(plan)

    # Add items out of order to verify retrieval ordering
    plan_repo.add_item(
        PatchPlanItem(
            patch_plan_id="PLAN-001",
            finding_id="FINDING-P2",
            sequence_order=2,
            estimated_hours=2.0,
            expected_risk_reduction=65.0,
            priority_decision="ATTEND",
            remediation_action="Upgrade p2",
        )
    )
    plan_repo.add_item(
        PatchPlanItem(
            patch_plan_id="PLAN-001",
            finding_id="FINDING-P1",
            sequence_order=1,
            estimated_hours=4.0,
            expected_risk_reduction=80.0,
            priority_decision="ACT",
            remediation_action="Upgrade p1",
        )
    )

    # get_items should be sorted by sequence_order asc: sequence 1, then sequence 2
    items = plan_repo.get_items("PLAN-001")
    assert len(items) == 2
    assert items[0].sequence_order == 1
    assert items[0].finding_id == "FINDING-P1"
    assert items[1].sequence_order == 2
    assert items[1].finding_id == "FINDING-P2"

    # get_plan_with_items eagerly loads items
    plan_with_items = plan_repo.get_plan_with_items("PLAN-001")
    assert plan_with_items is not None
    assert len(plan_with_items.items) == 2


# --------------------------------------------------------------------------
# 7. PolicyRepository Tests
# --------------------------------------------------------------------------

def test_policy_repo_crud_and_active_filters(db_session: Session):
    """Verify PolicyRepository manages policy documents and filters active policies."""
    repo = PolicyRepository(db_session)
    p1 = PolicyDocument(
        policy_id="POL-SEC-04",
        title="Vulnerability Remediation Policy",
        policy_type="VULNERABILITY_MANAGEMENT",
        version="2.4",
        status="ACTIVE",
    )
    p2 = PolicyDocument(
        policy_id="POL-ARCHIVED",
        title="Deprecated Policy",
        policy_type="VULNERABILITY_MANAGEMENT",
        version="1.0",
        status="ARCHIVED",
    )
    repo.create(p1)
    repo.create(p2)

    # Fetch by policy_id
    retrieved = repo.get_by_policy_id("POL-SEC-04")
    assert retrieved is not None
    assert retrieved.title == "Vulnerability Remediation Policy"

    # list_active
    active = repo.list_active()
    assert len(active) == 1
    assert active[0].policy_id == "POL-SEC-04"

    # list_by_type
    by_type = repo.list_by_type("VULNERABILITY_MANAGEMENT")
    assert len(by_type) == 2


# --------------------------------------------------------------------------
# 8. Transaction Boundary & Rollback Tests
# --------------------------------------------------------------------------

def test_repository_operations_do_not_commit_and_can_rollback(db_session: Session):
    """Verify repository methods flush but do not commit, allowing session-level rollbacks."""
    repo = AssetRepository(db_session)
    asset = Asset(
        asset_id="ASSET-RB",
        hostname="rollback-test.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    repo.create(asset)

    # Asset is in session (flushed)
    assert repo.get_by_asset_id("ASSET-RB") is not None

    # Roll back transaction at session boundary
    db_session.rollback()

    # Asset should no longer exist in database
    assert repo.get_by_asset_id("ASSET-RB") is None


# --------------------------------------------------------------------------
# 9. Error Handling Tests
# --------------------------------------------------------------------------

def test_expected_not_found_returns_none(db_session: Session):
    """Verify get_by_* methods return None when entity does not exist."""
    asset_repo = AssetRepository(db_session)
    assert asset_repo.get_by_id(99999) is None
    assert asset_repo.get_by_asset_id("NON-EXISTENT") is None
    assert asset_repo.get_by_hostname("missing.host.local") is None

    vuln_repo = VulnerabilityRepository(db_session)
    assert vuln_repo.get_by_id(99999) is None
    assert vuln_repo.get_by_finding_id("MISSING-FINDING") is None


def test_integrity_errors_propagate(db_session: Session):
    """Verify database IntegrityErrors are raised and not silently swallowed."""
    repo = AssetRepository(db_session)
    a1 = Asset(
        asset_id="ASSET-INT-DUP",
        hostname="host1.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    a2 = Asset(
        asset_id="ASSET-INT-DUP",  # duplicate ID
        hostname="host2.local",
        asset_type="SERVER",
        business_tier="NON_CRITICAL",
        criticality="LOW",
        network_exposure="INTERNAL",
        data_sensitivity="PUBLIC",
        environment="TESTING",
    )
    repo.create(a1)
    with pytest.raises(IntegrityError):
        repo.create(a2)
    db_session.rollback()
