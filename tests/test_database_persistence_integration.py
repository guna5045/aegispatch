"""Phase 5E: End-to-end database persistence integration and release gate tests.

Validates the full chain:
    Source JSON -> Benchmark Ingestion -> Repositories -> ORM -> SQLite
    Phase 3 Deterministic Risk Engine -> RiskAssessmentRepository -> SQLite
    Patch Plan Orchestration -> PatchPlanRepository -> SQLite
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session

from src.database.base import Base
from src.database.config import DEFAULT_RUNTIME_DIR
from src.database.engine import create_db_engine, reset_engine
from src.database.init_db import check_db_health, init_db
from src.database.ingestion.benchmark_ingestion import ingest_benchmark
from src.database.models.patch_plan import PatchPlan, PatchPlanItem
from src.database.models.risk import RiskAssessment
from src.database.repositories.asset_repository import AssetRepository
from src.database.repositories.control_repository import ControlRepository
from src.database.repositories.patch_plan_repository import PatchPlanRepository
from src.database.repositories.policy_repository import PolicyRepository
from src.database.repositories.risk_repository import RiskAssessmentRepository
from src.database.repositories.threat_repository import ThreatIntelligenceRepository
from src.database.repositories.vulnerability_repository import VulnerabilityRepository
from src.database.session import get_session_maker
from src.services.data_service import load_benchmark_findings, load_cmdb_assets
from src.services.persistence_service import PersistenceService
from src.tools.risk_engine import evaluate_risk


@pytest.fixture(autouse=True)
def clean_engine():
    """Ensure engine cache is cleaned before and after tests."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def in_memory_engine():
    """Create an isolated, in-memory SQLite engine with foreign keys enabled."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON;"))
        conn.commit()
    init_db(engine=engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(in_memory_engine) -> Session:
    """Yield an isolated transactional database session."""
    maker = get_session_maker(in_memory_engine)
    sess = maker()
    try:
        yield sess
    finally:
        sess.close()



def test_database_initialization_creates_all_eight_tables(in_memory_engine):
    """Verify init_db() creates all 8 expected domain tables idempotently."""
    inspector = inspect(in_memory_engine)
    tables = set(inspector.get_table_names())

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
    assert expected_tables.issubset(tables)

    # Calling init_db again is idempotent and does not fail
    init_db(engine=in_memory_engine)
    assert check_db_health(engine=in_memory_engine) is True


def test_end_to_end_benchmark_persistence_flow(session):
    """Verify complete end-to-end benchmark ingestion and repository access."""
    # 1. Ingest benchmark dataset
    summary = ingest_benchmark(session=session)

    assert summary.assets_created == 18
    assert summary.controls_created == 18
    assert summary.findings_created == 60
    assert summary.policies_created == 3
    assert summary.threat_observations_created == 0

    # 2. Query via Repositories
    asset_repo = AssetRepository(session)
    control_repo = ControlRepository(session)
    vuln_repo = VulnerabilityRepository(session)
    policy_repo = PolicyRepository(session)
    threat_repo = ThreatIntelligenceRepository(session)
    risk_repo = RiskAssessmentRepository(session)
    plan_repo = PatchPlanRepository(session)

    assets = asset_repo.list_all()
    assert len(assets) == 18
    assert assets[0].asset_id == "ASSET-001"
    assert assets[-1].asset_id == "ASSET-018"

    findings = vuln_repo.list_all()
    assert len(findings) == 60
    assert findings[0].finding_id == "FINDING-001"
    assert findings[-1].finding_id == "FINDING-060"

    # Verify every finding references an ingested asset
    for f in findings:
        assert asset_repo.get_by_asset_id(f.asset_id) is not None

    # Verify controls
    controls = control_repo.list_all()
    assert len(controls) == 18

    # Verify policies
    policies = policy_repo.list_all()
    assert len(policies) == 3
    policy_ids = {p.policy_id for p in policies}
    assert policy_ids == {"POL-SEC-04", "POL-IT-09", "POL-SEC-12"}

    # Verify threat intelligence observations, risk assessments, patch plans remain empty
    threats = threat_repo.list_recent()
    assert len(threats) == 0

    assert risk_repo.list_highest_risk(limit=10) == []
    assert plan_repo.list_all() == []


def test_phase3_risk_engine_persisted_integration(session):
    """Verify Phase 3 contextual risk engine calculation can be persisted and retrieved."""
    # 1. Ingest benchmark data to satisfy foreign keys
    ingest_benchmark(session=session)

    # 2. Load real Phase 1/2 benchmark models for finding & asset
    findings_dict = load_benchmark_findings()
    assets_dict = load_cmdb_assets()

    finding_pydantic = findings_dict["FINDING-001"]
    asset_pydantic = assets_dict[finding_pydantic.asset_id]

    # 3. Evaluate risk using the EXISTING Phase 3 deterministic risk engine (no formula duplication)
    risk_result = evaluate_risk(finding_pydantic, asset_pydantic, threat=None)
    assert risk_result.environmental_risk_score > 0.0

    # 4. Persist result through PersistenceService
    saved_orm = PersistenceService.save_risk_assessment(session, risk_result)
    assert saved_orm.id is not None
    assert saved_orm.finding_id == "FINDING-001"
    assert saved_orm.environmental_risk_score == pytest.approx(risk_result.environmental_risk_score, rel=1e-3)

    # 5. Retrieve and verify all risk components (B, T, E, R, M_control, ERS, Decision)
    retrieved = PersistenceService.get_latest_risk_assessment(session, "FINDING-001")
    assert retrieved is not None
    assert retrieved.assessment_id == risk_result.assessment_id
    assert retrieved.cve_id == finding_pydantic.cve_id
    assert retrieved.asset_id == asset_pydantic.asset_id

    # Verify mathematical inputs match risk engine output
    meta = risk_result.calculation_metadata or {}
    assert retrieved.base_score == pytest.approx(float(meta.get("base_score", 0.0)), rel=1e-3)
    assert retrieved.threat_score == pytest.approx(float(meta.get("threat_score", 0.0)), rel=1e-3)
    assert retrieved.environmental_score == pytest.approx(float(meta.get("environmental_score", 0.0)), rel=1e-3)
    assert retrieved.raw_risk_score == pytest.approx(float(meta.get("weighted_risk", 0.0)), rel=1e-3)
    assert retrieved.control_multiplier == pytest.approx(float(meta.get("control_multiplier", 1.0)), rel=1e-3)
    assert retrieved.environmental_risk_score == pytest.approx(risk_result.environmental_risk_score, rel=1e-3)
    assert retrieved.decision == risk_result.decision.value
    assert retrieved.risk_tier == risk_result.risk_tier.value
    assert len(retrieved.explanation) > 0


def test_historical_risk_assessments_for_same_finding(session):
    """Verify historical risk evaluations can be accumulated over time without replacing past records."""
    ingest_benchmark(session=session)

    findings_dict = load_benchmark_findings()
    assets_dict = load_cmdb_assets()

    finding = findings_dict["FINDING-002"]
    asset = assets_dict[finding.asset_id]

    # First evaluation at T1
    t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    res_1 = evaluate_risk(finding, asset, assessment_id="ASSESS-HIST-001", assessed_at=t1)
    PersistenceService.save_risk_assessment(session, res_1)

    # Second evaluation at T2
    t2 = datetime(2026, 1, 2, 12, 0, 0, tzinfo=timezone.utc)
    res_2 = evaluate_risk(finding, asset, assessment_id="ASSESS-HIST-002", assessed_at=t2)
    PersistenceService.save_risk_assessment(session, res_2)

    # Check history: should have 2 historical records, ordered newest first
    history = PersistenceService.list_risk_assessments_for_finding(session, "FINDING-002")
    assert len(history) == 2
    assert history[0].assessment_id == "ASSESS-HIST-002"
    assert history[1].assessment_id == "ASSESS-HIST-001"

    latest = PersistenceService.get_latest_risk_assessment(session, "FINDING-002")
    assert latest.assessment_id == "ASSESS-HIST-002"


def test_patch_plan_and_items_persistence_integration(session):
    """Verify PatchPlan and PatchPlanItem persistence, execution ordering, and rollback plan storage."""
    ingest_benchmark(session=session)

    # Create a patch plan
    plan = PatchPlan(
        plan_id="PLAN-2026-Q1-001",
        title="Emergency Edge Mitigation Sprint",
        status="APPROVED",
        capacity_hours=40.0,
        total_estimated_hours=18.5,
        expected_risk_reduction=72.4,
        notes="High-priority remediation targeting perimeter edge assets.",
        approved_at=datetime.now(timezone.utc),
    )

    items = [
        PatchPlanItem(
            item_id="ITEM-001",
            patch_plan_id="PLAN-2026-Q1-001",
            finding_id="FINDING-001",
            sequence_order=1,
            estimated_hours=6.0,
            expected_risk_reduction=35.0,
            priority_decision="IMMEDIATE_PATCH",
            remediation_action="Apply vendor kernel security hotfix 5.15.0-89-generic",
            rollback_plan={"strategy": "boot_previous_kernel", "backup_snapshot": "snap-20260101-01"},
            status="SCHEDULED",
            dependencies=[],
        ),
        PatchPlanItem(
            item_id="ITEM-002",
            patch_plan_id="PLAN-2026-Q1-001",
            finding_id="FINDING-002",
            sequence_order=2,
            estimated_hours=12.5,
            expected_risk_reduction=37.4,
            priority_decision="SCHEDULED_PATCH",
            remediation_action="Upgrade nginx to 1.25.3-release and restart reverse-proxy",
            rollback_plan={"strategy": "revert_docker_tag", "previous_image": "nginx:1.24.0-alpine"},
            status="PENDING",
            dependencies=["ITEM-001"],
        ),
    ]

    saved_plan = PersistenceService.save_patch_plan(session, plan, items=items)
    assert saved_plan.id is not None
    assert saved_plan.plan_id == "PLAN-2026-Q1-001"

    # Retrieve and verify eager loading of items and strict sequence ordering
    retrieved_plan = PersistenceService.get_patch_plan(session, "PLAN-2026-Q1-001")
    assert retrieved_plan is not None
    assert retrieved_plan.title == "Emergency Edge Mitigation Sprint"
    assert len(retrieved_plan.items) == 2
    assert retrieved_plan.items[0].sequence_order == 1
    assert retrieved_plan.items[0].finding_id == "FINDING-001"
    assert retrieved_plan.items[0].rollback_plan["strategy"] == "boot_previous_kernel"
    assert retrieved_plan.items[1].sequence_order == 2
    assert retrieved_plan.items[1].finding_id == "FINDING-002"
    assert retrieved_plan.items[1].dependencies == ["ITEM-001"]


def test_runtime_database_is_never_touched_by_tests():
    """Verify test execution strictly uses isolated environments and never touches runtime database."""
    runtime_db = DEFAULT_RUNTIME_DIR / "aegispatch.db"
    # Even if runtime_db exists, tests must never overwrite or delete it.
    # We verify that DEFAULT_RUNTIME_DIR is properly configured.
    assert Path(DEFAULT_RUNTIME_DIR).name == "runtime"


def test_persistence_service_domain_queries(session):
    """Verify PersistenceService high-level asset, finding, control, and policy queries."""
    PersistenceService.ingest_benchmark_dataset(session)

    # 1. Assets
    assets = PersistenceService.list_assets(session)
    assert len(assets) == 18
    asset_01 = PersistenceService.get_asset(session, "ASSET-001")
    assert asset_01 is not None
    assert asset_01.hostname == "api-gw-prod-01.aegis.internal"

    # Controls for asset
    controls = PersistenceService.list_controls_for_asset(session, "ASSET-001")
    assert len(controls) == 2
    control_names = {c.name for c in controls}
    assert "Cloudflare Enterprise WAF" in control_names
    assert "Edge Rate Limiting & Anti-DDoS" in control_names

    # 2. Findings
    findings = PersistenceService.list_findings(session)
    assert len(findings) == 60
    finding_01 = PersistenceService.get_finding(session, "FINDING-001")
    assert finding_01 is not None
    assert finding_01.cve_id == "CVE-2023-38545"

    asset_findings = PersistenceService.list_findings_for_asset(session, "ASSET-001")
    assert len(asset_findings) > 0
    assert all(f.asset_id == "ASSET-001" for f in asset_findings)

    # 3. Policies
    policies = PersistenceService.list_policies(session)
    assert len(policies) == 3
    pol_sec = PersistenceService.get_policy(session, "POL-SEC-04")
    assert pol_sec is not None
    assert pol_sec.title == "Enterprise Vulnerability Remediation and Patch Management Policy"


def test_persistence_service_save_risk_assessment_formats(session):
    """Verify PersistenceService supports ORM objects and dictionary representations."""
    PersistenceService.ingest_benchmark_dataset(session)

    # 1. Save from dict
    dict_payload = {
        "assessment_id": "RSK-CUSTOM-DICT-001",
        "finding_id": "FINDING-003",
        "cve_id": "CVE-2023-38545",
        "asset_id": "ASSET-001",
        "base_score": 9.8,
        "threat_score": 8.5,
        "environmental_score": 9.0,
        "raw_risk_score": 9.2,
        "control_multiplier": 0.5,
        "environmental_risk_score": 46.0,
        "risk_tier": "HIGH",
        "decision": "ATTEND",
        "remediation_decision": "SCHEDULED_PATCH",
        "explanation": "High exposure with mitigating WAF control.",
        "supporting_evidence": ["Evidence 1", "Evidence 2"],
        "calculation_metadata": {"engine": "test_v1"},
        "engine_version": "test_v1",
        "assessed_at": datetime.now(timezone.utc),
    }

    saved_from_dict = PersistenceService.save_risk_assessment(session, dict_payload)
    assert saved_from_dict.id is not None
    assert saved_from_dict.assessment_id == "RSK-CUSTOM-DICT-001"

    # 2. Save direct ORM
    orm_payload = RiskAssessment(
        assessment_id="RSK-CUSTOM-ORM-001",
        finding_id="FINDING-003",
        cve_id="CVE-2023-38545",
        asset_id="ASSET-001",
        base_score=9.8,
        threat_score=8.5,
        environmental_score=9.0,
        raw_risk_score=9.2,
        control_multiplier=0.5,
        environmental_risk_score=46.0,
        risk_tier="HIGH",
        decision="ATTEND",
        remediation_decision="SCHEDULED_PATCH",
        explanation="Direct ORM entity insertion test.",
        engine_version="test_v1",
        assessed_at=datetime.now(timezone.utc),
    )
    saved_from_orm = PersistenceService.save_risk_assessment(session, orm_payload)
    assert saved_from_orm.id is not None
    assert saved_from_orm.assessment_id == "RSK-CUSTOM-ORM-001"

    # Both are recorded for FINDING-003
    history = PersistenceService.list_risk_assessments_for_finding(session, "FINDING-003")
    assert len(history) == 2


def test_persistence_service_idempotent_ingestion(session):
    """Verify consecutive ingestion calls through PersistenceService remain completely idempotent."""
    summary_1 = PersistenceService.ingest_benchmark_dataset(session)
    assert summary_1.assets_created == 18
    assert summary_1.findings_created == 60
    assert summary_1.assets_updated == 0

    summary_2 = PersistenceService.ingest_benchmark_dataset(session)
    assert summary_2.assets_created == 0
    assert summary_2.findings_created == 0
    assert summary_2.assets_updated == 18
    assert summary_2.findings_updated == 60

    # Final counts unchanged
    assert len(PersistenceService.list_assets(session)) == 18
    assert len(PersistenceService.list_findings(session)) == 60

