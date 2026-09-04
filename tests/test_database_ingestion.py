"""Comprehensive unit and integration tests for Aegis Patch Phase 5D: Benchmark Ingestion."""

import json
from pathlib import Path
import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from src.database import (
    Asset,
    AssetRepository,
    Base,
    ControlRepository,
    PatchPlan,
    PatchPlanItem,
    PolicyDocument,
    PolicyRepository,
    RiskAssessment,
    SecurityControl,
    ThreatIntelligenceObservation,
    VulnerabilityFinding,
    VulnerabilityRepository,
    create_db_engine,
    get_session_maker,
    ingest_benchmark,
    reset_engine,
    run_benchmark_ingestion,
)


@pytest.fixture(autouse=True)
def clean_engine():
    """Ensure engine cache is cleaned before and after tests."""
    reset_engine()
    yield
    reset_engine()


@pytest.fixture
def memory_db():
    """Create an isolated in-memory SQLite database with foreign keys enabled."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    with engine.connect() as conn:
        conn.execute(text("PRAGMA foreign_keys = ON"))
        conn.commit()

    Base.metadata.create_all(bind=engine)
    maker = get_session_maker(engine)
    yield engine, maker
    engine.dispose()


# --------------------------------------------------------------------------
# 1. Baseline Ingestion Tests
# --------------------------------------------------------------------------

def test_benchmark_ingestion_success(memory_db):
    """Verify that benchmark ingestion populates exactly 18 assets, 60 findings, controls, and policies."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        summary = ingest_benchmark(session=session)
        session.commit()

        # Check summary object
        assert summary.assets_created == 18
        assert summary.assets_updated == 0
        assert summary.findings_created == 60
        assert summary.findings_updated == 0
        assert summary.controls_created == 18
        assert summary.controls_updated == 0
        assert summary.policies_created == 3
        assert summary.policies_updated == 0
        assert summary.threat_observations_created == 0  # Preserved offline baseline

        # Database counts verification
        asset_count = session.query(Asset).count()
        finding_count = session.query(VulnerabilityFinding).count()
        control_count = session.query(SecurityControl).count()
        policy_count = session.query(PolicyDocument).count()
        threat_count = session.query(ThreatIntelligenceObservation).count()
        risk_count = session.query(RiskAssessment).count()
        plan_count = session.query(PatchPlan).count()
        item_count = session.query(PatchPlanItem).count()

        assert asset_count == 18
        assert finding_count == 60
        assert control_count == 18
        assert policy_count == 3
        assert threat_count == 0
        assert risk_count == 0
        assert plan_count == 0
        assert item_count == 0
    finally:
        session.close()


def test_every_finding_references_valid_asset(memory_db):
    """Verify that 100% of ingested findings point to an existing enterprise asset."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        ingest_benchmark(session=session)
        session.commit()

        findings = session.query(VulnerabilityFinding).all()
        assert len(findings) == 60

        asset_ids = {a.asset_id for a in session.query(Asset).all()}
        assert len(asset_ids) == 18

        for f in findings:
            assert f.asset_id in asset_ids
            assert f.asset is not None
            assert f.asset.asset_id == f.asset_id
    finally:
        session.close()


def test_asset_and_control_mapping(memory_db):
    """Verify specific known benchmark assets and their controls are accurately mapped."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        ingest_benchmark(session=session)
        session.commit()

        # Check ASSET-001
        asset_1 = session.query(Asset).filter_by(asset_id="ASSET-001").first()
        assert asset_1 is not None
        assert asset_1.hostname == "api-gw-prod-01.aegis.internal"
        assert asset_1.criticality == "CRITICAL"
        assert asset_1.network_exposure == "INTERNET_FACING"
        assert asset_1.environment == "PRODUCTION"
        assert len(asset_1.controls) == 2
        control_names = [c.name for c in asset_1.controls]
        assert "Cloudflare Enterprise WAF" in control_names
        assert "Edge Rate Limiting & Anti-DDoS" in control_names

        # Check ASSET-018
        asset_18 = session.query(Asset).filter_by(asset_id="ASSET-018").first()
        assert asset_18 is not None
        assert asset_18.environment == "TESTING"
        assert asset_18.criticality == "LOW"
    finally:
        session.close()


def test_policy_document_mapping(memory_db):
    """Verify policy documents POL-SEC-04, POL-IT-09, and POL-SEC-12 are persisted with correct metadata."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        ingest_benchmark(session=session)
        session.commit()

        policies = {p.policy_id: p for p in session.query(PolicyDocument).all()}
        assert set(policies.keys()) == {"POL-SEC-04", "POL-IT-09", "POL-SEC-12"}

        sec_04 = policies["POL-SEC-04"]
        assert sec_04.title == "Enterprise Vulnerability Remediation and Patch Management Policy"
        assert sec_04.version == "2.4"
        assert sec_04.status == "ACTIVE"
        assert sec_04.content_hash.startswith("sha256:")

        it_09 = policies["POL-IT-09"]
        assert it_09.version == "3.1"
    finally:
        session.close()


# --------------------------------------------------------------------------
# 2. Idempotency & Upsert Tests
# --------------------------------------------------------------------------

def test_ingestion_idempotency(memory_db):
    """Verify that running ingestion twice produces the same logical database state without duplicates."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        # First ingestion run
        s1 = ingest_benchmark(session=session)
        session.commit()
        assert s1.assets_created == 18
        assert s1.findings_created == 60
        assert s1.controls_created == 18
        assert s1.policies_created == 3

        # Second ingestion run on same database
        s2 = ingest_benchmark(session=session)
        session.commit()
        assert s2.assets_created == 0
        assert s2.assets_updated == 18
        assert s2.findings_created == 0
        assert s2.findings_updated == 60
        assert s2.controls_created == 0
        assert s2.controls_updated == 18
        assert s2.policies_created == 0
        assert s2.policies_updated == 3

        # Final database counts must be strictly unchanged
        assert session.query(Asset).count() == 18
        assert session.query(VulnerabilityFinding).count() == 60
        assert session.query(SecurityControl).count() == 18
        assert session.query(PolicyDocument).count() == 3
    finally:
        session.close()


def test_upsert_modifies_existing_source_fields(memory_db, tmp_path):
    """Verify that modified source fields are updated during subsequent ingestion."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        # Initial ingestion
        ingest_benchmark(session=session)
        session.commit()

        # Create a modified CMDB JSON
        from src.database.config import PROJECT_ROOT
        orig_cmdb = json.load(open(PROJECT_ROOT / "data" / "synthetic" / "enterprise_cmdb.json", encoding="utf-8"))
        # Change hostname of ASSET-001
        orig_cmdb[0]["hostname"] = "api-gw-prod-MODIFIED.aegis.internal"

        mod_cmdb_path = tmp_path / "modified_cmdb.json"
        with open(mod_cmdb_path, "w", encoding="utf-8") as f:
            json.dump(orig_cmdb, f)

        # Ingest with modified CMDB
        ingest_benchmark(session=session, cmdb_path=mod_cmdb_path)
        session.commit()

        asset_1 = session.query(Asset).filter_by(asset_id="ASSET-001").first()
        assert asset_1.hostname == "api-gw-prod-MODIFIED.aegis.internal"
        # Total count still 18
        assert session.query(Asset).count() == 18
    finally:
        session.close()


# --------------------------------------------------------------------------
# 3. Transaction Atomicity & Failure Rollback Tests
# --------------------------------------------------------------------------

def test_ingestion_failure_causes_complete_rollback(memory_db, tmp_path):
    """Verify that an invalid record (e.g., unknown asset reference) causes a complete atomic rollback."""
    engine, maker = memory_db

    # Create invalid scans JSON with a finding referencing non-existent asset
    from src.database.config import PROJECT_ROOT
    scans_data = json.load(open(PROJECT_ROOT / "data" / "synthetic" / "benchmark_60_scans.json", encoding="utf-8"))
    scans_data[10]["asset_id"] = "ASSET-NON-EXISTENT"

    bad_scans_path = tmp_path / "bad_scans.json"
    with open(bad_scans_path, "w", encoding="utf-8") as f:
        json.dump(scans_data, f)

    session: Session = maker()
    try:
        # Attempt ingestion which must fail due to foreign key validation
        with pytest.raises(ValueError, match="references unknown asset 'ASSET-NON-EXISTENT'"):
            ingest_benchmark(session=session, scans_path=bad_scans_path)

        # Rollback at transaction boundary
        session.rollback()

        # The database must remain completely empty: 0 assets, 0 findings, 0 controls!
        assert session.query(Asset).count() == 0
        assert session.query(VulnerabilityFinding).count() == 0
        assert session.query(SecurityControl).count() == 0
    finally:
        session.close()


def test_missing_cmdb_file_raises_error(memory_db):
    """Verify missing CMDB file raises FileNotFoundError without modifying database."""
    engine, maker = memory_db
    session: Session = maker()
    try:
        with pytest.raises(FileNotFoundError):
            ingest_benchmark(session=session, cmdb_path="/non/existent/path.json")
        session.rollback()
        assert session.query(Asset).count() == 0
    finally:
        session.close()


def test_malformed_json_raises_error(memory_db, tmp_path):
    """Verify malformed JSON raises ValueError and rolls back."""
    bad_json_path = tmp_path / "corrupted.json"
    bad_json_path.write_text("{ this is not valid json }", encoding="utf-8")

    engine, maker = memory_db
    session: Session = maker()
    try:
        with pytest.raises(ValueError, match="Malformed CMDB JSON"):
            ingest_benchmark(session=session, cmdb_path=bad_json_path)
        session.rollback()
        assert session.query(Asset).count() == 0
    finally:
        session.close()


# --------------------------------------------------------------------------
# 4. Top-Level Entry Point & Isolation Tests
# --------------------------------------------------------------------------

def test_run_benchmark_ingestion_entry_point():
    """Verify run_benchmark_ingestion() top-level runner executes on isolated in-memory database."""
    engine = create_db_engine("sqlite:///:memory:", echo=False)
    summary = run_benchmark_ingestion(engine=engine)
    assert summary.total_assets == 18
    assert summary.total_findings == 60
    assert summary.total_controls == 18
    assert summary.total_policies == 3
    engine.dispose()
