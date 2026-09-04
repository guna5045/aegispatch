"""Tests for contextual risk assessment API endpoints."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.services.data_service import load_benchmark_findings, load_cmdb_assets
from src.services.persistence_service import PersistenceService
from src.tools.risk_engine import evaluate_risk


def test_persisted_risk_assessment_retrieval(client: TestClient, db_session: Session):
    """Verify calculating and persisting a risk assessment enables API retrieval via /vulnerabilities/{id}/risk."""
    findings = load_benchmark_findings()
    assets = load_cmdb_assets()

    finding = findings["FINDING-001"]
    asset = assets[finding.asset_id]

    # Evaluate with Phase 3 engine and persist
    res = evaluate_risk(finding, asset, threat=None)
    PersistenceService.save_risk_assessment(db_session, res)
    db_session.commit()

    # Query endpoint
    response = client.get("/api/v1/vulnerabilities/FINDING-001/risk")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "FINDING-001"
    assert data["assessment_id"] == res.assessment_id
    assert data["environmental_risk_score"] > 0.0
    assert data["base_score"] > 0.0
    assert data["decision"] in ["ACT", "ATTEND", "PLAN", "TRACK", "IMMEDIATE_PATCH", "SCHEDULED_PATCH", "MITIGATE", "ACCEPT_RISK", "MONITOR"]
    assert len(data["explanation"]) > 0


def test_list_highest_risk_assessments(client: TestClient, db_session: Session):
    """Verify /api/v1/risk/highest returns top evaluations ordered by ERS descending."""
    findings = load_benchmark_findings()
    assets = load_cmdb_assets()

    # Persist two assessments
    f1, a1 = findings["FINDING-002"], assets[findings["FINDING-002"].asset_id]
    f2, a2 = findings["FINDING-003"], assets[findings["FINDING-003"].asset_id]

    r1 = evaluate_risk(f1, a1, threat=None)
    r2 = evaluate_risk(f2, a2, threat=None)

    PersistenceService.save_risk_assessment(db_session, r1)
    PersistenceService.save_risk_assessment(db_session, r2)
    db_session.commit()

    response = client.get("/api/v1/risk/highest?limit=5")
    assert response.status_code == 200
    items = response.json()
    assert len(items) >= 2
    # Verify descending ordering
    for i in range(len(items) - 1):
        assert items[i]["environmental_risk_score"] >= items[i + 1]["environmental_risk_score"]


def test_risk_history_for_finding(client: TestClient, db_session: Session):
    """Verify /api/v1/risk/{finding_id}/history returns evaluations in newest-first order."""
    findings = load_benchmark_findings()
    assets = load_cmdb_assets()

    f = findings["FINDING-004"]
    a = assets[f.asset_id]

    t1 = datetime(2026, 1, 1, 10, 0, 0, tzinfo=timezone.utc)
    t2 = datetime(2026, 1, 2, 10, 0, 0, tzinfo=timezone.utc)

    r1 = evaluate_risk(f, a, assessment_id="ASSESS-H-001", assessed_at=t1)
    r2 = evaluate_risk(f, a, assessment_id="ASSESS-H-002", assessed_at=t2)

    PersistenceService.save_risk_assessment(db_session, r1)
    PersistenceService.save_risk_assessment(db_session, r2)
    db_session.commit()

    response = client.get("/api/v1/risk/FINDING-004/history")
    assert response.status_code == 200
    history = response.json()
    assert len(history) == 2
    assert history[0]["assessment_id"] == "ASSESS-H-002"
    assert history[1]["assessment_id"] == "ASSESS-H-001"
