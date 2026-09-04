"""Tests for stored threat intelligence observations API endpoint (Offline / Stored Only)."""

from __future__ import annotations

from datetime import datetime, timezone
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.database.models.threat import ThreatIntelligenceObservation
from src.database.repositories.threat_repository import ThreatIntelligenceRepository


def test_get_threat_observations_empty_baseline(client: TestClient):
    """Verify endpoint returns empty list for CVE with no stored telemetry (offline baseline)."""
    response = client.get("/api/v1/threat-intelligence/CVE-2023-38545")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 0


def test_get_threat_observations_persisted_record(client: TestClient, db_session: Session):
    """Verify stored threat observation can be queried without making external network calls."""
    repo = ThreatIntelligenceRepository(db_session)
    obs = ThreatIntelligenceObservation(
        cve_id="CVE-2023-44487",
        source="CISA_KEV_ARCHIVE",
        is_cisa_kev=True,
        epss_score=0.975,
        exploit_available=True,
        notes="HTTP/2 Rapid Reset documented in archive.",
        observed_at=datetime.now(timezone.utc),
    )
    repo.create(obs)
    db_session.commit()

    response = client.get("/api/v1/threat-intelligence/CVE-2023-44487")
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["cve_id"] == "CVE-2023-44487"
    assert data[0]["source"] == "CISA_KEV_ARCHIVE"
    assert data[0]["is_cisa_kev"] is True
    assert data[0]["epss_score"] == 0.975
