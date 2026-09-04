"""Tests for vulnerability scan findings API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_vulnerabilities_default_pagination(client: TestClient):
    """Verify listing findings returns the first page of 60 benchmark findings."""
    response = client.get("/api/v1/vulnerabilities")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] == 60
    assert len(data["items"]) == 20
    assert data["pagination"]["page"] == 1
    assert data["pagination"]["total_pages"] == 3
    assert data["items"][0]["finding_id"] == "FINDING-001"


def test_list_vulnerabilities_search(client: TestClient):
    """Verify searching findings by CVE or package substring."""
    response = client.get("/api/v1/vulnerabilities?search=curl")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] > 0
    assert any("curl" in item["affected_package"].lower() or "curl" in item["title"].lower() for item in data["items"])


def test_list_vulnerabilities_filter_severity(client: TestClient):
    """Verify filtering findings by severity rating."""
    response = client.get("/api/v1/vulnerabilities?severity=CRITICAL")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] > 0
    assert all(item["severity"] == "CRITICAL" for item in data["items"])


def test_list_vulnerabilities_filter_asset(client: TestClient):
    """Verify filtering findings by asset_id."""
    response = client.get("/api/v1/vulnerabilities?asset_id=ASSET-001")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] > 0
    assert all(item["asset_id"] == "ASSET-001" for item in data["items"])


def test_get_vulnerability_detail_success(client: TestClient):
    """Verify retrieving full technical details and references for a finding."""
    response = client.get("/api/v1/vulnerabilities/FINDING-001")
    assert response.status_code == 200
    data = response.json()
    assert data["finding_id"] == "FINDING-001"
    assert data["cve_id"] == "CVE-2023-38545"
    assert len(data["description"]) > 0
    assert data["cvss_score"] == 9.8


def test_get_vulnerability_not_found(client: TestClient):
    """Verify retrieving unknown finding returns 404."""
    response = client.get("/api/v1/vulnerabilities/FINDING-NONEXISTENT")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"


def test_get_vulnerability_risk_not_persisted(client: TestClient):
    """Verify requesting risk for finding with no persisted evaluation returns 404."""
    # Benchmark findings do not have persisted risk assessments initially
    response = client.get("/api/v1/vulnerabilities/FINDING-010/risk")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"
    assert "No risk assessment has been persisted" in data["error"]["message"]
