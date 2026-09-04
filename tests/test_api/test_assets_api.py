"""Tests for enterprise assets API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_assets_default_pagination(client: TestClient):
    """Verify listing assets returns the first page of 18 benchmark assets."""
    response = client.get("/api/v1/assets")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "pagination" in data
    assert data["pagination"]["total_items"] == 18
    assert len(data["items"]) == 18
    assert data["pagination"]["page"] == 1
    assert data["items"][0]["asset_id"] == "ASSET-001"


def test_list_assets_custom_pagination(client: TestClient):
    """Verify page and page_size windowing."""
    response = client.get("/api/v1/assets?page=2&page_size=5")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 5
    assert data["pagination"]["page"] == 2
    assert data["pagination"]["page_size"] == 5
    assert data["pagination"]["total_items"] == 18
    assert data["pagination"]["total_pages"] == 4
    assert data["items"][0]["asset_id"] == "ASSET-006"


def test_list_assets_filtering_by_environment(client: TestClient):
    """Verify filtering assets by environment."""
    response = client.get("/api/v1/assets?environment=PRODUCTION")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] > 0
    assert all(item["environment"] == "PRODUCTION" for item in data["items"])


def test_list_assets_filtering_by_criticality(client: TestClient):
    """Verify filtering assets by criticality rating."""
    response = client.get("/api/v1/assets?criticality=CRITICAL")
    assert response.status_code == 200
    data = response.json()
    assert data["pagination"]["total_items"] > 0
    assert all(item["criticality"] == "CRITICAL" for item in data["items"])


def test_get_asset_detail_success(client: TestClient):
    """Verify retrieving an asset with its active compensating controls."""
    response = client.get("/api/v1/assets/ASSET-001")
    assert response.status_code == 200
    data = response.json()
    assert data["asset_id"] == "ASSET-001"
    assert data["hostname"] == "api-gw-prod-01.aegis.internal"
    assert "controls" in data
    assert len(data["controls"]) == 2
    assert data["findings_count"] > 0


def test_get_asset_not_found(client: TestClient):
    """Verify retrieving a nonexistent asset returns 404 with structured error."""
    response = client.get("/api/v1/assets/ASSET-NONEXISTENT")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"
    assert "ASSET-NONEXISTENT" in data["error"]["message"]


def test_get_asset_findings_success(client: TestClient):
    """Verify retrieving all findings mapped to a valid asset."""
    response = client.get("/api/v1/assets/ASSET-001/findings")
    assert response.status_code == 200
    findings = response.json()
    assert isinstance(findings, list)
    assert len(findings) > 0
    assert all(f["asset_id"] == "ASSET-001" for f in findings)


def test_get_asset_findings_unknown_asset(client: TestClient):
    """Verify retrieving findings for an unknown asset returns 404."""
    response = client.get("/api/v1/assets/ASSET-999/findings")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"
