"""Tests for organizational security policies API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_list_policies(client: TestClient):
    """Verify listing all 3 ingested benchmark security policies."""
    response = client.get("/api/v1/policies")
    assert response.status_code == 200
    policies = response.json()
    assert isinstance(policies, list)
    assert len(policies) == 3
    ids = {p["policy_id"] for p in policies}
    assert ids == {"POL-SEC-04", "POL-IT-09", "POL-SEC-12"}


def test_list_policies_filter_status(client: TestClient):
    """Verify filtering policies by status."""
    response = client.get("/api/v1/policies?status=ACTIVE")
    assert response.status_code == 200
    policies = response.json()
    assert len(policies) == 3
    assert all(p["status"] == "ACTIVE" for p in policies)


def test_get_policy_detail_success(client: TestClient):
    """Verify retrieving policy detail including SHA-256 digest and metadata."""
    response = client.get("/api/v1/policies/POL-SEC-04")
    assert response.status_code == 200
    data = response.json()
    assert data["policy_id"] == "POL-SEC-04"
    assert "Patch Management" in data["title"]
    assert data["content_hash"].startswith("sha256:")
    assert data["policy_metadata"]["word_count"] > 0


def test_get_policy_not_found(client: TestClient):
    """Verify retrieving unknown policy returns 404."""
    response = client.get("/api/v1/policies/POL-UNKNOWN-99")
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"
