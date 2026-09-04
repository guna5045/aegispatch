"""Tests for API health and root metadata endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_api_root_endpoint(client: TestClient):
    """Verify GET / returns basic application information and documentation link."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app_name"] == "AegisPatch"
    assert "version" in data["app_version"] or len(data["app_version"]) > 0
    assert data["docs_url"] == "/docs"
    assert data["api_prefix"] == "/api/v1"


def test_health_check_endpoint_healthy(client: TestClient):
    """Verify GET /api/v1/health returns 200 with operational database connectivity."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["database"] == "healthy"
    assert data["app_name"] == "AegisPatch"
