"""Tests for API error handling, validation, and security invariants."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_validation_error_format(client: TestClient):
    """Verify invalid payload returns structured 422 error without stack trace."""
    # Attempt creating patch plan with negative capacity
    invalid_payload = {
        "plan_id": "PLAN-INVALID-01",
        "title": "Invalid Plan",
        "capacity_hours": -10.0,
    }
    response = client.post("/api/v1/patch-plans", json=invalid_payload)
    assert response.status_code == 422
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "VALIDATION_ERROR"
    assert "validation failed" in data["error"]["message"]
    assert isinstance(data["error"]["details"], list)


def test_not_found_error_format(client: TestClient):
    """Verify missing entity returns structured 404 error."""
    response = client.get("/api/v1/assets/UNKNOWN-ASSET-ID")
    assert response.status_code == 404
    data = response.json()
    assert "error" in data
    assert data["error"]["code"] == "NOT_FOUND"
    assert "UNKNOWN-ASSET-ID" in data["error"]["message"]


def test_cors_configuration_no_wildcard(client: TestClient):
    """Verify CORS middleware headers are restrictive and do not use wildcard with credentials."""
    response = client.options(
        "/api/v1/health",
        headers={
            "Origin": "http://evil-attacker.com",
            "Access-Control-Request-Method": "GET",
        },
    )
    # Evil origin must not receive Access-Control-Allow-Origin: * with credentials
    allow_origin = response.headers.get("access-control-allow-origin")
    assert allow_origin != "*"
    assert allow_origin != "http://evil-attacker.com"


def test_pagination_bounds_validation(client: TestClient):
    """Verify pagination parameter bounds are strictly enforced."""
    # page_size > 100 should be rejected by validation
    response = client.get("/api/v1/assets?page_size=500")
    assert response.status_code == 422
    data = response.json()
    assert data["error"]["code"] == "VALIDATION_ERROR"

    # page < 1 should be rejected
    response2 = client.get("/api/v1/assets?page=0")
    assert response2.status_code == 422
    data2 = response2.json()
    assert data2["error"]["code"] == "VALIDATION_ERROR"
