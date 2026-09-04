"""Tests for patch remediation plan API endpoints."""

from __future__ import annotations

from fastapi.testclient import TestClient


def test_create_and_get_patch_plan(client: TestClient):
    """Verify creating a patch plan via POST and retrieving it via GET."""
    payload = {
        "plan_id": "PLAN-API-TEST-001",
        "title": "Q1 Edge Gateway Remediation",
        "capacity_hours": 30.0,
        "notes": "FastAPI integration test plan.",
    }
    response = client.post("/api/v1/patch-plans", json=payload)
    assert response.status_code == 201
    created = response.json()
    assert created["plan_id"] == "PLAN-API-TEST-001"
    assert created["capacity_hours"] == 30.0
    assert created["status"] == "DRAFT"

    # Retrieve
    get_res = client.get("/api/v1/patch-plans/PLAN-API-TEST-001")
    assert get_res.status_code == 200
    plan_data = get_res.json()
    assert plan_data["title"] == "Q1 Edge Gateway Remediation"
    assert plan_data["items_count"] == 0


def test_create_duplicate_patch_plan_conflict(client: TestClient):
    """Verify creating a plan with an existing plan_id returns 409 Conflict."""
    payload = {
        "plan_id": "PLAN-API-TEST-001",
        "title": "Duplicate Plan Attempt",
        "capacity_hours": 20.0,
    }
    response = client.post("/api/v1/patch-plans", json=payload)
    assert response.status_code == 409
    data = response.json()
    assert data["error"]["code"] == "CONFLICT"


def test_add_item_to_patch_plan_and_sequence_ordering(client: TestClient):
    """Verify adding items to plan preserves execution sequence ordering and rollback info."""
    item1 = {
        "finding_id": "FINDING-001",
        "sequence_order": 1,
        "estimated_hours": 4.5,
        "expected_risk_reduction": 35.0,
        "priority_decision": "IMMEDIATE_PATCH",
        "remediation_action": "Apply vendor security hotfix",
        "rollback_plan": {"backup": "snap-1", "command": "rollback.sh"},
    }
    res1 = client.post("/api/v1/patch-plans/PLAN-API-TEST-001/items", json=item1)
    assert res1.status_code == 201
    item1_data = res1.json()
    assert item1_data["sequence_order"] == 1
    assert item1_data["rollback_plan"]["backup"] == "snap-1"

    item2 = {
        "finding_id": "FINDING-002",
        "sequence_order": 2,
        "estimated_hours": 8.0,
        "expected_risk_reduction": 20.0,
        "priority_decision": "SCHEDULED_PATCH",
        "remediation_action": "Upgrade component",
        "dependencies": [item1_data["item_id"]],
    }
    res2 = client.post("/api/v1/patch-plans/PLAN-API-TEST-001/items", json=item2)
    assert res2.status_code == 201

    # Verify plan now lists 2 ordered items
    plan_res = client.get("/api/v1/patch-plans/PLAN-API-TEST-001")
    assert plan_res.status_code == 200
    plan_data = plan_res.json()
    assert plan_data["items_count"] == 2
    assert plan_data["items"][0]["sequence_order"] == 1
    assert plan_data["items"][1]["sequence_order"] == 2


def test_add_item_invalid_finding_rejected(client: TestClient):
    """Verify scheduling an unknown finding returns 404."""
    item_payload = {
        "finding_id": "FINDING-NONEXISTENT",
        "sequence_order": 3,
        "estimated_hours": 2.0,
        "expected_risk_reduction": 10.0,
        "priority_decision": "SCHEDULED_PATCH",
        "remediation_action": "Invalid test",
    }
    response = client.post("/api/v1/patch-plans/PLAN-API-TEST-001/items", json=item_payload)
    assert response.status_code == 404
    data = response.json()
    assert data["error"]["code"] == "NOT_FOUND"


def test_add_duplicate_finding_in_same_plan_rejected(client: TestClient):
    """Verify adding the same finding twice to one plan returns 409 Conflict."""
    duplicate_item = {
        "finding_id": "FINDING-001",
        "sequence_order": 3,
        "estimated_hours": 1.0,
        "expected_risk_reduction": 5.0,
        "priority_decision": "SCHEDULED_PATCH",
        "remediation_action": "Duplicate test",
    }
    response = client.post("/api/v1/patch-plans/PLAN-API-TEST-001/items", json=duplicate_item)
    assert response.status_code == 409
    data = response.json()
    assert data["error"]["code"] == "CONFLICT"


def test_same_finding_can_exist_in_different_plans(client: TestClient):
    """Verify database permits the same finding to be referenced in distinct plans."""
    # Create second plan
    plan2_payload = {
        "plan_id": "PLAN-API-TEST-002",
        "title": "Alternative Remediation Plan",
        "capacity_hours": 50.0,
    }
    client.post("/api/v1/patch-plans", json=plan2_payload)

    # Schedule FINDING-001 in second plan
    item_payload = {
        "finding_id": "FINDING-001",
        "sequence_order": 1,
        "estimated_hours": 4.5,
        "expected_risk_reduction": 35.0,
        "priority_decision": "IMMEDIATE_PATCH",
        "remediation_action": "Patch in second plan",
    }
    res = client.post("/api/v1/patch-plans/PLAN-API-TEST-002/items", json=item_payload)
    assert res.status_code == 201


def test_patch_plan_update(client: TestClient):
    """Verify modifying mutable fields of a patch plan via PATCH."""
    update_payload = {
        "title": "Updated Q1 Edge Sprint",
        "status": "APPROVED",
        "capacity_hours": 35.0,
    }
    response = client.patch("/api/v1/patch-plans/PLAN-API-TEST-001", json=update_payload)
    assert response.status_code == 200
    data = response.json()
    assert data["title"] == "Updated Q1 Edge Sprint"
    assert data["status"] == "APPROVED"
    assert data["capacity_hours"] == 35.0
