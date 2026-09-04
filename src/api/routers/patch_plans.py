"""Patch remediation plan management and scheduling API router."""

from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.patch_plans import (
    PatchPlanCreate,
    PatchPlanItemCreate,
    PatchPlanItemRead,
    PatchPlanRead,
    PatchPlanUpdate,
)
from src.database.models.patch_plan import PatchPlan, PatchPlanItem
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/patch-plans", tags=["Patch Plans"])


@router.get(
    "",
    response_model=List[PatchPlanRead],
    summary="List All Patch Remediation Plans",
    description="Retrieve all persisted patch remediation plans along with scheduled item counts.",
)
def list_patch_plans(db: Session = Depends(get_db)) -> List[PatchPlanRead]:
    """Retrieve all patch plans."""
    plans = PersistenceService.list_patch_plans(db)
    result = []
    for plan in plans:
        # Eagerly load plan with items
        loaded_plan = PersistenceService.get_patch_plan(db, plan.plan_id) or plan
        items_count = len(loaded_plan.items)
        plan_dict = {col.name: getattr(loaded_plan, col.name) for col in loaded_plan.__table__.columns}
        plan_dict["items"] = [PatchPlanItemRead.model_validate(item) for item in loaded_plan.items]
        plan_dict["items_count"] = items_count
        result.append(PatchPlanRead(**plan_dict))
    return result


@router.get(
    "/{plan_id}",
    response_model=PatchPlanRead,
    summary="Get Patch Plan by Identifier",
    description="Retrieve a remediation plan with its ordered sequence of scheduled patch items.",
)
def get_patch_plan(plan_id: str, db: Session = Depends(get_db)) -> PatchPlanRead:
    """Retrieve single patch plan by domain identifier."""
    plan = PersistenceService.get_patch_plan(db, plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch plan '{plan_id}' not found.",
        )
    items_count = len(plan.items)
    plan_dict = {col.name: getattr(plan, col.name) for col in plan.__table__.columns}
    plan_dict["items"] = [PatchPlanItemRead.model_validate(item) for item in plan.items]
    plan_dict["items_count"] = items_count
    return PatchPlanRead(**plan_dict)


@router.post(
    "",
    response_model=PatchPlanRead,
    status_code=status.HTTP_201_CREATED,
    summary="Create New Patch Remediation Plan",
    description="Register an operational remediation plan specifying engineering maintenance capacity limits.",
)
def create_patch_plan(payload: PatchPlanCreate, db: Session = Depends(get_db)) -> PatchPlanRead:
    """Create a new patch plan."""
    existing = PersistenceService.get_patch_plan(db, payload.plan_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Patch plan '{payload.plan_id}' already exists.",
        )

    orm_plan = PatchPlan(
        plan_id=payload.plan_id,
        title=payload.title,
        status=payload.status,
        capacity_hours=payload.capacity_hours,
        total_estimated_hours=payload.total_estimated_hours or 0.0,
        expected_risk_reduction=payload.expected_risk_reduction or 0.0,
        notes=payload.notes,
    )
    created = PersistenceService.create_patch_plan(db, orm_plan)
    plan_dict = {col.name: getattr(created, col.name) for col in created.__table__.columns}
    plan_dict["items"] = []
    plan_dict["items_count"] = 0
    return PatchPlanRead(**plan_dict)


@router.post(
    "/{plan_id}/items",
    response_model=PatchPlanItemRead,
    status_code=status.HTTP_201_CREATED,
    summary="Add Scheduled Item to Patch Plan",
    description="Append a scheduled remediation action to an existing plan, validating finding existence and dependency rank.",
)
def add_item_to_patch_plan(
    plan_id: str,
    payload: PatchPlanItemCreate,
    db: Session = Depends(get_db),
) -> PatchPlanItemRead:
    """Schedule a remediation item inside an existing patch plan."""
    plan = PersistenceService.get_patch_plan(db, plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch plan '{plan_id}' not found.",
        )

    finding = PersistenceService.get_finding(db, payload.finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{payload.finding_id}' not found.",
        )

    # Check for duplicate finding in the same plan
    for existing_item in plan.items:
        if existing_item.finding_id == payload.finding_id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Finding '{payload.finding_id}' is already scheduled in plan '{plan_id}'.",
            )

    item = PatchPlanItem(
        item_id=payload.item_id or f"ITEM-{plan_id}-{payload.sequence_order:03d}",
        patch_plan_id=plan_id,
        finding_id=payload.finding_id,
        sequence_order=payload.sequence_order,
        estimated_hours=payload.estimated_hours,
        expected_risk_reduction=payload.expected_risk_reduction,
        priority_decision=payload.priority_decision,
        remediation_action=payload.remediation_action,
        rollback_plan=payload.rollback_plan,
        status=payload.status,
        dependencies=payload.dependencies or [],
    )
    created_item = PersistenceService.add_item_to_patch_plan(db, item)
    return PatchPlanItemRead.model_validate(created_item)


@router.patch(
    "/{plan_id}",
    response_model=PatchPlanRead,
    summary="Update Patch Plan Attributes",
    description="Update metadata, capacity limits, or approval lifecycle status of an existing remediation plan.",
)
def update_patch_plan(
    plan_id: str,
    payload: PatchPlanUpdate,
    db: Session = Depends(get_db),
) -> PatchPlanRead:
    """Update mutable attributes on a patch plan."""
    plan = PersistenceService.get_patch_plan(db, plan_id)
    if not plan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Patch plan '{plan_id}' not found.",
        )

    update_data = payload.model_dump(exclude_unset=True)
    for field_name, value in update_data.items():
        setattr(plan, field_name, value)

    updated = PersistenceService.update_patch_plan(db, plan)
    items_count = len(updated.items)
    plan_dict = {col.name: getattr(updated, col.name) for col in updated.__table__.columns}
    plan_dict["items"] = [PatchPlanItemRead.model_validate(item) for item in updated.items]
    plan_dict["items_count"] = items_count
    return PatchPlanRead(**plan_dict)
