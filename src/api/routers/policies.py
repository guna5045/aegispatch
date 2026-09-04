"""Organizational policy document API router."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.policies import PolicyDetail, PolicyRead
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/policies", tags=["Policies"])


@router.get(
    "",
    response_model=List[PolicyRead],
    summary="List Organizational Security Policies",
    description="Retrieve ingested security and remediation governance policies, optionally filtered by status or policy type.",
)
def list_policies(
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status (e.g. ACTIVE, DRAFT)"),
    policy_type: Optional[str] = Query(None, description="Filter by classification type (e.g. SECURITY, IT_GOVERNANCE)"),
    db: Session = Depends(get_db),
) -> List[PolicyRead]:
    """Retrieve all ingested policies matching optional filters."""
    policies = PersistenceService.filter_policies(
        session=db,
        status=status_filter,
        policy_type=policy_type,
    )
    return [PolicyRead.model_validate(p) for p in policies]


@router.get(
    "/{policy_id}",
    response_model=PolicyDetail,
    summary="Get Policy Document by Identifier",
    description="Retrieve full metadata, SHA-256 digest, and classification details for a security policy.",
)
def get_policy(policy_id: str, db: Session = Depends(get_db)) -> PolicyDetail:
    """Retrieve policy document by domain identifier."""
    policy = PersistenceService.get_policy(db, policy_id)
    if not policy:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Policy document '{policy_id}' not found.",
        )
    return PolicyDetail.model_validate(policy)
