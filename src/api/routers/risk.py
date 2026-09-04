"""Contextual risk assessment and evaluation audit trail API router."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.risk import RiskAssessmentRead
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/risk", tags=["Risk"])


@router.get(
    "/highest",
    response_model=List[RiskAssessmentRead],
    summary="List Highest-Risk Vulnerability Assessments",
    description="Retrieve top persisted contextual risk assessments sorted by Environmental Risk Score (ERS) descending.",
)
def list_highest_risk_assessments(
    decision: Optional[str] = Query(None, description="Filter by decision band (ACT, ATTEND, PLAN, TRACK)"),
    risk_tier: Optional[str] = Query(None, description="Filter by risk tier (CRITICAL, HIGH, MEDIUM, LOW)"),
    limit: int = Query(10, ge=1, le=100, description="Maximum number of records to return"),
    db: Session = Depends(get_db),
) -> List[RiskAssessmentRead]:
    """Retrieve highest-risk assessments ordered by ERS descending."""
    assessments = PersistenceService.filter_highest_risks(
        session=db,
        decision=decision,
        risk_tier=risk_tier,
        limit=limit,
    )
    return [RiskAssessmentRead.model_validate(a) for a in assessments]


@router.get(
    "/{finding_id}/history",
    response_model=List[RiskAssessmentRead],
    summary="Get Historical Risk Evaluations for Finding",
    description="Retrieve all historical risk assessments computed for a finding in newest-first chronological order.",
)
def get_finding_risk_history(finding_id: str, db: Session = Depends(get_db)) -> List[RiskAssessmentRead]:
    """Retrieve historical risk assessments preserving mathematical audit trail."""
    finding = PersistenceService.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )

    history = PersistenceService.list_risk_assessments_for_finding(db, finding_id)
    return [RiskAssessmentRead.model_validate(a) for a in history]
