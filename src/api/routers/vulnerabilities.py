"""Vulnerability scanner findings API router."""

from __future__ import annotations

import math
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.common import PaginatedResponse, PaginationMeta
from src.api.schemas.risk import RiskAssessmentRead
from src.api.schemas.vulnerabilities import FindingDetail, FindingRead
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get(
    "",
    response_model=PaginatedResponse[FindingRead],
    summary="List and Filter Vulnerability Findings",
    description="Search and filter vulnerability findings by free text, severity, triage status, or affected asset.",
)
def list_vulnerabilities(
    search: Optional[str] = Query(None, description="Free text search across CVE, title, package, and identifiers"),
    severity: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by lifecycle triage status"),
    asset_id: Optional[str] = Query(None, description="Filter by affected asset identifier"),
    cve_id: Optional[str] = Query(None, description="Filter by exact CVE identifier"),
    page: int = Query(1, ge=1, description="1-indexed page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[FindingRead]:
    """Retrieve paginated vulnerability findings matching query parameters."""
    items, total = PersistenceService.filter_findings(
        session=db,
        query=search,
        severity=severity,
        status=status_filter,
        asset_id=asset_id,
        cve_id=cve_id,
        page=page,
        page_size=page_size,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[FindingRead](
        items=[FindingRead.model_validate(item) for item in items],
        pagination=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total,
            total_pages=total_pages,
        ),
    )


@router.get(
    "/{finding_id}",
    response_model=FindingDetail,
    summary="Get Vulnerability Finding by Identifier",
    description="Retrieve deep technical description, scanner origin, and advisory reference links for a finding.",
)
def get_vulnerability(finding_id: str, db: Session = Depends(get_db)) -> FindingDetail:
    """Retrieve single vulnerability finding by domain identifier."""
    finding = PersistenceService.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )
    return FindingDetail.model_validate(finding)


@router.get(
    "/{finding_id}/risk",
    response_model=RiskAssessmentRead,
    summary="Get Latest Persisted Risk Assessment for Finding",
    description="Retrieve the latest auditable Environmental Risk Score (ERS) and triage decision persisted for this finding.",
)
def get_vulnerability_risk(finding_id: str, db: Session = Depends(get_db)) -> RiskAssessmentRead:
    """Retrieve the latest persisted risk evaluation for a finding."""
    finding = PersistenceService.get_finding(db, finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability finding '{finding_id}' not found.",
        )

    assessment = PersistenceService.get_latest_risk_assessment(db, finding_id)
    if not assessment:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No risk assessment has been persisted for finding '{finding_id}'.",
        )
    return RiskAssessmentRead.model_validate(assessment)
