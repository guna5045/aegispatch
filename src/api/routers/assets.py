"""Enterprise asset and security controls API router."""

from __future__ import annotations

import math
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.assets import AssetDetail, AssetRead, ControlRead
from src.api.schemas.common import PaginatedResponse, PaginationMeta
from src.api.schemas.vulnerabilities import FindingRead
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/assets", tags=["Assets"])


@router.get(
    "",
    response_model=PaginatedResponse[AssetRead],
    summary="List and Filter Enterprise Assets",
    description="Query enterprise assets with optional filters on environment, criticality, and network exposure.",
)
def list_assets(
    environment: Optional[str] = Query(None, description="Filter by environment (e.g. PRODUCTION, STAGING)"),
    criticality: Optional[str] = Query(None, description="Filter by criticality (e.g. CRITICAL, HIGH)"),
    network_exposure: Optional[str] = Query(None, description="Filter by exposure (e.g. INTERNET_FACING, INTERNAL)"),
    page: int = Query(1, ge=1, description="1-indexed page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: Session = Depends(get_db),
) -> PaginatedResponse[AssetRead]:
    """Retrieve paginated assets matching optional query filters."""
    items, total = PersistenceService.filter_assets(
        session=db,
        environment=environment,
        criticality=criticality,
        network_exposure=network_exposure,
        page=page,
        page_size=page_size,
    )
    total_pages = math.ceil(total / page_size) if total > 0 else 0

    return PaginatedResponse[AssetRead](
        items=[AssetRead.model_validate(item) for item in items],
        pagination=PaginationMeta(
            page=page,
            page_size=page_size,
            total_items=total,
            total_pages=total_pages,
        ),
    )


@router.get(
    "/{asset_id}",
    response_model=AssetDetail,
    summary="Get Asset by Identifier",
    description="Retrieve deep asset configuration, active compensating controls, and finding statistics.",
)
def get_asset(asset_id: str, db: Session = Depends(get_db)) -> AssetDetail:
    """Retrieve details for a single asset by domain identifier."""
    asset = PersistenceService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )

    controls = PersistenceService.list_controls_for_asset(db, asset_id)
    findings = PersistenceService.list_findings_for_asset(db, asset_id)

    control_models = [ControlRead.model_validate(c) for c in controls]
    asset_dict = {col.name: getattr(asset, col.name) for col in asset.__table__.columns}
    asset_dict["controls"] = control_models
    asset_dict["findings_count"] = len(findings)

    return AssetDetail(**asset_dict)


@router.get(
    "/{asset_id}/findings",
    response_model=List[FindingRead],
    summary="List Findings for Asset",
    description="Retrieve all vulnerability scan findings identified on the specified enterprise asset.",
)
def get_asset_findings(asset_id: str, db: Session = Depends(get_db)) -> List[FindingRead]:
    """List all findings mapped to an asset."""
    asset = PersistenceService.get_asset(db, asset_id)
    if not asset:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset '{asset_id}' not found.",
        )

    findings = PersistenceService.list_findings_for_asset(db, asset_id)
    return [FindingRead.model_validate(f) for f in findings]
