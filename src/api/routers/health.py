"""Health and readiness diagnostic API router."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from config.constants import APP_NAME, APP_VERSION
from src.api.dependencies import get_db
from src.api.schemas.common import HealthResponse
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/health", tags=["Health"])


@router.get(
    "",
    response_model=HealthResponse,
    summary="System and Database Connectivity Health Check",
    description="Reports the operational status of the Aegis Patch API and checks active database connectivity via SELECT 1.",
)
def check_health(db: Session = Depends(get_db)) -> JSONResponse:
    """Check connectivity to persistent storage and return operational health."""
    db_healthy = PersistenceService.check_health(engine=db.get_bind())
    payload = HealthResponse(
        status="healthy" if db_healthy else "degraded",
        app_name=APP_NAME,
        app_version=APP_VERSION,
        database="healthy" if db_healthy else "unavailable",
    )
    status_code = status.HTTP_200_OK if db_healthy else status.HTTP_503_SERVICE_UNAVAILABLE
    return JSONResponse(status_code=status_code, content=payload.model_dump())
