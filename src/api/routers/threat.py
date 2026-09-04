"""Threat intelligence observation telemetry API router (Offline / Stored Only)."""

from __future__ import annotations

from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from src.api.dependencies import get_db
from src.api.schemas.threat import ThreatObservationRead
from src.services.persistence_service import PersistenceService

router = APIRouter(prefix="/threat-intelligence", tags=["Threat Intelligence"])


@router.get(
    "/{cve_id}",
    response_model=List[ThreatObservationRead],
    summary="Get Stored Threat Intelligence Observations for CVE",
    description="Retrieve locally persisted threat intelligence observations for a CVE. Operates strictly offline without external network calls.",
)
def get_threat_observations(cve_id: str, db: Session = Depends(get_db)) -> List[ThreatObservationRead]:
    """Retrieve locally stored exploit observations and EPSS telemetry for a CVE."""
    observations = PersistenceService.get_threat_observations_for_cve(db, cve_id)
    return [ThreatObservationRead.model_validate(obs) for obs in observations]
