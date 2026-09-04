"""Repository for threat intelligence observations and exploit telemetry."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models.threat import ThreatIntelligenceObservation


class ThreatIntelligenceRepository:
    """Data access repository for ThreatIntelligenceObservation ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[ThreatIntelligenceObservation]:
        """Retrieve an observation by its primary key ID."""
        return self.session.get(ThreatIntelligenceObservation, id)

    def list_by_cve(self, cve_id: str) -> List[ThreatIntelligenceObservation]:
        """List all historical observations for a CVE, newest first."""
        stmt = (
            select(ThreatIntelligenceObservation)
            .where(ThreatIntelligenceObservation.cve_id == cve_id)
            .order_by(
                ThreatIntelligenceObservation.observed_at.desc(),
                ThreatIntelligenceObservation.id.desc(),
            )
        )
        return list(self.session.scalars(stmt).all())

    def list_by_source(self, source: str) -> List[ThreatIntelligenceObservation]:
        """List observations by provider or intelligence source."""
        stmt = (
            select(ThreatIntelligenceObservation)
            .where(ThreatIntelligenceObservation.source == source)
            .order_by(
                ThreatIntelligenceObservation.observed_at.desc(),
                ThreatIntelligenceObservation.id.desc(),
            )
        )
        return list(self.session.scalars(stmt).all())

    def get_latest_for_cve(self, cve_id: str) -> Optional[ThreatIntelligenceObservation]:
        """Retrieve the most recent observation for a CVE across all sources."""
        stmt = (
            select(ThreatIntelligenceObservation)
            .where(ThreatIntelligenceObservation.cve_id == cve_id)
            .order_by(
                ThreatIntelligenceObservation.observed_at.desc(),
                ThreatIntelligenceObservation.id.desc(),
            )
            .limit(1)
        )
        return self.session.scalars(stmt).first()

    def get_latest_by_cve_and_source(
        self, cve_id: str, source: str
    ) -> Optional[ThreatIntelligenceObservation]:
        """Retrieve the most recent observation for a CVE from a specific source."""
        stmt = (
            select(ThreatIntelligenceObservation)
            .where(
                ThreatIntelligenceObservation.cve_id == cve_id,
                ThreatIntelligenceObservation.source == source,
            )
            .order_by(
                ThreatIntelligenceObservation.observed_at.desc(),
                ThreatIntelligenceObservation.id.desc(),
            )
            .limit(1)
        )
        return self.session.scalars(stmt).first()

    def list_recent(self, limit: int = 50) -> List[ThreatIntelligenceObservation]:
        """List the most recent threat observations across all CVEs."""
        stmt = (
            select(ThreatIntelligenceObservation)
            .order_by(
                ThreatIntelligenceObservation.observed_at.desc(),
                ThreatIntelligenceObservation.id.desc(),
            )
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def create(
        self, observation: ThreatIntelligenceObservation
    ) -> ThreatIntelligenceObservation:
        """Persist a new threat intelligence observation to the session and flush."""
        self.session.add(observation)
        self.session.flush()
        self.session.refresh(observation)
        return observation

    def delete(self, observation: ThreatIntelligenceObservation) -> bool:
        """Delete an observation from the session and flush."""
        self.session.delete(observation)
        self.session.flush()
        return True
