"""SQLAlchemy ORM model for threat intelligence observations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import Boolean, CheckConstraint, DateTime, Float, Index, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base


class ThreatIntelligenceObservation(Base):
    """Observed threat intelligence signals and exploit telemetry for a CVE."""

    __tablename__ = "threat_intelligence_observations"
    __table_args__ = (
        CheckConstraint(
            "epss_score IS NULL OR (epss_score >= 0.0 AND epss_score <= 1.0)",
            name="ck_threat_epss_range",
        ),
        Index("ix_threat_cve_observed", "cve_id", "observed_at"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Optional unique observation identifier
    observation_id: Mapped[Optional[str]] = mapped_column(
        String(64),
        unique=True,
        index=True,
        nullable=True,
    )

    # Target CVE identifier (multiple observations allowed per CVE over time)
    cve_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)

    # Provenance source (e.g., CISA KEV, FIRST EPSS, ExploitDB)
    source: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    observed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )

    # CISA KEV telemetry
    is_cisa_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    cisa_kev_date_added: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    cisa_kev_due_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # EPSS metrics
    epss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    epss_percentile: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Exploit availability and weaponization
    exploit_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    exploit_maturity: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    confidence: Mapped[str] = mapped_column(String(32), default="HIGH", nullable=False)

    # Structured provider evidence payload
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    source_reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Audit timestamp
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<ThreatIntelligenceObservation(cve='{self.cve_id}', source='{self.source}', kev={self.is_cisa_kev}, epss={self.epss_score})>"
