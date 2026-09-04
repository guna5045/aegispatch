"""SQLAlchemy ORM model for computed contextual risk assessments."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import CheckConstraint, DateTime, Float, ForeignKey, Index, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.base import Base

if TYPE_CHECKING:
    from src.database.models.vulnerability import VulnerabilityFinding


class RiskAssessment(Base):
    """Contextual risk evaluation result and auditable mathematical inputs for a finding."""

    __tablename__ = "risk_assessments"
    __table_args__ = (
        CheckConstraint(
            "environmental_risk_score >= 0.0 AND environmental_risk_score <= 100.0",
            name="ck_risk_assessment_ers_range",
        ),
        CheckConstraint(
            "control_multiplier >= 0.0 AND control_multiplier <= 1.0",
            name="ck_risk_assessment_multiplier_range",
        ),
        Index("ix_risk_finding_assessed", "finding_id", "assessed_at"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Unique assessment record identifier
    assessment_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Associated finding foreign key (NOT unique: supports historical recalculations)
    finding_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("vulnerability_findings.finding_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    cve_id: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    asset_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # Risk calculation components (B, T, E, R, M_control, ERS)
    base_score: Mapped[float] = mapped_column(Float, nullable=False)
    threat_score: Mapped[float] = mapped_column(Float, nullable=False)
    environmental_score: Mapped[float] = mapped_column(Float, nullable=False)
    raw_risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    control_multiplier: Mapped[float] = mapped_column(Float, nullable=False)
    environmental_risk_score: Mapped[float] = mapped_column(Float, index=True, nullable=False)

    # Triage decision and severity band
    risk_tier: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    decision: Mapped[str] = mapped_column(String(32), index=True, nullable=False)
    remediation_decision: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)

    # Explanatory and audit evidence
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_evidence: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)
    calculation_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Provenance metadata
    engine_version: Mapped[str] = mapped_column(String(64), default="1.0.0", nullable=False)
    assessed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
        nullable=False,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationship to parent finding
    finding: Mapped[VulnerabilityFinding] = relationship(
        "VulnerabilityFinding",
        back_populates="risk_assessments",
    )

    def __repr__(self) -> str:
        return f"<RiskAssessment(assessment_id='{self.assessment_id}', finding_id='{self.finding_id}', ers={self.environmental_risk_score}, decision='{self.decision}')>"
