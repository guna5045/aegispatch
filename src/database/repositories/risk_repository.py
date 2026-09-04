"""Repository for contextual risk assessment evaluations."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models.risk import RiskAssessment


class RiskAssessmentRepository:
    """Data access repository for RiskAssessment ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[RiskAssessment]:
        """Retrieve an assessment by its primary key ID."""
        return self.session.get(RiskAssessment, id)

    def get_by_assessment_id(self, assessment_id: str) -> Optional[RiskAssessment]:
        """Retrieve an assessment by its unique domain identifier (e.g., 'ASSESS-001')."""
        stmt = select(RiskAssessment).where(RiskAssessment.assessment_id == assessment_id)
        return self.session.scalars(stmt).first()

    def list_by_finding(self, finding_id: str) -> List[RiskAssessment]:
        """List all historical risk evaluations for a finding, latest first."""
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.finding_id == finding_id)
            .order_by(RiskAssessment.assessed_at.desc(), RiskAssessment.id.desc())
        )
        return list(self.session.scalars(stmt).all())

    def get_latest_for_finding(self, finding_id: str) -> Optional[RiskAssessment]:
        """Retrieve the most recent contextual risk assessment computed for a finding."""
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.finding_id == finding_id)
            .order_by(RiskAssessment.assessed_at.desc(), RiskAssessment.id.desc())
            .limit(1)
        )
        return self.session.scalars(stmt).first()

    def get_by_decision(self, decision: str) -> List[RiskAssessment]:
        """List assessments matching a specific Aegis decision band (ACT, ATTEND, PLAN, TRACK)."""
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.decision == decision)
            .order_by(
                RiskAssessment.environmental_risk_score.desc(),
                RiskAssessment.assessed_at.desc(),
                RiskAssessment.id.desc(),
            )
        )
        return list(self.session.scalars(stmt).all())

    def get_by_risk_tier(self, risk_tier: str) -> List[RiskAssessment]:
        """List assessments matching a risk tier (CRITICAL, HIGH, MEDIUM, LOW)."""
        stmt = (
            select(RiskAssessment)
            .where(RiskAssessment.risk_tier == risk_tier)
            .order_by(
                RiskAssessment.environmental_risk_score.desc(),
                RiskAssessment.assessed_at.desc(),
                RiskAssessment.id.desc(),
            )
        )
        return list(self.session.scalars(stmt).all())

    def list_highest_risk(self, limit: int = 10) -> List[RiskAssessment]:
        """List top findings ordered by Environmental Risk Score (ERS) descending."""
        stmt = (
            select(RiskAssessment)
            .order_by(
                RiskAssessment.environmental_risk_score.desc(),
                RiskAssessment.assessed_at.desc(),
                RiskAssessment.id.desc(),
            )
            .limit(limit)
        )
        return list(self.session.scalars(stmt).all())

    def filter_highest_risk(
        self,
        decision: Optional[str] = None,
        risk_tier: Optional[str] = None,
        limit: int = 10,
    ) -> List[RiskAssessment]:
        """List highest-risk evaluations filtered by decision or risk tier, ordered by ERS descending."""
        stmt = select(RiskAssessment)
        if decision:
            stmt = stmt.where(RiskAssessment.decision == decision)
        if risk_tier:
            stmt = stmt.where(RiskAssessment.risk_tier == risk_tier)
        stmt = stmt.order_by(
            RiskAssessment.environmental_risk_score.desc(),
            RiskAssessment.assessed_at.desc(),
            RiskAssessment.id.desc(),
        ).limit(limit)
        return list(self.session.scalars(stmt).all())

    def create(self, assessment: RiskAssessment) -> RiskAssessment:
        """Persist a new computed risk assessment to the session and flush."""
        self.session.add(assessment)
        self.session.flush()
        self.session.refresh(assessment)
        return assessment

    def update(self, assessment: RiskAssessment) -> RiskAssessment:
        """Flush changes to an existing risk assessment in the session."""
        self.session.flush()
        self.session.refresh(assessment)
        return assessment

    def delete(self, assessment: RiskAssessment) -> bool:
        """Delete an assessment from the session and flush."""
        self.session.delete(assessment)
        self.session.flush()
        return True
