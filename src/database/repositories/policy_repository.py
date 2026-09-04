"""Repository for organizational security policy documents."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models.policy import PolicyDocument


class PolicyRepository:
    """Data access repository for PolicyDocument ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[PolicyDocument]:
        """Retrieve a policy by its primary key ID."""
        return self.session.get(PolicyDocument, id)

    def get_by_policy_id(self, policy_id: str) -> Optional[PolicyDocument]:
        """Retrieve a policy by its unique domain identifier (e.g., 'POL-SEC-04')."""
        stmt = select(PolicyDocument).where(PolicyDocument.policy_id == policy_id)
        return self.session.scalars(stmt).first()

    def list_all(self) -> List[PolicyDocument]:
        """List all policy documents sorted by policy_id ascending."""
        stmt = select(PolicyDocument).order_by(PolicyDocument.policy_id.asc())
        return list(self.session.scalars(stmt).all())

    def list_active(self) -> List[PolicyDocument]:
        """List all active operational security policies."""
        stmt = (
            select(PolicyDocument)
            .where(PolicyDocument.status == "ACTIVE")
            .order_by(PolicyDocument.policy_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def list_by_type(self, policy_type: str) -> List[PolicyDocument]:
        """List policy documents matching a category or classification type."""
        stmt = (
            select(PolicyDocument)
            .where(PolicyDocument.policy_type == policy_type)
            .order_by(PolicyDocument.policy_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def filter_policies(
        self,
        status: Optional[str] = None,
        policy_type: Optional[str] = None,
    ) -> List[PolicyDocument]:
        """List policies filtered by status and/or classification type, sorted by policy_id."""
        stmt = select(PolicyDocument)
        if status:
            stmt = stmt.where(PolicyDocument.status == status)
        if policy_type:
            stmt = stmt.where(PolicyDocument.policy_type == policy_type)
        stmt = stmt.order_by(PolicyDocument.policy_id.asc())
        return list(self.session.scalars(stmt).all())

    def create(self, policy: PolicyDocument) -> PolicyDocument:
        """Persist a new policy document to the session and flush."""
        self.session.add(policy)
        self.session.flush()
        self.session.refresh(policy)
        return policy

    def update(self, policy: PolicyDocument) -> PolicyDocument:
        """Flush changes to an existing policy in the session."""
        self.session.flush()
        self.session.refresh(policy)
        return policy

    def delete(self, policy: PolicyDocument) -> bool:
        """Delete a policy document from the session and flush."""
        self.session.delete(policy)
        self.session.flush()
        return True
