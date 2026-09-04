"""Repository for compensating and security controls."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models.control import SecurityControl


class ControlRepository:
    """Data access repository for SecurityControl ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[SecurityControl]:
        """Retrieve a control by its primary key ID."""
        return self.session.get(SecurityControl, id)

    def list_all(self) -> List[SecurityControl]:
        """List all security controls, sorted by id ascending."""
        stmt = select(SecurityControl).order_by(SecurityControl.id.asc())
        return list(self.session.scalars(stmt).all())

    def list_by_asset(self, asset_id: str) -> List[SecurityControl]:
        """List all controls configured on an asset, sorted by control_id ascending."""
        stmt = (
            select(SecurityControl)
            .where(SecurityControl.asset_id == asset_id)
            .order_by(SecurityControl.control_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def list_active_by_asset(self, asset_id: str) -> List[SecurityControl]:
        """List only operational active controls configured on an asset."""
        stmt = (
            select(SecurityControl)
            .where(
                SecurityControl.asset_id == asset_id,
                SecurityControl.active.is_(True),
            )
            .order_by(SecurityControl.control_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def create(self, control: SecurityControl) -> SecurityControl:
        """Persist a new security control to the session and flush."""
        self.session.add(control)
        self.session.flush()
        self.session.refresh(control)
        return control

    def update(self, control: SecurityControl) -> SecurityControl:
        """Flush changes to an existing control in the session."""
        self.session.flush()
        self.session.refresh(control)
        return control

    def delete(self, control: SecurityControl) -> bool:
        """Delete a control from the session and flush."""
        self.session.delete(control)
        self.session.flush()
        return True
