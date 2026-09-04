"""Repository for patch remediation plans and scheduled actions."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from src.database.models.patch_plan import PatchPlan, PatchPlanItem


class PatchPlanRepository:
    """Data access repository for PatchPlan and PatchPlanItem ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[PatchPlan]:
        """Retrieve a patch plan by its primary key ID."""
        return self.session.get(PatchPlan, id)

    def get_by_plan_id(self, plan_id: str) -> Optional[PatchPlan]:
        """Retrieve a patch plan by its unique domain identifier (e.g., 'PLAN-2026-001')."""
        stmt = select(PatchPlan).where(PatchPlan.plan_id == plan_id)
        return self.session.scalars(stmt).first()

    def get_plan_with_items(self, plan_id: str) -> Optional[PatchPlan]:
        """Retrieve a patch plan with its ordered remediation items eagerly loaded."""
        stmt = (
            select(PatchPlan)
            .options(selectinload(PatchPlan.items))
            .where(PatchPlan.plan_id == plan_id)
        )
        return self.session.scalars(stmt).first()

    def list_all(self) -> List[PatchPlan]:
        """List all remediation plans sorted by plan_id ascending."""
        stmt = select(PatchPlan).order_by(PatchPlan.plan_id.asc())
        return list(self.session.scalars(stmt).all())

    def list_by_status(self, status: str) -> List[PatchPlan]:
        """List plans filtered by lifecycle approval status (DRAFT, APPROVED, etc.)."""
        stmt = (
            select(PatchPlan)
            .where(PatchPlan.status == status)
            .order_by(PatchPlan.plan_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def create(self, plan: PatchPlan) -> PatchPlan:
        """Persist a new patch plan to the session and flush."""
        self.session.add(plan)
        self.session.flush()
        self.session.refresh(plan)
        return plan

    def update(self, plan: PatchPlan) -> PatchPlan:
        """Flush changes to an existing plan in the session."""
        self.session.flush()
        self.session.refresh(plan)
        return plan

    def delete(self, plan: PatchPlan) -> bool:
        """Delete a plan and its cascaded items from the session and flush."""
        self.session.delete(plan)
        self.session.flush()
        return True

    def add_item(self, item: PatchPlanItem) -> PatchPlanItem:
        """Persist a new remediation item inside a patch plan and flush."""
        self.session.add(item)
        self.session.flush()
        self.session.refresh(item)
        return item

    def get_items(self, plan_id: str) -> List[PatchPlanItem]:
        """Retrieve all scheduled remediation items for a plan in strict execution sequence order."""
        stmt = (
            select(PatchPlanItem)
            .where(PatchPlanItem.patch_plan_id == plan_id)
            .order_by(PatchPlanItem.sequence_order.asc())
        )
        return list(self.session.scalars(stmt).all())

    def delete_item(self, item: PatchPlanItem) -> bool:
        """Delete an individual item from a patch plan."""
        self.session.delete(item)
        self.session.flush()
        return True
