"""SQLAlchemy ORM models for patch plans and scheduled remediation items."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.base import Base

if TYPE_CHECKING:
    from src.database.models.vulnerability import VulnerabilityFinding


class PatchPlan(Base):
    """Remediation plan scheduling patch actions within engineering capacity limits."""

    __tablename__ = "patch_plans"
    __table_args__ = (
        CheckConstraint("capacity_hours >= 0.0", name="ck_patch_plans_capacity_positive"),
        CheckConstraint("total_estimated_hours >= 0.0", name="ck_patch_plans_effort_positive"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Unique plan identifier (e.g., PLAN-2026-001)
    plan_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Descriptive and lifecycle state
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    status: Mapped[str] = mapped_column(String(64), index=True, default="DRAFT", nullable=False)

    # Resource metrics and expected outcomes
    capacity_hours: Mapped[float] = mapped_column(Float, nullable=False)
    total_estimated_hours: Mapped[float] = mapped_column(Float, nullable=False)
    expected_risk_reduction: Mapped[float] = mapped_column(Float, nullable=False)

    # Planning notes and justifications
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Approval and completion audit timestamps
    approved_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Ordered list of scheduled patch items
    items: Mapped[List[PatchPlanItem]] = relationship(
        "PatchPlanItem",
        back_populates="plan",
        cascade="all, delete-orphan",
        order_by="PatchPlanItem.sequence_order",
    )

    def __repr__(self) -> str:
        return f"<PatchPlan(plan_id='{self.plan_id}', title='{self.title}', status='{self.status}', capacity={self.capacity_hours}h)>"


class PatchPlanItem(Base):
    """Specific scheduled remediation action within a patch plan."""

    __tablename__ = "patch_plan_items"
    __table_args__ = (
        UniqueConstraint("patch_plan_id", "finding_id", name="uq_patch_plan_item_plan_finding"),
        CheckConstraint("sequence_order >= 0", name="ck_patch_plan_items_sequence_positive"),
        CheckConstraint("estimated_hours >= 0.0", name="ck_patch_plan_items_hours_positive"),
    )

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Optional item-level identifier
    item_id: Mapped[Optional[str]] = mapped_column(String(64), unique=True, index=True, nullable=True)

    # Associations
    patch_plan_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("patch_plans.plan_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )
    finding_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("vulnerability_findings.finding_id", ondelete="RESTRICT"),
        index=True,
        nullable=False,
    )

    # Scheduling metrics
    sequence_order: Mapped[int] = mapped_column(Integer, index=True, nullable=False)
    estimated_hours: Mapped[float] = mapped_column(Float, nullable=False)
    expected_risk_reduction: Mapped[float] = mapped_column(Float, nullable=False)
    priority_decision: Mapped[str] = mapped_column(String(32), nullable=False)

    # Execution specifications
    remediation_action: Mapped[str] = mapped_column(Text, nullable=False)
    rollback_plan: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(64), default="PENDING", nullable=False)
    dependencies: Mapped[Optional[List[str]]] = mapped_column(JSON, nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    # Relationships
    plan: Mapped[PatchPlan] = relationship("PatchPlan", back_populates="items")
    finding: Mapped[VulnerabilityFinding] = relationship("VulnerabilityFinding", back_populates="patch_plan_items")

    def __repr__(self) -> str:
        return f"<PatchPlanItem(plan='{self.patch_plan_id}', finding='{self.finding_id}', seq={self.sequence_order}, hours={self.estimated_hours})>"
