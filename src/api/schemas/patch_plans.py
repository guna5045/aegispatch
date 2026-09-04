"""Patch remediation plan and scheduled item API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class PatchPlanItemCreate(BaseModel):
    """Payload to schedule a new remediation item within an existing patch plan."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., min_length=1, description="Target finding identifier to remediate")
    sequence_order: int = Field(..., ge=0, description="Execution sequence rank (lower executes earlier)")
    estimated_hours: float = Field(..., ge=0.0, description="Estimated engineering maintenance hours required")
    expected_risk_reduction: float = Field(..., ge=0.0, description="Projected ERS risk reduction achieved by applying patch")
    priority_decision: str = Field(default="SCHEDULED_PATCH", description="Action priority (e.g. IMMEDIATE_PATCH, SCHEDULED_PATCH)")
    remediation_action: str = Field(..., min_length=1, description="Specific patch or configuration instruction")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Safe recovery instructions and backup parameters")
    status: str = Field(default="PENDING", description="Remediation lifecycle state")
    dependencies: Optional[List[str]] = Field(default_factory=list, description="List of prerequisite item or package IDs")
    item_id: Optional[str] = Field(None, description="Optional custom item domain identifier")


class PatchPlanItemRead(BaseModel):
    """Read representation of a scheduled remediation action."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Database item primary key")
    item_id: Optional[str] = Field(None, description="Unique item domain identifier")
    patch_plan_id: str = Field(..., description="Parent patch plan domain identifier")
    finding_id: str = Field(..., description="Associated vulnerability finding identifier")
    sequence_order: int = Field(..., description="Scheduled sequence execution rank")
    estimated_hours: float = Field(..., description="Estimated effort in engineering hours")
    expected_risk_reduction: float = Field(..., description="Projected ERS reduction")
    priority_decision: str = Field(..., description="Operational priority band")
    remediation_action: str = Field(..., description="Remediation instructions")
    rollback_plan: Optional[Dict[str, Any]] = Field(None, description="Rollback strategy metadata")
    status: str = Field(..., description="Item status (e.g. PENDING, SCHEDULED, COMPLETED)")
    dependencies: Optional[List[str]] = Field(default_factory=list, description="Item dependency prerequisites")


class PatchPlanCreate(BaseModel):
    """Payload to create a new remediation patch plan."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str = Field(..., min_length=1, description="Unique patch plan domain identifier (e.g. PLAN-2026-001)")
    title: str = Field(..., min_length=1, max_length=255, description="Descriptive title of the patch plan")
    capacity_hours: float = Field(..., ge=0.0, description="Available engineering maintenance window capacity in hours")
    total_estimated_hours: float = Field(default=0.0, ge=0.0, description="Initial total estimated remediation effort")
    expected_risk_reduction: float = Field(default=0.0, ge=0.0, description="Initial total expected risk reduction")
    status: str = Field(default="DRAFT", description="Lifecycle approval status (e.g. DRAFT, APPROVED)")
    notes: Optional[str] = Field(None, description="Operational justifications and scope notes")


class PatchPlanUpdate(BaseModel):
    """Payload to update an existing patch remediation plan."""

    model_config = ConfigDict(extra="forbid")

    title: Optional[str] = Field(None, min_length=1, max_length=255)
    status: Optional[str] = Field(None)
    capacity_hours: Optional[float] = Field(None, ge=0.0)
    total_estimated_hours: Optional[float] = Field(None, ge=0.0)
    expected_risk_reduction: Optional[float] = Field(None, ge=0.0)
    notes: Optional[str] = Field(None)


class PatchPlanRead(BaseModel):
    """Read representation of a patch remediation plan with items."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Database plan primary key")
    plan_id: str = Field(..., description="Unique plan domain identifier")
    title: str = Field(..., description="Plan title")
    status: str = Field(..., description="Lifecycle status")
    capacity_hours: float = Field(..., description="Capacity limit in engineering hours")
    total_estimated_hours: float = Field(..., description="Aggregate estimated effort in hours")
    expected_risk_reduction: float = Field(..., description="Aggregate expected risk reduction")
    notes: Optional[str] = Field(None, description="Operational notes")
    approved_at: Optional[datetime] = Field(None, description="Timestamp of human approval")
    completed_at: Optional[datetime] = Field(None, description="Timestamp of plan completion")
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: Optional[datetime] = Field(None, description="Last update timestamp")
    items: List[PatchPlanItemRead] = Field(default_factory=list, description="Ordered sequence of remediation items")
    items_count: int = Field(0, description="Count of scheduled items in plan")
