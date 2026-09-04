"""Policy document API response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, Optional, Union
from pydantic import BaseModel, ConfigDict, Field


class PolicyRead(BaseModel):
    """Summary representation of an organizational security policy document."""

    model_config = ConfigDict(from_attributes=True)

    policy_id: str = Field(..., description="Unique policy identifier (e.g. POL-SEC-04)")
    title: str = Field(..., description="Full policy document title")
    policy_type: str = Field(..., description="Categorical classification of policy")
    version: str = Field(..., description="Document revision version string")
    status: str = Field(..., description="Lifecycle status (e.g. ACTIVE, DRAFT)")
    effective_date: Optional[Union[datetime, str]] = Field(None, description="Date policy came into force")
    source_path: Optional[str] = Field(None, description="Repository filesystem relative path")


class PolicyDetail(PolicyRead):
    """Detailed policy payload including metadata attributes."""

    content_hash: Optional[str] = Field(None, description="SHA-256 integrity digest of source content")
    policy_metadata: Optional[Dict[str, Any]] = Field(None, description="Structured policy section and metrics metadata")
