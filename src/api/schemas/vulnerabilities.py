"""Vulnerability finding API response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class FindingRead(BaseModel):
    """Summary representation of a scanner vulnerability finding."""

    model_config = ConfigDict(from_attributes=True)

    finding_id: str = Field(..., description="Unique scanner finding identifier (e.g. FINDING-001)")
    cve_id: str = Field(..., description="Standard CVE identifier (e.g. CVE-2023-38545)")
    title: str = Field(..., description="Brief vulnerability title")
    severity: str = Field(..., description="Vulnerability severity rating")
    cvss_score: float = Field(..., description="CVSS base score (0.0 - 10.0)")
    affected_package: str = Field(..., description="Software component, library, or package name")
    installed_version: str = Field(..., description="Version of the affected component currently deployed")
    fixed_version: Optional[str] = Field(None, description="Upstream vendor version resolving the vulnerability")
    asset_id: str = Field(..., description="Target asset identifier affected by this finding")
    status: str = Field(..., description="Lifecycle triage status")


class FindingDetail(FindingRead):
    """Detailed vulnerability finding payload including descriptions and reference links."""

    description: str = Field(..., description="Full technical description of vulnerability and impact")
    source: str = Field(..., description="Source scanner or ingestion agent")
    references: Optional[List[str]] = Field(default_factory=list, description="External advisories, bulletins, and documentation links")
    first_seen: Optional[datetime] = Field(None, description="Timestamp when finding was first detected")
    last_seen: Optional[datetime] = Field(None, description="Timestamp when finding was most recently observed")
