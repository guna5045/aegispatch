"""Threat intelligence observation API response schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ThreatObservationRead(BaseModel):
    """Telemetry record capturing verified exploit activity or EPSS score."""

    model_config = ConfigDict(from_attributes=True)

    id: int = Field(..., description="Database observation primary key")
    observation_id: Optional[str] = Field(None, description="Unique observation domain identifier")
    cve_id: str = Field(..., description="Associated CVE identifier")
    source: str = Field(..., description="Intelligence provider or observation source")
    is_cisa_kev: bool = Field(False, description="Flag indicating CISA Known Exploited Vulnerabilities status")
    epss_score: Optional[float] = Field(None, description="EPSS exploitation probability score")
    epss_percentile: Optional[float] = Field(None, description="EPSS percentile ranking")
    exploit_available: bool = Field(False, description="Flag indicating public exploit availability")
    exploit_maturity: Optional[str] = Field(None, description="Observed exploit maturity level")
    confidence: str = Field("HIGH", description="Observation confidence rating")
    notes: Optional[str] = Field(None, description="Contextual analyst or feed notes")
    observed_at: datetime = Field(..., description="Timestamp observation was recorded")
