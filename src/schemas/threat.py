"""Threat intelligence evidence data models."""

from enum import Enum
from typing import List, Optional
from pydantic import AwareDatetime, BaseModel, ConfigDict, Field


class ThreatConfidence(str, Enum):
    """Assessment confidence level for retrieved threat intelligence."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class ThreatEvidence(BaseModel):
    """External threat intelligence signals and exploit evidence for a CVE."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this threat intelligence observation",
    )
    cve_id: str = Field(
        ...,
        pattern=r"^CVE-\d{4}-\d{4,7}$",
        description="Target CVE identifier",
    )
    is_cisa_kev: bool = Field(
        default=False,
        description="True if listed in CISA Known Exploited Vulnerabilities catalog",
    )
    cisa_kev_date_added: Optional[AwareDatetime] = Field(
        None,
        description="Timestamp when CVE was added to CISA KEV catalog",
    )
    cisa_kev_due_date: Optional[AwareDatetime] = Field(
        None,
        description="Federal remediation due date specified by CISA KEV",
    )
    epss_score: float | None = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Exploit Prediction Scoring System probability score between 0.0 and 1.0; None when EPSS intelligence is unavailable.",
    )
    epss_percentile: Optional[float] = Field(
        None,
        ge=0.0,
        le=1.0,
        description="EPSS relative percentile ranking between 0.0 and 1.0",
    )
    public_poc_available: bool = Field(
        default=False,
        description="True if a functional public proof-of-concept exploit is identified",
    )
    threat_source: str = Field(
        ...,
        min_length=1,
        description="Primary intelligence source (e.g., CISA KEV, FIRST EPSS, GitHub Advisories)",
    )
    retrieved_at: AwareDatetime = Field(
        ...,
        description="Timezone-aware timestamp when this threat evidence was fetched or cached",
    )
    confidence: ThreatConfidence = Field(
        default=ThreatConfidence.HIGH,
        description="Confidence rating of the threat evidence source",
    )
    reference_urls: List[str] = Field(
        default_factory=list,
        description="Direct URLs to threat advisories or exploit repositories",
    )
    notes: Optional[str] = Field(
        None,
        description="Operational context or analyst notes regarding exploitation activity",
    )
