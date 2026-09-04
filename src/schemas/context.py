"""Environmental context models combining asset exposure, criticality, and organizational policies."""

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field
from src.schemas.asset import (
    AssetCriticality,
    BusinessTier,
    CompensatingControl,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
)


class PolicyCitation(BaseModel):
    """Structured organizational security policy requirement or standard citation."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    policy_id: str = Field(..., min_length=1, description="Policy document identifier (e.g., SEC-POL-04)")
    policy_name: str = Field(..., min_length=1, description="Official title of the policy")
    section: str = Field(..., min_length=1, description="Relevant policy section or clause (e.g., Section 4.2)")
    requirement_summary: str = Field(
        ...,
        min_length=1,
        description="Concise description of the policy requirement (e.g., Internet-facing critical CVEs patched within 7 days)",
    )
    reference_uri: Optional[str] = Field(
        None,
        description="URI or relative path to policy document artifact",
    )


class AssetContext(BaseModel):
    """Normalized environmental context when evaluating a vulnerability against an asset."""

    model_config = ConfigDict(extra="forbid")

    context_id: str = Field(
        ...,
        min_length=1,
        description="Unique identifier for this contextual evaluation record",
    )
    asset_id: str = Field(..., min_length=1, description="Target asset identifier")
    finding_id: str = Field(..., min_length=1, description="Target vulnerability finding identifier")
    criticality: AssetCriticality = Field(..., description="Asset criticality rating")
    network_exposure: NetworkExposure = Field(..., description="Asset network boundary exposure")
    data_sensitivity: DataSensitivity = Field(..., description="Asset resident data sensitivity")
    business_tier: BusinessTier = Field(..., description="Asset business tier rating")
    environment: EnvironmentType = Field(..., description="Asset environment type")
    applicable_controls: List[CompensatingControl] = Field(
        default_factory=list,
        description="Active compensating controls relevant to this finding",
    )
    policy_citations: List[PolicyCitation] = Field(
        default_factory=list,
        description="Structured citations of applicable corporate security policies",
    )
    context_summary: Optional[str] = Field(
        None,
        description="Analytical summary of combined environmental risk factors",
    )
