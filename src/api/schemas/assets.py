"""Asset and security control API response schemas."""

from __future__ import annotations

from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ControlRead(BaseModel):
    """Compensating security control representation."""

    model_config = ConfigDict(from_attributes=True)

    control_id: str = Field(..., description="Unique control identifier")
    name: str = Field(..., description="Control name")
    description: Optional[str] = Field(None, description="Detailed control description")
    control_type: Optional[str] = Field(None, description="Category of control")
    active: bool = Field(True, description="Whether the control is currently enforced")


class AssetRead(BaseModel):
    """Summary representation of an enterprise asset."""

    model_config = ConfigDict(from_attributes=True)

    asset_id: str = Field(..., description="Unique enterprise asset identifier (e.g. ASSET-001)")
    hostname: str = Field(..., description="Fully-qualified domain name or hostname")
    asset_type: str = Field(..., description="Asset categorical type")
    business_tier: str = Field(..., description="Organizational criticality tier")
    criticality: str = Field(..., description="Operational business criticality")
    network_exposure: str = Field(..., description="Boundary network accessibility")
    data_sensitivity: str = Field(..., description="Classification level of hosted data")
    environment: str = Field(..., description="Deployment lifecycle environment")
    ip_address: Optional[str] = Field(None, description="Network IP address")
    os: Optional[str] = Field(None, description="Operating system distribution and version")


class AssetDetail(AssetRead):
    """Deep inspection model for an asset including compensating controls and finding metrics."""

    controls: List[ControlRead] = Field(default_factory=list, description="Compensating controls active on this asset")
    findings_count: int = Field(0, description="Total active vulnerability findings mapped to this asset")
