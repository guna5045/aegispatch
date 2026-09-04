"""Asset data models representing enterprise infrastructure context."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AssetType(str, Enum):
    """Categorical type of the computing asset."""

    SERVER = "SERVER"
    WORKSTATION = "WORKSTATION"
    CONTAINER = "CONTAINER"
    CLOUD_INSTANCE = "CLOUD_INSTANCE"
    DATABASE = "DATABASE"
    NETWORK_DEVICE = "NETWORK_DEVICE"
    APPLICATION = "APPLICATION"


class BusinessTier(str, Enum):
    """Organizational business priority tier."""

    MISSION_CRITICAL = "MISSION_CRITICAL"
    BUSINESS_CRITICAL = "BUSINESS_CRITICAL"
    INTERNAL_OPERATIONAL = "INTERNAL_OPERATIONAL"
    NON_CRITICAL = "NON_CRITICAL"


class AssetCriticality(str, Enum):
    """Operational criticality rating of the asset."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class NetworkExposure(str, Enum):
    """Network accessibility and boundary exposure."""

    INTERNET_FACING = "INTERNET_FACING"
    DMZ = "DMZ"
    INTERNAL = "INTERNAL"
    AIR_GAPPED = "AIR_GAPPED"


class DataSensitivity(str, Enum):
    """Classification of data hosted or processed by the asset."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    RESTRICTED = "RESTRICTED"


class EnvironmentType(str, Enum):
    """Deployment lifecycle environment."""

    PRODUCTION = "PRODUCTION"
    STAGING = "STAGING"
    DEVELOPMENT = "DEVELOPMENT"
    TESTING = "TESTING"


class ControlStatus(str, Enum):
    """Operational status of a compensating security control."""

    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    DEGRADED = "DEGRADED"


class PatchWindow(BaseModel):
    """Structured maintenance and patching availability window."""

    model_config = ConfigDict(extra="forbid")

    day_of_week: str = Field(
        ...,
        min_length=3,
        description="Designated maintenance day of week (e.g., Saturday, Sunday, Daily)",
    )
    start_time_utc: str = Field(
        ...,
        pattern=r"^([01]\d|2[0-3]):([0-5]\d)$",
        description="UTC start time in 24-hour HH:MM format",
    )
    duration_hours: float = Field(
        ...,
        gt=0.0,
        le=72.0,
        description="Maximum duration of the maintenance window in hours",
    )
    timezone: str = Field(
        default="UTC",
        description="Timezone designation for scheduling records",
    )


class CompensatingControl(BaseModel):
    """Compensating security control mitigating vulnerability exposure."""

    model_config = ConfigDict(extra="forbid")

    control_id: str = Field(..., min_length=1, description="Unique identifier for the control")
    name: str = Field(..., min_length=1, description="Name of the security control (e.g., WAF, EDR, Network ACL)")
    description: str = Field(..., description="Operational description of how the control functions")
    status: ControlStatus = Field(default=ControlStatus.ACTIVE, description="Current operational state")


class Asset(BaseModel):
    """Enterprise infrastructure asset with operational and risk context."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., min_length=1, description="Unique enterprise asset identifier")
    hostname: str = Field(..., min_length=1, description="Hostname or canonical logical name")
    asset_type: AssetType = Field(..., description="Classification type of the asset")
    business_tier: BusinessTier = Field(..., description="Organizational importance tier")
    criticality: AssetCriticality = Field(..., description="Inherent asset criticality level")
    network_exposure: NetworkExposure = Field(..., description="Network boundary exposure level")
    data_sensitivity: DataSensitivity = Field(..., description="Sensitivity rating of resident data")
    environment: EnvironmentType = Field(..., description="Lifecycle deployment environment")
    owner_team: str = Field(..., min_length=1, description="Responsible owning team or individual")
    patch_window: Optional[PatchWindow] = Field(None, description="Authorized maintenance schedule window")
    compensating_controls: List[CompensatingControl] = Field(
        default_factory=list,
        description="Active compensating controls associated with the asset",
    )
    metadata: Dict[str, str] = Field(
        default_factory=dict,
        description="Additional string metadata tags (e.g., cloud provider, region, cluster)",
    )
