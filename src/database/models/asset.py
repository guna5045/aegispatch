"""SQLAlchemy ORM model for enterprise infrastructure assets."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from sqlalchemy import DateTime, Index, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.base import Base

if TYPE_CHECKING:
    from src.database.models.control import SecurityControl
    from src.database.models.vulnerability import VulnerabilityFinding


class Asset(Base):
    """Enterprise infrastructure asset record from the CMDB."""

    __tablename__ = "assets"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Unique enterprise identifier (e.g., ASSET-001)
    asset_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Asset context attributes
    hostname: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    asset_type: Mapped[str] = mapped_column(String(64), nullable=False)
    business_tier: Mapped[str] = mapped_column(String(64), nullable=False)
    criticality: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    network_exposure: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    data_sensitivity: Mapped[str] = mapped_column(String(64), nullable=False)
    environment: Mapped[str] = mapped_column(String(64), index=True, nullable=False)

    # Descriptive & ownership metadata
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    owner_team: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Structured maintenance window and asset tags
    patch_window: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)
    asset_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

    # Audit timestamps
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
    findings: Mapped[List[VulnerabilityFinding]] = relationship(
        "VulnerabilityFinding",
        back_populates="asset",
        cascade="all, delete-orphan",
    )
    controls: Mapped[List[SecurityControl]] = relationship(
        "SecurityControl",
        back_populates="asset",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        return f"<Asset(asset_id='{self.asset_id}', hostname='{self.hostname}', env='{self.environment}')>"
