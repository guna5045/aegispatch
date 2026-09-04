"""SQLAlchemy ORM model for compensating and security controls."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.database.base import Base

if TYPE_CHECKING:
    from src.database.models.asset import Asset


class SecurityControl(Base):
    """Compensating security control mitigating vulnerability exposure on an asset."""

    __tablename__ = "security_controls"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Control identifier and association
    control_id: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    asset_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("assets.asset_id", ondelete="CASCADE"),
        index=True,
        nullable=False,
    )

    # Descriptive fields
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    control_category: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)

    # Operational status
    status: Mapped[str] = mapped_column(String(32), default="ACTIVE", nullable=False)
    active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Quantified effectiveness / discount factor if provided
    effectiveness_discount: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Structured verification or audit evidence
    evidence: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

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

    # Relationship to parent asset
    asset: Mapped[Asset] = relationship("Asset", back_populates="controls")

    def __repr__(self) -> str:
        return f"<SecurityControl(control_id='{self.control_id}', name='{self.name}', asset_id='{self.asset_id}', active={self.active})>"
