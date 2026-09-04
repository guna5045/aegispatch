"""SQLAlchemy ORM model for organizational security policy documents and metadata."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy import DateTime, String
from sqlalchemy.dialects.sqlite import JSON
from sqlalchemy.orm import Mapped, mapped_column

from src.database.base import Base


class PolicyDocument(Base):
    """Organizational security policy metadata utilized for compliance and remediation governance."""

    __tablename__ = "policy_documents"

    # Primary key
    id: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)

    # Unique policy identifier (e.g., POL-SEC-04, POL-IT-09, POL-SEC-12)
    policy_id: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)

    # Title and classification
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    policy_type: Mapped[str] = mapped_column(String(64), index=True, nullable=False)
    version: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(32), index=True, default="ACTIVE", nullable=False)

    # Governance dates
    effective_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    review_date: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    # File reference and integrity hash
    source_path: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)
    content_hash: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    # Flexible metadata (e.g., tags, scope, authority)
    policy_metadata: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON, nullable=True)

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

    def __repr__(self) -> str:
        return f"<PolicyDocument(policy_id='{self.policy_id}', title='{self.title}', version='{self.version}', status='{self.status}')>"
