"""Repository for enterprise infrastructure assets."""

from __future__ import annotations

from typing import List, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from src.database.models.asset import Asset


class AssetRepository:
    """Data access repository for Asset ORM entities."""

    def __init__(self, session: Session) -> None:
        """Initialize repository with an active SQLAlchemy database session."""
        self.session = session

    def get_by_id(self, id: int) -> Optional[Asset]:
        """Retrieve an asset by its primary key ID."""
        return self.session.get(Asset, id)

    def get_by_asset_id(self, asset_id: str) -> Optional[Asset]:
        """Retrieve an asset by its unique domain identifier (e.g., 'ASSET-001')."""
        stmt = select(Asset).where(Asset.asset_id == asset_id)
        return self.session.scalars(stmt).first()

    def get_by_hostname(self, hostname: str) -> Optional[Asset]:
        """Retrieve an asset by its hostname."""
        stmt = select(Asset).where(Asset.hostname == hostname)
        return self.session.scalars(stmt).first()

    def list_all(self) -> List[Asset]:
        """List all enterprise assets sorted by asset_id ascending."""
        stmt = select(Asset).order_by(Asset.asset_id.asc())
        return list(self.session.scalars(stmt).all())

    def list_by_environment(self, environment: str) -> List[Asset]:
        """List assets belonging to a specific deployment lifecycle environment."""
        stmt = (
            select(Asset)
            .where(Asset.environment == environment)
            .order_by(Asset.asset_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def list_by_criticality(self, criticality: str) -> List[Asset]:
        """List assets matching an operational business criticality rating."""
        stmt = (
            select(Asset)
            .where(Asset.criticality == criticality)
            .order_by(Asset.asset_id.asc())
        )
        return list(self.session.scalars(stmt).all())

    def filter_and_paginate(
        self,
        environment: Optional[str] = None,
        criticality: Optional[str] = None,
        network_exposure: Optional[str] = None,
        offset: int = 0,
        limit: int = 20,
    ) -> tuple[List[Asset], int]:
        """Filter assets by attributes and return paginated items and total matching count."""
        stmt = select(Asset)
        if environment:
            stmt = stmt.where(Asset.environment == environment)
        if criticality:
            stmt = stmt.where(Asset.criticality == criticality)
        if network_exposure:
            stmt = stmt.where(Asset.network_exposure == network_exposure)

        from sqlalchemy import func
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = self.session.scalar(count_stmt) or 0

        paginated_stmt = stmt.order_by(Asset.asset_id.asc()).offset(offset).limit(limit)
        items = list(self.session.scalars(paginated_stmt).all())
        return items, total

    def create(self, asset: Asset) -> Asset:
        """Persist a new asset to the session and flush."""
        self.session.add(asset)
        self.session.flush()
        self.session.refresh(asset)
        return asset

    def update(self, asset: Asset) -> Asset:
        """Flush changes to an existing asset in the session."""
        self.session.flush()
        self.session.refresh(asset)
        return asset

    def delete(self, asset: Asset) -> bool:
        """Delete an asset from the session and flush."""
        self.session.delete(asset)
        self.session.flush()
        return True
