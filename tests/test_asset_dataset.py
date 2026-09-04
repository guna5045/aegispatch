"""Automated tests validating the synthetic enterprise CMDB asset dataset."""

import json
from pathlib import Path
import pytest
from src.schemas import (
    Asset,
    AssetCriticality,
    AssetType,
    BusinessTier,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
)


@pytest.fixture
def asset_dataset_path() -> Path:
    """Path to the synthetic CMDB JSON dataset."""
    return Path("data/synthetic/enterprise_cmdb.json")


@pytest.fixture
def raw_assets(asset_dataset_path: Path):
    """Load raw JSON content from disk."""
    assert asset_dataset_path.exists(), f"File {asset_dataset_path} does not exist"
    with open(asset_dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    assert isinstance(data, list), "CMDB dataset root must be a JSON array"
    return data


def test_asset_count_and_uniqueness(raw_assets):
    """Verify exactly 18 unique assets exist with deterministic IDs."""
    assert len(raw_assets) == 18, f"Expected exactly 18 assets, found {len(raw_assets)}"

    asset_ids = [item.get("asset_id") for item in raw_assets]
    assert len(set(asset_ids)) == 18, "Asset IDs must all be unique"

    expected_ids = [f"ASSET-{i:03d}" for i in range(1, 19)]
    assert sorted(asset_ids) == expected_ids, "Asset IDs must strictly follow ASSET-001 to ASSET-018 sequence"


def test_pydantic_schema_validation(raw_assets):
    """Verify all 18 records parse cleanly through Pydantic Asset model without errors."""
    parsed_assets = [Asset.model_validate(record) for record in raw_assets]
    assert len(parsed_assets) == 18

    # Hostname format validation
    for asset in parsed_assets:
        assert asset.hostname.endswith(".aegis.internal"), f"Unexpected hostname domain: {asset.hostname}"
        assert len(asset.owner_team) > 0, f"Asset {asset.asset_id} missing owner_team"
        assert asset.patch_window is not None, f"Asset {asset.asset_id} missing patch_window"
        assert asset.patch_window.duration_hours > 0.0


def test_categorical_enums_validity(raw_assets):
    """Verify all categorical fields match strictly defined enum values."""
    for record in raw_assets:
        assert record["asset_type"] in AssetType._value2member_map_
        assert record["business_tier"] in BusinessTier._value2member_map_
        assert record["criticality"] in AssetCriticality._value2member_map_
        assert record["network_exposure"] in NetworkExposure._value2member_map_
        assert record["data_sensitivity"] in DataSensitivity._value2member_map_
        assert record["environment"] in EnvironmentType._value2member_map_


def test_fleet_diversity():
    """Verify that the fleet spans all intended environmental and business dimensions."""
    with open("data/synthetic/enterprise_cmdb.json", "r", encoding="utf-8") as f:
        assets = [Asset.model_validate(r) for r in json.load(f)]

    exposures = {a.network_exposure for a in assets}
    assert NetworkExposure.INTERNET_FACING in exposures
    assert NetworkExposure.DMZ in exposures
    assert NetworkExposure.INTERNAL in exposures
    assert NetworkExposure.AIR_GAPPED in exposures

    environments = {a.environment for a in assets}
    assert EnvironmentType.PRODUCTION in environments
    assert EnvironmentType.STAGING in environments
    assert EnvironmentType.DEVELOPMENT in environments
    assert EnvironmentType.TESTING in environments

    tiers = {a.business_tier for a in assets}
    assert BusinessTier.MISSION_CRITICAL in tiers
    assert BusinessTier.BUSINESS_CRITICAL in tiers
    assert BusinessTier.INTERNAL_OPERATIONAL in tiers
    assert BusinessTier.NON_CRITICAL in tiers

    sensitivities = {a.data_sensitivity for a in assets}
    assert DataSensitivity.RESTRICTED in sensitivities
    assert DataSensitivity.CONFIDENTIAL in sensitivities
    assert DataSensitivity.INTERNAL in sensitivities
    assert DataSensitivity.PUBLIC in sensitivities


def test_counterexample_support_assets_exist():
    """Verify presence of specific asset archetypes needed for counterexample scenarios."""
    with open("data/synthetic/enterprise_cmdb.json", "r", encoding="utf-8") as f:
        assets = [Asset.model_validate(r) for r in json.load(f)]

    # 1. Highly critical, internet-facing production asset (e.g., ASSET-001 or ASSET-002)
    critical_public_assets = [
        a for a in assets
        if a.criticality == AssetCriticality.CRITICAL
        and a.network_exposure == NetworkExposure.INTERNET_FACING
        and a.environment == EnvironmentType.PRODUCTION
    ]
    assert len(critical_public_assets) >= 1, "Must have at least one critical internet-facing production asset"

    # 2. Low-criticality, air-gapped dev/testing asset (e.g., ASSET-018)
    isolated_low_value_assets = [
        a for a in assets
        if a.criticality == AssetCriticality.LOW
        and a.network_exposure == NetworkExposure.AIR_GAPPED
        and a.environment in (EnvironmentType.DEVELOPMENT, EnvironmentType.TESTING)
    ]
    assert len(isolated_low_value_assets) >= 1, "Must have at least one isolated low-criticality test/dev asset"

    # 3. Assets with active compensating controls (WAF, EDR, Sandboxing)
    controlled_assets = [a for a in assets if len(a.compensating_controls) > 0]
    assert len(controlled_assets) >= 5, "Expected multiple assets with active compensating controls"
    
    # 4. Assets without compensating controls for comparison
    uncontrolled_assets = [a for a in assets if len(a.compensating_controls) == 0]
    assert len(uncontrolled_assets) >= 3, "Expected some assets without compensating controls for comparison"
