"""Tests for Phase 7 asset tools: query_asset_cmdb, get_network_reachability, query_rag_policy."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.base import Base
from src.database.models.asset import Asset as DBAsset
from src.database.models.control import SecurityControl
from src.schemas.asset import NetworkExposure
from src.tools.asset_tools import (
    get_network_reachability,
    query_asset_cmdb,
    query_rag_policy,
)
from src.tools.schemas import (
    GetNetworkReachabilityInput,
    QueryAssetCmdbInput,
    QueryRagPolicyInput,
    SideEffectClass,
    ToolStatus,
)


@pytest.fixture
def in_memory_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine)
    session = sm()
    try:
        yield session
    finally:
        session.close()


def test_query_asset_cmdb_found(in_memory_session):
    asset = DBAsset(
        asset_id="ASSET-001",
        hostname="gw-prod-01",
        asset_type="SERVER",
        environment="PRODUCTION",
        criticality="CRITICAL",
        business_tier="MISSION_CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="CONFIDENTIAL",
        owner_team="SecOps",
        patch_window={"day_of_week": "SUN", "start_time_utc": "02:00", "duration_hours": 4.0},
    )
    ctrl = SecurityControl(
        control_id="CTRL-01",
        name="WAF",
        description="Cloud WAF",
        asset_id="ASSET-001",
        active=True,
    )
    in_memory_session.add_all([asset, ctrl])
    in_memory_session.commit()

    inp = QueryAssetCmdbInput(asset_id="ASSET-001")
    out = query_asset_cmdb(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.READ_ONLY
    assert out.asset is not None
    assert out.asset.asset_id == "ASSET-001"
    assert out.asset.hostname == "gw-prod-01"
    assert "WAF" in out.compensating_controls
    assert "SUN_02:00" in out.patch_window


def test_query_asset_cmdb_not_found(in_memory_session):
    inp = QueryAssetCmdbInput(asset_id="ASSET-999")
    out = query_asset_cmdb(inp, session=in_memory_session)

    assert out.status == ToolStatus.NOT_FOUND
    assert out.asset is None
    assert len(out.compensating_controls) == 0


def test_get_network_reachability_internet_facing(in_memory_session):
    asset = DBAsset(
        asset_id="ASSET-001",
        hostname="gw-prod-01",
        asset_type="SERVER",
        environment="PRODUCTION",
        criticality="CRITICAL",
        business_tier="MISSION_CRITICAL",
        network_exposure="INTERNET_FACING",
        data_sensitivity="CONFIDENTIAL",
        owner_team="SecOps",
    )
    in_memory_session.add(asset)
    in_memory_session.commit()

    inp = GetNetworkReachabilityInput(asset_id="ASSET-001")
    out = get_network_reachability(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.reachable_from_internet is True
    assert out.network_exposure == NetworkExposure.INTERNET_FACING
    assert "Direct internet ingress reachability is enabled" in out.rationale


def test_get_network_reachability_isolated(in_memory_session):
    asset = DBAsset(
        asset_id="ASSET-018",
        hostname="lab-airgap-01",
        asset_type="WORKSTATION",
        environment="DEVELOPMENT",
        criticality="LOW",
        business_tier="NON_CRITICAL",
        network_exposure="AIR_GAPPED",
        data_sensitivity="PUBLIC",
        owner_team="LabOps",
    )
    in_memory_session.add(asset)
    in_memory_session.commit()

    inp = GetNetworkReachabilityInput(asset_id="ASSET-018")
    out = get_network_reachability(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.reachable_from_internet is False
    assert out.network_exposure == NetworkExposure.AIR_GAPPED
    assert "Air-gapped isolated zone" in out.rationale


def test_query_rag_policy_found():
    inp = QueryRagPolicyInput(query="SLA", policy_id="POL-SEC-04")
    out = query_rag_policy(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.READ_ONLY
    assert out.retrieval_mode == "LOCAL_DETERMINISTIC"
    assert len(out.matched_policies) > 0
    assert any("POL-SEC-04" in p.policy_id for p in out.matched_policies)


def test_query_rag_policy_not_found():
    inp = QueryRagPolicyInput(query="NONEXISTENT_TOPIC_XYZ_12345")
    out = query_rag_policy(inp)

    assert out.status == ToolStatus.NOT_FOUND
    assert len(out.matched_policies) == 0
