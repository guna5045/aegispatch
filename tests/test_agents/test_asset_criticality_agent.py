"""Tests for Phase 9C: Asset Criticality Specialist Agent.

Comprehensive test coverage validating:
1. Valid critical production asset
2. Valid lower-criticality development asset
3. Internet-facing asset reachability
4. DMZ asset reachability
5. Internal asset reachability
6. Air-gapped asset reachability
7. Restricted data sensitivity asset
8. Confidential data sensitivity asset
9. Public data sensitivity asset
10. Controls present
11. No controls present
12. Network reachable flag true
13. Network reachable flag false
14. Network unavailable/unknown handling
15. Policy evidence available
16. Policy unavailable / no match
17. Asset not found in CMDB
18. Malformed CMDB result
19. Malformed network result
20. Malformed policy result
21. Tool exception handling
22. Unknown tool handling
23. Partial source availability
24. All context sources unavailable
25. Registry boundary enforcement
26. Deterministic repeated execution
27. State isolation across instances and invocations
28. Malicious hostname / policy text treated as inert data
29. Evidence provenance tracking
30. Correct final status assignment
31. Trace correctness and sequence numbers
32. Real benchmark CMDB integration
"""

from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from src.agents.asset_criticality import (
    AssetCriticalityAgent,
    AssetCriticalityInput,
    AssetCriticalityResult,
    AssetCriticalityStatus,
)
from src.agents.schemas import AgentStepActionType, NoticeSeverity
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    AssetType,
    BusinessTier,
    CompensatingControl,
    ControlStatus,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
)
from src.services.data_service import load_cmdb_assets
from src.tools.registry import ToolDefinition, ToolRegistry, default_tool_registry
from src.tools.schemas import (
    GetNetworkReachabilityInput,
    GetNetworkReachabilityOutput,
    PolicyClause,
    ProvenanceSourceType,
    QueryAssetCmdbInput,
    QueryAssetCmdbOutput,
    QueryRagPolicyInput,
    QueryRagPolicyOutput,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
)


@pytest.fixture
def agent() -> AssetCriticalityAgent:
    """Instantiate fresh AssetCriticalityAgent with default tool registry."""
    return AssetCriticalityAgent()


@pytest.fixture
def cmdb_assets() -> Dict[str, Asset]:
    """Load canonical benchmark CMDB assets."""
    return load_cmdb_assets()


# 1. Valid Critical Production Asset (Real Registry)
def test_1_valid_critical_production_asset(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001", finding_id="FINDING-001")

    assert res.status == AssetCriticalityStatus.SUCCESS
    assert res.asset_id == "ASSET-001"
    assert res.finding_id == "FINDING-001"
    assert res.business_criticality == AssetCriticality.CRITICAL
    assert res.business_tier == BusinessTier.MISSION_CRITICAL
    assert res.environment == EnvironmentType.PRODUCTION
    assert res.network_exposure == NetworkExposure.INTERNET_FACING
    assert res.data_sensitivity == DataSensitivity.CONFIDENTIAL
    assert res.reachable_from_internet is True
    assert len(res.compensating_controls) > 0
    assert len(res.step_traces) == 3


# 2. Valid Lower-Criticality Development Asset (Real Registry)
def test_2_valid_lower_criticality_dev_asset(agent: AssetCriticalityAgent):
    # ASSET-008 is an internal analytics database in synthetic CMDB
    res = agent.run(asset_id="ASSET-008")

    assert res.status == AssetCriticalityStatus.SUCCESS
    assert res.asset_id == "ASSET-008"
    assert res.business_criticality == AssetCriticality.MEDIUM
    assert res.business_tier == BusinessTier.INTERNAL_OPERATIONAL


# 3. Internet-Facing Asset Reachability
def test_3_internet_facing_reachability(agent: AssetCriticalityAgent):
    # ASSET-001 is internet-facing
    res = agent.run(asset_id="ASSET-001")
    assert res.network_exposure == NetworkExposure.INTERNET_FACING
    assert res.reachable_from_internet is True
    assert "Direct internet ingress reachability is enabled" in (res.reachability_rationale or "")


# 4. DMZ Asset Reachability
def test_4_dmz_asset_reachability():
    mock_registry = ToolRegistry()
    asset = Asset(
        asset_id="ASSET-DMZ",
        hostname="dmz-gw.corp.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.BUSINESS_CRITICAL,
        criticality=AssetCriticality.HIGH,
        network_exposure=NetworkExposure.DMZ,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        environment=EnvironmentType.PRODUCTION,
        owner_team="SecOps",
        compensating_controls=[],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=asset,
                compensating_controls=["WAF"],
            ),
        )
    )
    mock_registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Mock network",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=lambda inp: GetNetworkReachabilityOutput(
                tool_name="get_network_reachability",
                status=ToolStatus.SUCCESS,
                message="DMZ reachability checked",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset_id=inp.asset_id,
                network_exposure=NetworkExposure.DMZ,
                reachable_from_internet=False,
                rationale="Positioned in DMZ perimeter; internet ingress requires gateway proxy.",
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-DMZ")

    assert res.network_exposure == NetworkExposure.DMZ
    assert res.reachable_from_internet is False
    assert "DMZ perimeter" in (res.reachability_rationale or "")


# 5. Internal Asset Reachability
def test_5_internal_asset_reachability(agent: AssetCriticalityAgent):
    # ASSET-002 or ASSET-004 is internal in benchmark CMDB
    res = agent.run(asset_id="ASSET-002")
    if res.network_exposure == NetworkExposure.INTERNAL:
        assert res.reachable_from_internet is False
        assert "Internal network zone only" in (res.reachability_rationale or "")


# 6. Air-Gapped Asset Reachability
def test_6_air_gapped_asset_reachability():
    mock_registry = ToolRegistry()
    asset = Asset(
        asset_id="ASSET-ISOLATED",
        hostname="vault.isolated.internal",
        asset_type=AssetType.DATABASE,
        business_tier=BusinessTier.MISSION_CRITICAL,
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.AIR_GAPPED,
        data_sensitivity=DataSensitivity.RESTRICTED,
        environment=EnvironmentType.PRODUCTION,
        owner_team="DBA",
        compensating_controls=[],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=asset,
            ),
        )
    )
    mock_registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Mock network",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=lambda inp: GetNetworkReachabilityOutput(
                tool_name="get_network_reachability",
                status=ToolStatus.SUCCESS,
                message="Air-gapped checked",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset_id=inp.asset_id,
                network_exposure=NetworkExposure.AIR_GAPPED,
                reachable_from_internet=False,
                rationale="Air-gapped isolated zone; completely decoupled from external network paths.",
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-ISOLATED")

    assert res.network_exposure == NetworkExposure.AIR_GAPPED
    assert res.reachable_from_internet is False
    assert "Air-gapped isolated zone" in (res.reachability_rationale or "")


# 7. Restricted Data Sensitivity Asset
def test_7_restricted_data_sensitivity(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-002")
    assert res.data_sensitivity == DataSensitivity.RESTRICTED


# 8. Confidential Data Sensitivity Asset
def test_8_confidential_data_sensitivity():
    mock_registry = ToolRegistry()
    asset = Asset(
        asset_id="ASSET-CONF",
        hostname="conf.corp.internal",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.BUSINESS_CRITICAL,
        criticality=AssetCriticality.HIGH,
        network_exposure=NetworkExposure.INTERNAL,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        environment=EnvironmentType.PRODUCTION,
        owner_team="Finance",
        compensating_controls=[],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=asset,
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-CONF")

    assert res.data_sensitivity == DataSensitivity.CONFIDENTIAL


# 9. Public Data Sensitivity Asset
def test_9_public_data_sensitivity():
    mock_registry = ToolRegistry()
    asset = Asset(
        asset_id="ASSET-PUB",
        hostname="www.corp.example.com",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.INTERNAL_OPERATIONAL,
        criticality=AssetCriticality.LOW,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.PUBLIC,
        environment=EnvironmentType.PRODUCTION,
        owner_team="Marketing",
        compensating_controls=[],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=asset,
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-PUB")

    assert res.data_sensitivity == DataSensitivity.PUBLIC


# 10. Controls Present (WAF, EDR, etc.)
def test_10_controls_present(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001")
    assert len(res.compensating_controls) > 0
    assert any("WAF" in c or "Cloudflare" in c for c in res.compensating_controls)


# 11. No Controls Present
def test_11_no_controls_present():
    mock_registry = ToolRegistry()
    asset = Asset(
        asset_id="ASSET-BARE",
        hostname="bare.internal",
        asset_type=AssetType.WORKSTATION,
        business_tier=BusinessTier.NON_CRITICAL,
        criticality=AssetCriticality.LOW,
        network_exposure=NetworkExposure.INTERNAL,
        data_sensitivity=DataSensitivity.INTERNAL,
        environment=EnvironmentType.DEVELOPMENT,
        owner_team="Dev",
        compensating_controls=[],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=asset,
                compensating_controls=[],
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-BARE")

    assert len(res.compensating_controls) == 0
    assert "without active compensating controls" in (res.assessment_summary or "")


# 12. Network Reachable Flag True
def test_12_network_reachable_true(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001")
    assert res.reachable_from_internet is True


# 13. Network Reachable Flag False
def test_13_network_reachable_false(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-002")
    if res.network_exposure != NetworkExposure.INTERNET_FACING:
        assert res.reachable_from_internet is False


# 14. Network Unavailable / Unknown Handling (Never Converts to False Internal)
def test_14_network_unavailable_handling():
    mock_registry = ToolRegistry()
    mock_registry.register(default_tool_registry.get("query_asset_cmdb"))
    mock_registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Unavailable network tool",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=lambda inp: GetNetworkReachabilityOutput(
                tool_name="get_network_reachability",
                status=ToolStatus.NOT_AVAILABLE,
                message="Network topology cache unavailable",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset_id=inp.asset_id,
                network_exposure=NetworkExposure.INTERNAL,
                reachable_from_internet=False,
                rationale="Topology data offline.",
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert res.source_availability.network_available is False
    assert res.reachable_from_internet is None  # Honest None, not falsely converted to False
    assert any(w.code == "NETWORK_TOOL_UNAVAILABLE" for w in res.warnings)


# 15. Policy Evidence Available
def test_15_policy_evidence_available(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001")
    assert res.source_availability.policy_available is True
    assert len(res.policy_clauses) > 0
    assert any("POL-" in p.policy_id for p in res.policy_clauses)


# 16. Policy Unavailable / No Match Handling
def test_16_policy_unavailable_handling():
    mock_registry = ToolRegistry()
    mock_registry.register(default_tool_registry.get("query_asset_cmdb"))
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(
        ToolDefinition(
            name="query_rag_policy",
            description="Unavailable policy tool",
            category="GOVERNANCE",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryRagPolicyInput,
            output_schema=QueryRagPolicyOutput,
            handler=lambda inp: QueryRagPolicyOutput(
                tool_name="query_rag_policy",
                status=ToolStatus.NOT_AVAILABLE,
                message="Policy corpus unavailable",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="policy", source_type=ProvenanceSourceType.LOCAL_DATASET),
                retrieval_mode="LOCAL_DETERMINISTIC",
                matched_policies=[],
            ),
        )
    )

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert res.source_availability.policy_available is False
    assert len(res.policy_clauses) == 0
    assert any(w.code == "POLICY_CORPUS_UNAVAILABLE" for w in res.warnings)


# 17. Asset Not Found in CMDB
def test_17_asset_not_found(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-NONEXISTENT-999")

    assert res.status == AssetCriticalityStatus.NOT_FOUND
    assert res.business_criticality is None
    assert res.hostname is None
    assert any(w.code == "ASSET_NOT_FOUND" for w in res.warnings)
    assert "was not found in enterprise CMDB" in (res.assessment_summary or "")


# 18. Malformed CMDB Result
def test_18_malformed_cmdb_result():
    mock_registry = ToolRegistry()
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Corrupted CMDB tool",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: "NOT_AN_OUTPUT_OBJECT",  # type: ignore[return-value]
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert any(e.code == "CMDB_TOOL_ERROR" for e in res.errors)


# 19. Malformed Network Result
def test_19_malformed_network_result():
    mock_registry = ToolRegistry()
    mock_registry.register(default_tool_registry.get("query_asset_cmdb"))
    mock_registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Corrupted network tool",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=lambda inp: "NOT_AN_OUTPUT_OBJECT",  # type: ignore[return-value]
        )
    )
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert any(e.code == "NETWORK_TOOL_ERROR" for e in res.errors)


# 20. Malformed Policy Result
def test_20_malformed_policy_result():
    mock_registry = ToolRegistry()
    mock_registry.register(default_tool_registry.get("query_asset_cmdb"))
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(
        ToolDefinition(
            name="query_rag_policy",
            description="Corrupted policy tool",
            category="GOVERNANCE",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryRagPolicyInput,
            output_schema=QueryRagPolicyOutput,
            handler=lambda inp: "NOT_AN_OUTPUT_OBJECT",  # type: ignore[return-value]
        )
    )

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert any(e.code == "POLICY_TOOL_ERROR" for e in res.errors)


# 21. Tool Exception Handling
def test_21_tool_exception_handling():
    mock_registry = ToolRegistry()

    def crashing_cmdb(inp):
        raise RuntimeError("Database connection broken!")

    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Crashing CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=crashing_cmdb,
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert any(e.code == "CMDB_TOOL_ERROR" for e in res.errors)
    assert any("Database connection broken!" in e.message for e in res.errors)


# 22. Unknown Tool Handling
def test_22_unknown_tool_handling():
    empty_registry = ToolRegistry()
    custom_agent = AssetCriticalityAgent(registry=empty_registry)

    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.FAILED
    assert any("No tool registered under name" in e.message for e in res.errors)


# 23. Partial Source Availability
def test_23_partial_source_availability():
    mock_registry = ToolRegistry()
    mock_registry.register(default_tool_registry.get("query_asset_cmdb"))
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(
        ToolDefinition(
            name="query_rag_policy",
            description="Unavailable policy",
            category="GOVERNANCE",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryRagPolicyInput,
            output_schema=QueryRagPolicyOutput,
            handler=lambda inp: QueryRagPolicyOutput(
                tool_name="query_rag_policy",
                status=ToolStatus.NOT_AVAILABLE,
                message="Offline policy not found",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="policy", source_type=ProvenanceSourceType.LOCAL_DATASET),
                retrieval_mode="LOCAL_DETERMINISTIC",
                matched_policies=[],
            ),
        )
    )

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert res.source_availability.available_sources_count == 2
    assert res.source_availability.total_sources_queried == 3


# 24. All Context Sources Unavailable
def test_24_all_context_unavailable():
    mock_registry = ToolRegistry()
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Unavailable CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.NOT_AVAILABLE,
                message="CMDB offline",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
            ),
        )
    )
    mock_registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Unavailable network",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=lambda inp: GetNetworkReachabilityOutput(
                tool_name="get_network_reachability",
                status=ToolStatus.NOT_AVAILABLE,
                message="Network offline",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset_id=inp.asset_id,
                network_exposure=NetworkExposure.INTERNAL,
                reachable_from_internet=False,
                rationale="Topology unavailable.",
            ),
        )
    )
    mock_registry.register(
        ToolDefinition(
            name="query_rag_policy",
            description="Unavailable policy",
            category="GOVERNANCE",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryRagPolicyInput,
            output_schema=QueryRagPolicyOutput,
            handler=lambda inp: QueryRagPolicyOutput(
                tool_name="query_rag_policy",
                status=ToolStatus.NOT_AVAILABLE,
                message="Policy offline",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="policy", source_type=ProvenanceSourceType.LOCAL_DATASET),
                retrieval_mode="LOCAL_DETERMINISTIC",
                matched_policies=[],
            ),
        )
    )

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-001")

    assert res.status == AssetCriticalityStatus.PARTIAL_SUCCESS
    assert res.source_availability.available_sources_count == 0
    assert res.business_criticality is None
    assert res.reachable_from_internet is None


# 25. Registry Boundary Enforcement
def test_25_registry_boundary_enforcement():
    spy_registry = MagicMock(wraps=default_tool_registry)
    spy_agent = AssetCriticalityAgent(registry=spy_registry)

    res = spy_agent.run(asset_id="ASSET-001", finding_id="FINDING-001")

    assert spy_registry.invoke.call_count == 3
    invoked_tools = [call[0][0] for call in spy_registry.invoke.call_args_list]
    assert invoked_tools == ["query_asset_cmdb", "get_network_reachability", "query_rag_policy"]


# 26. Deterministic Repeated Execution
def test_26_deterministic_repeated_execution(agent: AssetCriticalityAgent):
    res1 = agent.run(asset_id="ASSET-001", finding_id="FINDING-001")
    res2 = agent.run(asset_id="ASSET-001", finding_id="FINDING-001")

    assert res1.asset_id == res2.asset_id
    assert res1.status == res2.status
    assert res1.business_criticality == res2.business_criticality
    assert res1.environment == res2.environment
    assert res1.compensating_controls == res2.compensating_controls
    assert len(res1.step_traces) == len(res2.step_traces)
    assert [t.action.tool_name for t in res1.step_traces] == [t.action.tool_name for t in res2.step_traces]


# 27. State Isolation Across Instances and Invocations
def test_27_state_isolation(agent: AssetCriticalityAgent):
    agent_a = AssetCriticalityAgent()
    agent_b = AssetCriticalityAgent()

    res_a = agent_a.run(asset_id="ASSET-001", finding_id="FINDING-001")
    res_b = agent_b.run(asset_id="ASSET-002", finding_id="FINDING-002")

    assert res_a.asset_id == "ASSET-001"
    assert res_a.finding_id == "FINDING-001"
    assert res_b.asset_id == "ASSET-002"
    assert res_b.finding_id == "FINDING-002"

    # Sequential run on same instance
    res_a_2 = agent_a.run(asset_id="ASSET-003", finding_id="FINDING-003")
    assert res_a_2.asset_id == "ASSET-003"
    assert res_a_2.finding_id == "FINDING-003"


# 28. Malicious Hostname / Policy Text Treated as Inert Data
def test_28_malicious_hostname_and_policy_inert():
    mock_registry = ToolRegistry()
    malicious_asset = Asset(
        asset_id="ASSET-EVIL",
        hostname="'; DROP TABLE assets; -- <script>alert(1)</script>",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.MISSION_CRITICAL,
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        environment=EnvironmentType.PRODUCTION,
        owner_team="__import__('os').system('echo pwned')",
        compensating_controls=[
            CompensatingControl(
                control_id="C-EVIL",
                name="WAF; rm -rf /",
                description="Malicious control",
                status=ControlStatus.ACTIVE,
            )
        ],
    )
    mock_registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Mock CMDB",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=lambda inp: QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Asset retrieved",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(source="cmdb", source_type=ProvenanceSourceType.PERSISTED_DATABASE),
                asset=malicious_asset,
                compensating_controls=["WAF; rm -rf /"],
            ),
        )
    )
    mock_registry.register(default_tool_registry.get("get_network_reachability"))
    mock_registry.register(default_tool_registry.get("query_rag_policy"))

    custom_agent = AssetCriticalityAgent(registry=mock_registry)
    res = custom_agent.run(asset_id="ASSET-EVIL")

    assert res.hostname == "'; DROP TABLE assets; -- <script>alert(1)</script>"
    assert "WAF; rm -rf /" in res.compensating_controls
    assert "<script>" in (res.assessment_summary or "")


# 29. Evidence Provenance Tracking
def test_29_evidence_provenance(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001")

    assert len(res.step_traces) == 3
    for trace in res.step_traces:
        assert trace.step_number in (1, 2, 3)
        assert trace.action.action_type == AgentStepActionType.CALL_TOOL
        assert trace.tool_result is not None
        assert trace.tool_result.provenance is not None


# 30. Correct Final Status Assignment
def test_30_final_status_assignment(agent: AssetCriticalityAgent):
    # Invalid input
    assert agent.run(asset_id=None).status == AssetCriticalityStatus.INVALID_INPUT
    assert agent.run(asset_id="   ").status == AssetCriticalityStatus.INVALID_INPUT

    # Not found
    assert agent.run(asset_id="ASSET-DOES-NOT-EXIST").status == AssetCriticalityStatus.NOT_FOUND

    # Success
    assert agent.run(asset_id="ASSET-001").status == AssetCriticalityStatus.SUCCESS


# 31. Trace Correctness and Step Sequence Numbers
def test_31_trace_correctness(agent: AssetCriticalityAgent):
    res = agent.run(asset_id="ASSET-001")

    assert len(res.step_traces) == 3
    assert res.step_traces[0].step_number == 1
    assert res.step_traces[0].action.tool_name == "query_asset_cmdb"
    assert res.step_traces[1].step_number == 2
    assert res.step_traces[1].action.tool_name == "get_network_reachability"
    assert res.step_traces[2].step_number == 3
    assert res.step_traces[2].action.tool_name == "query_rag_policy"


# 32. Real Benchmark CMDB Integration (All 18 Assets Tested)
def test_32_benchmark_cmdb_integration(agent: AssetCriticalityAgent, cmdb_assets: Dict[str, Asset]):
    assert len(cmdb_assets) == 18

    for asset_id, asset in cmdb_assets.items():
        res = agent.run(asset_id=asset_id)

        assert res.status == AssetCriticalityStatus.SUCCESS
        assert res.asset_id == asset_id
        assert res.hostname == asset.hostname
        assert res.business_criticality == asset.criticality
        assert res.business_tier == asset.business_tier
        assert res.environment == asset.environment
        assert res.network_exposure == asset.network_exposure
        assert res.data_sensitivity == asset.data_sensitivity
        if asset.network_exposure == NetworkExposure.INTERNET_FACING:
            assert res.reachable_from_internet is True
        else:
            assert res.reachable_from_internet is False
