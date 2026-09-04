"""Tests for ToolRegistry and framework-neutral tool orchestration."""

import pytest
from src.tools.registry import ToolDefinition, ToolRegistry, build_default_tool_registry
from src.tools.schemas import SideEffectClass, ToolStatus


def test_default_tool_registry_inventory():
    registry = build_default_tool_registry()

    assert registry.count == 17
    tools = registry.list_tools()
    assert len(tools) == 17

    names = {t.name for t in tools}
    expected_names = {
        "parse_raw_scan",
        "validate_finding_schema",
        "deduplicate_findings",
        "lookup_cisa_kev",
        "query_epss",
        "query_osv_database",
        "query_asset_cmdb",
        "get_network_reachability",
        "query_rag_policy",
        "calculate_environmental_risk",
        "map_ssvc_decision",
        "optimize_patch_capacity",
        "resolve_package_dependencies",
        "simulate_risk_reduction",
        "verify_score_derivation",
        "detect_hallucinated_claims",
        "validate_plan_constraints",
    }
    assert names == expected_names


def test_registry_categories():
    registry = build_default_tool_registry()

    scan_tools = registry.list_by_category("SCAN")
    assert len(scan_tools) == 3

    threat_tools = registry.list_by_category("THREAT")
    assert len(threat_tools) == 3

    asset_tools = registry.list_by_category("ASSET")
    assert len(asset_tools) == 3

    risk_tools = registry.list_by_category("RISK")
    assert len(risk_tools) == 2

    planning_tools = registry.list_by_category("PLANNING")
    assert len(planning_tools) == 3

    verification_tools = registry.list_by_category("VERIFICATION")
    assert len(verification_tools) == 3


def test_registry_side_effect_guarantees():
    registry = build_default_tool_registry()

    for tool in registry.list_tools():
        assert tool.side_effect in {
            SideEffectClass.READ_ONLY,
            SideEffectClass.COMPUTE_ONLY,
            SideEffectClass.SIMULATION,
            SideEffectClass.PERSISTENCE_WRITE,
        }
        # Guarantee: No tool has destructive infrastructure side effects
        assert tool.side_effect != "DESTRUCTIVE"


def test_registry_invoke():
    registry = build_default_tool_registry()

    # Invoke map_ssvc_decision via registry
    res = registry.invoke("map_ssvc_decision", {"ers_score": 90.0, "has_compensating_controls": False})
    assert res.status == ToolStatus.SUCCESS
    assert res.decision.value == "ACT"


def test_registry_duplicate_registration_error():
    registry = ToolRegistry()
    from src.tools.schemas import MapSsvcDecisionInput, MapSsvcDecisionOutput
    from src.tools.risk_tools import map_ssvc_decision

    t = ToolDefinition(
        name="test_tool",
        description="test",
        category="TEST",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        input_schema=MapSsvcDecisionInput,
        output_schema=MapSsvcDecisionOutput,
        handler=map_ssvc_decision,
    )
    registry.register(t)
    with pytest.raises(ValueError, match="already registered"):
        registry.register(t)
