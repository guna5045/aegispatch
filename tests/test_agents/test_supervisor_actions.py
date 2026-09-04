"""Tests for Phase 8C Supervisor Workflow and Action Contracts."""

import pytest
from pydantic import ValidationError

from src.agents.planner import AgentPlanner
from src.agents.schemas import (
    AgentAction,
    AgentStepActionType,
    AgentWorkflowType,
    CallToolAction,
    FailAction,
    FinalizeAction,
    InvestigateFindingContext,
    PlanRemediationContext,
    PlannerDecision,
    PrioritizeFindingsContext,
    ReplanAction,
    SupervisorState,
    WhatIfContext,
    WorkflowContext,
)


def test_1_all_workflow_enum_values():
    expected = {
        "INVESTIGATE_FINDING": AgentWorkflowType.INVESTIGATE_FINDING,
        "PRIORITIZE_FINDINGS": AgentWorkflowType.PRIORITIZE_FINDINGS,
        "PLAN_REMEDIATION": AgentWorkflowType.PLAN_REMEDIATION,
        "WHAT_IF": AgentWorkflowType.WHAT_IF,
    }
    for val_str, enum_val in expected.items():
        assert AgentWorkflowType(val_str) == enum_val


def test_2_invalid_workflow_rejection():
    with pytest.raises(ValueError):
        AgentWorkflowType("INVALID_AUTONOMOUS_WORKFLOW")


def test_3_investigate_finding_context_validation():
    ctx = InvestigateFindingContext(target_finding_id="FINDING-001", target_asset_id="ASSET-001")
    assert ctx.target_finding_id == "FINDING-001"
    assert ctx.target_asset_id == "ASSET-001"
    assert ctx.require_verification is True

    # Requires non-empty target_finding_id
    with pytest.raises(ValidationError):
        InvestigateFindingContext(target_finding_id="")


def test_4_prioritize_findings_context():
    ctx = PrioritizeFindingsContext(
        selected_finding_ids=["FINDING-001", "FINDING-002"],
        minimum_cvss_filter=7.0,
    )
    assert len(ctx.selected_finding_ids) == 2
    assert ctx.minimum_cvss_filter == 7.0

    # Invalid CVSS filter > 10.0
    with pytest.raises(ValidationError):
        PrioritizeFindingsContext(minimum_cvss_filter=15.0)


def test_5_plan_remediation_context():
    ctx = PlanRemediationContext(
        capacity_limit_hours=24.0,
        target_finding_ids=["FINDING-001", "FINDING-002"],
        require_rollback_plans=True,
    )
    assert ctx.capacity_limit_hours == 24.0
    assert ctx.require_rollback_plans is True

    # Capacity limit must be positive
    with pytest.raises(ValidationError):
        PlanRemediationContext(capacity_limit_hours=0.0)


def test_6_what_if_context():
    ctx = WhatIfContext(
        finding_id="FINDING-001",
        asset_id="ASSET-001",
        hypothetical_controls=["WAF", "NETWORK_SEGMENTATION"],
        hypothetical_capacity_hours=12.0,
    )
    assert ctx.finding_id == "FINDING-001"
    assert len(ctx.hypothetical_controls) == 2
    assert ctx.hypothetical_capacity_hours == 12.0


def test_7_call_tool_action():
    action = CallToolAction(
        tool_name="lookup_cisa_kev",
        tool_arguments={"cve_id": "CVE-2023-38545"},
        rationale="Check CISA KEV catalog for active exploitation telemetry.",
        target_finding_id="FINDING-001",
    )
    assert action.action_type == AgentStepActionType.CALL_TOOL
    assert action.tool_name == "lookup_cisa_kev"
    assert action.tool_arguments["cve_id"] == "CVE-2023-38545"
    assert action.is_terminal is False


def test_8_call_tool_requires_tool_name():
    with pytest.raises(ValidationError):
        CallToolAction(tool_name="", rationale="Calling with empty tool name")

    # Unified AgentAction requires non-empty tool_name when action_type is CALL_TOOL
    with pytest.raises(ValidationError, match="tool_name must be non-empty"):
        AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="",
            rationale="Testing empty name",
        )


def test_9_call_tool_arguments_serialization():
    action = CallToolAction(
        tool_name="calculate_environmental_risk",
        tool_arguments={"finding_id": "FINDING-001", "epss_score": 0.92},
        rationale="Calculate ERS",
    )
    dumped = action.model_dump()
    assert dumped["tool_name"] == "calculate_environmental_risk"
    assert dumped["tool_arguments"]["epss_score"] == 0.92

    reloaded = CallToolAction.model_validate(dumped)
    assert reloaded.tool_arguments["epss_score"] == 0.92


def test_10_finalize_action():
    fin = FinalizeAction(
        rationale="All evidence collected and verified; score 92.5 maps to ACT.",
        verified=True,
    )
    assert fin.action_type == AgentStepActionType.FINALIZE
    assert fin.is_terminal is True
    assert fin.verified is True


def test_11_replan_action():
    rep = ReplanAction(
        trigger="TELEMETRY_UNAVAILABLE",
        rationale="EPSS telemetry unavailable; fallback to public PoC signals.",
        missing_information=["epss_score"],
        suggested_alternative="evaluate_with_unindexed_threat",
    )
    assert rep.action_type == AgentStepActionType.REPLAN
    assert rep.is_terminal is False
    assert rep.trigger == "TELEMETRY_UNAVAILABLE"


def test_12_replan_reason_validation():
    with pytest.raises(ValidationError):
        ReplanAction(trigger="TRIG", rationale="")


def test_13_fail_action():
    fail = FailAction(
        error_code="TARGET_NOT_FOUND",
        error_message="Asset ASSET-999 does not exist in CMDB.",
        rationale="Unrecoverable missing asset context halts investigation.",
    )
    assert fail.action_type == AgentStepActionType.FAIL
    assert fail.is_terminal is True
    assert fail.error_code == "TARGET_NOT_FOUND"


def test_14_fail_reason_validation():
    with pytest.raises(ValidationError):
        FailAction(error_code="ERR", error_message="msg", rationale="")


def test_15_terminal_non_terminal_classification():
    call_act = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="query_asset_cmdb",
        rationale="Get asset",
    )
    replan_act = AgentAction(
        action_type=AgentStepActionType.REPLAN,
        trigger="MISSING_DATA",
        rationale="Need fallback",
    )
    fin_act = AgentAction(
        action_type=AgentStepActionType.FINALIZE,
        rationale="Complete",
    )
    fail_act = AgentAction(
        action_type=AgentStepActionType.FAIL,
        error_code="FATAL_ERR",
        rationale="Cannot proceed",
    )

    assert call_act.is_terminal is False
    assert replan_act.is_terminal is False
    assert fin_act.is_terminal is True
    assert fail_act.is_terminal is True


def test_16_action_serialization_roundtrip():
    act = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="query_asset_cmdb",
        tool_arguments={"asset_id": "ASSET-001"},
        rationale="Retrieve operational context for target host",
        target_asset_id="ASSET-001",
    )
    dumped = act.model_dump()
    reconstructed = AgentAction.model_validate(dumped)

    assert reconstructed.action_type == AgentStepActionType.CALL_TOOL
    assert reconstructed.tool_name == "query_asset_cmdb"
    assert reconstructed.tool_arguments["asset_id"] == "ASSET-001"
    assert reconstructed.is_terminal is False


def test_17_workflow_context_serialization_roundtrip():
    wf_ctx = WorkflowContext(
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        investigate=InvestigateFindingContext(
            target_finding_id="FINDING-001",
            target_asset_id="ASSET-001",
        ),
    )
    dumped = wf_ctx.model_dump()
    reconstructed = WorkflowContext.model_validate(dumped)

    assert reconstructed.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING
    assert reconstructed.investigate.target_finding_id == "FINDING-001"


def test_18_malformed_workflow_context_mismatch():
    # Mismatched context: INVESTIGATE_FINDING without investigate context
    with pytest.raises(ValidationError, match="investigate context must be provided"):
        WorkflowContext(
            workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
            what_if=WhatIfContext(finding_id="F1", asset_id="A1"),
        )


def test_19_planner_decision_envelope():
    decision = PlannerDecision(
        action=AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="lookup_cisa_kev",
            tool_arguments={"cve_id": "CVE-2023-38545"},
            rationale="Query KEV catalog",
        ),
        confidence=1.0,
        iteration=1,
        planner_name="DeterministicSupervisorPlanner",
    )
    dumped = decision.model_dump()
    reloaded = PlannerDecision.model_validate(dumped)

    assert reloaded.confidence == 1.0
    assert reloaded.iteration == 1
    assert reloaded.action.tool_name == "lookup_cisa_kev"


def test_20_no_executable_objects_in_serialized_action():
    action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="query_epss",
        tool_arguments={"cve_id": "CVE-2023-38545"},
        rationale="Retrieve EPSS probability score",
    )
    dumped = action.model_dump()

    # Verify every leaf in dumped dict is a JSON-safe primitive
    def _check_primitives(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                assert isinstance(k, str)
                _check_primitives(v)
        elif isinstance(obj, list):
            for elem in obj:
                _check_primitives(elem)
        else:
            assert isinstance(obj, (str, int, float, bool, type(None)))

    _check_primitives(dumped)
