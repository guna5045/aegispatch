"""Unit tests for Phase 8A Supervisor Agent foundation contracts and planner interfaces."""

import pytest
from src.agents.planner import AgentPlanner
from src.agents.schemas import (
    AgentAction,
    AgentExecutionStatus,
    AgentStepActionType,
    AgentStepTrace,
    AgentWorkflowType,
    SupervisorState,
)
from src.tools.schemas import ToolStatus


def test_agent_workflow_types():
    assert AgentWorkflowType.INVESTIGATE_FINDING == "INVESTIGATE_FINDING"
    assert AgentWorkflowType.PRIORITIZE_FINDINGS == "PRIORITIZE_FINDINGS"
    assert AgentWorkflowType.PLAN_REMEDIATION == "PLAN_REMEDIATION"
    assert AgentWorkflowType.WHAT_IF == "WHAT_IF"


def test_agent_step_action_types():
    assert AgentStepActionType.CALL_TOOL == "CALL_TOOL"
    assert AgentStepActionType.REPLAN == "REPLAN"
    assert AgentStepActionType.FINALIZE == "FINALIZE"
    assert AgentStepActionType.FAIL == "FAIL"


def test_supervisor_state_instantiation():
    state = SupervisorState(
        run_id="RUN-TEST-001",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate critical vulnerability on edge gateway",
        target_finding_id="FINDING-001",
        target_asset_id="ASSET-001",
    )

    assert state.run_id == "RUN-TEST-001"
    assert state.status == AgentExecutionStatus.PENDING
    assert state.iteration_count == 0
    assert state.max_iterations == 20
    assert len(state.step_traces) == 0
    assert len(state.warnings) == 0
    assert len(state.errors) == 0
    assert state.final_result is None


def test_agent_action_and_step_trace():
    action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="lookup_cisa_kev",
        tool_arguments={"cve_id": "CVE-2023-38545"},
        rationale="Check if CVE-2023-38545 is listed in active exploitation catalog.",
        target_finding_id="FINDING-001",
    )

    assert action.action_type == AgentStepActionType.CALL_TOOL
    assert action.tool_name == "lookup_cisa_kev"
    assert action.tool_arguments["cve_id"] == "CVE-2023-38545"

    trace = AgentStepTrace(
        step_number=1,
        action=action,
        status=ToolStatus.SUCCESS,
        notes="Tool executed successfully",
    )

    assert trace.step_number == 1
    assert trace.action.tool_name == "lookup_cisa_kev"
    assert trace.status == ToolStatus.SUCCESS


def test_agent_planner_interface_contract():
    class DummyPlanner(AgentPlanner):
        def plan(self, state: SupervisorState) -> AgentAction:
            return AgentAction(
                action_type=AgentStepActionType.FINALIZE,
                rationale="Goal reached immediately.",
            )

    planner = DummyPlanner()
    state = SupervisorState(
        run_id="RUN-TEST-002",
        workflow_type=AgentWorkflowType.WHAT_IF,
        user_goal="Simulate adding WAF to gateway",
    )

    action = planner.plan(state)
    assert action.action_type == AgentStepActionType.FINALIZE
    assert action.rationale == "Goal reached immediately."
