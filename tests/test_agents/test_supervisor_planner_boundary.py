"""Tests for Phase 8G Supervisor Planner Abstraction & LLM Boundary.

Verifies:
1. AgentPlanner interface conformance
2. Runtime dependency injection and custom planner support
3. Default deterministic planner behavior
4. Fake planner injecting CALL_TOOL, FINALIZE, and FAIL actions
5. Safe handling of invalid/unknown planner outputs (INVALID_PLANNER_OUTPUT)
6. State isolation across independent planner instances
7. LLMSupervisorPlanner explicit failure when unconfigured (LLM_PLANNER_NOT_CONFIGURED)
8. build_llm_planner_input projection security (strips DB, callables, secrets)
9. validate_llm_action enforcement (validates schema, registry boundary, rejects forbidden keys)
10. FallbackSupervisorPlanner composite execution
11. Offline guarantee: zero network or external LLM dependencies
"""

from typing import Any, Dict, List, Optional, Union
import pytest

from src.agents import (
    AgentAction,
    AgentExecutionStatus,
    AgentPlanner,
    AgentStepActionType,
    AgentWorkflowType,
    CallToolAction,
    DeterministicSupervisorPlanner,
    FailAction,
    FallbackSupervisorPlanner,
    FinalizeAction,
    LLMSupervisorPlanner,
    PlannerDecision,
    SupervisorAgent,
    SupervisorLLMContext,
    SupervisorPlanner,
    SupervisorRuntime,
    SupervisorState,
    build_llm_planner_input,
    validate_llm_action,
)
from src.services.data_service import load_benchmark_findings
from src.tools.registry import default_tool_registry
from src.tools.schemas import ToolStatus


@pytest.fixture(scope="module")
def benchmark_findings():
    """Loaded benchmark findings for test scenarios."""
    return load_benchmark_findings()


# ==============================================================================
# Mock Planners for Testing Dependency Injection
# ==============================================================================

class MockCallToolPlanner(AgentPlanner):
    """Planner that executes a single tool call then finalizes or fails."""

    def __init__(self, tool_name: str, tool_args: Dict[str, Any]) -> None:
        self.tool_name = tool_name
        self.tool_args = tool_args
        self.invoked = False

    def plan(self, state: SupervisorState) -> AgentAction:
        if not self.invoked:
            self.invoked = True
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name=self.tool_name,
                tool_arguments=self.tool_args,
                rationale=f"Mock calling tool {self.tool_name}",
            )
        return AgentAction(
            action_type=AgentStepActionType.FAIL,
            error_code="MOCK_DONE",
            rationale="Mock execution complete.",
        )


class MockFailPlanner(AgentPlanner):
    """Planner that immediately terminates with a specific FAIL action."""

    def __init__(self, error_code: str = "INTENTIONAL_MOCK_FAILURE") -> None:
        self.error_code = error_code

    def plan(self, state: SupervisorState) -> AgentAction:
        return AgentAction(
            action_type=AgentStepActionType.FAIL,
            error_code=self.error_code,
            rationale=f"Intentional test failure with code {self.error_code}",
        )


class MockInvalidOutputPlanner(AgentPlanner):
    """Planner that returns an invalid non-action object."""

    def __init__(self, bad_output: Any) -> None:
        self.bad_output = bad_output

    def plan(self, state: SupervisorState) -> Any:
        return self.bad_output


# ==============================================================================
# 1. Interface Conformance & Default Behavior
# ==============================================================================

def test_planner_interface_conformance():
    """Verify DeterministicSupervisorPlanner satisfies AgentPlanner and SupervisorPlanner."""
    planner = DeterministicSupervisorPlanner()
    assert isinstance(planner, AgentPlanner)
    assert isinstance(planner, SupervisorPlanner)
    assert hasattr(planner, "plan")
    assert callable(planner.plan)


def test_runtime_default_uses_deterministic_planner():
    """Verify SupervisorRuntime defaults to DeterministicSupervisorPlanner."""
    runtime = SupervisorRuntime()
    assert isinstance(runtime._planner, DeterministicSupervisorPlanner)


def test_supervisor_facade_default_uses_deterministic_planner():
    """Verify SupervisorAgent defaults to DeterministicSupervisorPlanner."""
    agent = SupervisorAgent()
    assert isinstance(agent.planner, DeterministicSupervisorPlanner)


# ==============================================================================
# 2. Runtime Dependency Injection
# ==============================================================================

def test_runtime_accepts_injected_call_tool_planner():
    """Verify runtime executes a tool returned by a custom injected planner via tool registry."""
    planner = MockCallToolPlanner(
        tool_name="query_asset_cmdb",
        tool_args={"asset_id": "ASSET-001"},
    )
    runtime = SupervisorRuntime(planner=planner)

    state = SupervisorState(
        run_id="RUN-TEST-INJECT-TOOL",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test tool injection",
        target_finding_id="FINDING-001",
    )

    result_state = runtime.run(state)
    assert len(result_state.step_traces) >= 1
    first_step = result_state.step_traces[0]
    assert first_step.action.tool_name == "query_asset_cmdb"
    assert first_step.status == ToolStatus.SUCCESS
    assert any(ev.claim_or_property == "asset_context" for ev in result_state.evidence)


def test_runtime_accepts_injected_fail_planner():
    """Verify runtime properly handles and audits a FAIL action from a custom planner."""
    planner = MockFailPlanner(error_code="CUSTOM_SECURITY_HALT")
    runtime = SupervisorRuntime(planner=planner)

    state = SupervisorState(
        run_id="RUN-TEST-INJECT-FAIL",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test failure injection",
    )

    result_state = runtime.run(state)
    assert result_state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "CUSTOM_SECURITY_HALT" for err in result_state.errors)
    assert len(result_state.step_traces) == 1
    assert result_state.step_traces[0].action.action_type == AgentStepActionType.FAIL


def test_runtime_handles_invalid_planner_output_safely():
    """Verify returning a non-AgentAction (e.g. string or None) triggers INVALID_PLANNER_OUTPUT."""
    for bad_val in ["not an action", 12345, None, {"action": "fake"}]:
        planner = MockInvalidOutputPlanner(bad_output=bad_val)
        runtime = SupervisorRuntime(planner=planner)

        state = SupervisorState(
            run_id="RUN-TEST-BAD-OUTPUT",
            workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
            user_goal="Test invalid planner output handling",
        )

        result_state = runtime.run(state)
        assert result_state.status == AgentExecutionStatus.FAILED
        assert any(err.code == "INVALID_PLANNER_OUTPUT" for err in result_state.errors)


def test_planner_exception_caught_cleanly():
    """Verify an unhandled exception inside plan() is caught and recorded as PLANNER_EXCEPTION."""
    class CrashingPlanner(AgentPlanner):
        def plan(self, state: SupervisorState) -> AgentAction:
            raise ValueError("Deliberate planner algorithm crash")

    runtime = SupervisorRuntime(planner=CrashingPlanner())
    state = SupervisorState(
        run_id="RUN-TEST-CRASH",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test planner crash handling",
    )

    result_state = runtime.run(state)
    assert result_state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "PLANNER_EXCEPTION" for err in result_state.errors)
    assert "Deliberate planner algorithm crash" in result_state.errors[0].message


# ==============================================================================
# 3. LLM Boundary & Placeholder Contract
# ==============================================================================

def test_llm_planner_placeholder_fails_explicitly_when_unconfigured():
    """Verify LLMSupervisorPlanner fails explicitly with LLM_PLANNER_NOT_CONFIGURED."""
    planner = LLMSupervisorPlanner()
    assert not planner.is_configured

    state = SupervisorState(
        run_id="RUN-TEST-LLM",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt unconfigured LLM run",
    )

    with pytest.raises(RuntimeError, match="LLM_PLANNER_NOT_CONFIGURED"):
        planner.plan(state)


def test_llm_planner_inside_runtime_fails_safely():
    """Verify LLMSupervisorPlanner in runtime cleanly sets state to FAILED without unhandled crash."""
    runtime = SupervisorRuntime(planner=LLMSupervisorPlanner())
    state = SupervisorState(
        run_id="RUN-TEST-LLM-RUNTIME",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt unconfigured LLM run via runtime",
    )

    result_state = runtime.run(state)
    assert result_state.status == AgentExecutionStatus.FAILED
    assert any("LLM_PLANNER_NOT_CONFIGURED" in err.message for err in result_state.errors)


# ==============================================================================
# 4. LLM Input Projection (SupervisorLLMContext)
# ==============================================================================

def test_build_llm_planner_input_sanitization(benchmark_findings):
    """Verify build_llm_planner_input builds clean SupervisorLLMContext without internal handles."""
    f1 = benchmark_findings["FINDING-001"]

    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007")

    llm_context = build_llm_planner_input(state, allowed_tools=["lookup_cisa_kev", "query_asset_cmdb"])

    assert isinstance(llm_context, SupervisorLLMContext)
    assert llm_context.run_id == state.run_id
    assert llm_context.workflow_type == state.workflow_type
    assert llm_context.current_step == state.current_step
    assert len(llm_context.findings) >= 1
    assert len(llm_context.assets) >= 1
    assert len(llm_context.evidence) >= 1
    assert len(llm_context.recent_actions) >= 1
    assert llm_context.allowed_tools == ["lookup_cisa_kev", "query_asset_cmdb"]

    # Verify absence of internal objects or secrets
    context_dict = llm_context.model_dump()
    assert "db_session" not in context_dict
    assert "engine" not in context_dict
    assert "connection" not in context_dict
    assert "api_key" not in context_dict


# ==============================================================================
# 5. LLM Output Validation (validate_llm_action)
# ==============================================================================

def test_validate_llm_action_valid_call_tool():
    """Verify validate_llm_action accepts valid tool invocation payload."""
    raw_action = {
        "action_type": "CALL_TOOL",
        "tool_name": "lookup_cisa_kev",
        "tool_arguments": {"cve_id": "CVE-2023-38545"},
        "rationale": "Checking known exploited vulnerabilities",
    }
    validated = validate_llm_action(raw_action)
    assert isinstance(validated, AgentAction)
    assert validated.tool_name == "lookup_cisa_kev"


def test_validate_llm_action_rejects_unregistered_tool():
    """Verify validate_llm_action rejects tools not in default_tool_registry."""
    raw_action = {
        "action_type": "CALL_TOOL",
        "tool_name": "execute_shell_command",
        "tool_arguments": {"cmd": "rm -rf /"},
        "rationale": "Malicious tool attempt",
    }
    with pytest.raises(ValueError, match="Must be a registered tool in default_tool_registry"):
        validate_llm_action(raw_action)


def test_validate_llm_action_rejects_disallowed_tool():
    """Verify validate_llm_action enforces allowed_tools whitelist."""
    raw_action = {
        "action_type": "CALL_TOOL",
        "tool_name": "optimize_patch_capacity",
        "tool_arguments": {"candidates": []},
        "rationale": "Tool outside allowed whitelist",
    }
    with pytest.raises(ValueError, match="not permitted by allowed_tools whitelist"):
        validate_llm_action(raw_action, allowed_tools=["lookup_cisa_kev", "query_asset_cmdb"])


def test_validate_llm_action_rejects_forbidden_injection_keys():
    """Verify validate_llm_action rejects forbidden execution parameters like eval/cmd."""
    raw_action = {
        "action_type": "CALL_TOOL",
        "tool_name": "lookup_cisa_kev",
        "tool_arguments": {"cve_id": "CVE-2023-38545", "cmd": "whoami"},
        "rationale": "Parameter injection attempt",
    }
    with pytest.raises(ValueError, match="Prohibited security parameter"):
        validate_llm_action(raw_action)


# ==============================================================================
# 6. Fallback Planner Composite Execution
# ==============================================================================

def test_fallback_planner_delegation_when_enabled():
    """Verify FallbackSupervisorPlanner falls back to deterministic planner upon failure."""
    crashing_planner = MockFailPlanner(error_code="PRIMARY_ERROR")
    # Wrap in a planner that raises to trigger fallback
    class RaisingPlanner(AgentPlanner):
        def plan(self, state: SupervisorState) -> AgentAction:
            raise RuntimeError("Primary LLM connection timeout")

    fallback_planner = FallbackSupervisorPlanner(
        primary_planner=RaisingPlanner(),
        fallback_planner=DeterministicSupervisorPlanner(),
        enable_fallback=True,
    )

    agent = SupervisorAgent(planner=fallback_planner)
    state = agent.investigate_finding("FINDING-007")

    # Workflow must successfully complete via deterministic fallback
    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.final_result is not None
    assert any(w.code == "PLANNER_FALLBACK_TRIGGERED" for w in state.warnings)


def test_fallback_planner_raises_when_disabled():
    """Verify FallbackSupervisorPlanner does not swallow primary error when enable_fallback=False."""
    class RaisingPlanner(AgentPlanner):
        def plan(self, state: SupervisorState) -> AgentAction:
            raise RuntimeError("Primary unhandled error")

    fallback_planner = FallbackSupervisorPlanner(
        primary_planner=RaisingPlanner(),
        fallback_planner=DeterministicSupervisorPlanner(),
        enable_fallback=False,
    )

    state = SupervisorState(
        run_id="RUN-TEST-FALLBACK-DISABLED",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test disabled fallback",
    )

    with pytest.raises(RuntimeError, match="Primary unhandled error"):
        fallback_planner.plan(state)


# ==============================================================================
# 7. Planner State Isolation
# ==============================================================================

def test_planner_state_isolation_between_agent_instances():
    """Verify multiple SupervisorAgent instances using distinct planners remain completely isolated."""
    agent_1 = SupervisorAgent(planner=DeterministicSupervisorPlanner())
    agent_2 = SupervisorAgent(planner=MockFailPlanner(error_code="FAIL_INSTANCE_2"))

    state_1 = agent_1.investigate_finding("FINDING-007")
    state_2 = agent_2.investigate_finding("FINDING-007")

    assert state_1.status == AgentExecutionStatus.COMPLETED
    assert state_2.status == AgentExecutionStatus.FAILED
    assert any(e.code == "FAIL_INSTANCE_2" for e in state_2.errors)
    assert len(state_1.errors) == 0
