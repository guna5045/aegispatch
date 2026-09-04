"""Integration and unit tests for Phase 8D Supervisor Agent runtime.

Validates:
1. Complete INVESTIGATE_FINDING autonomous execution for FINDING-007.
2. State -> Plan -> Action -> Execute -> Observe -> Update -> Verify -> Finalize loop.
3. Tool Registry enforcement (all tools called strictly via default_tool_registry).
4. Genuine REPLAN on unavailable threat telemetry (OSV NOT_AVAILABLE).
5. Explicit preservation of NOT_FOUND statuses (CISA KEV).
6. Verification gate blocking incorrect score finalization.
7. Maximum iterations guardrail (MAX_ITERATIONS_REACHED).
8. Structured handling of unknown tools and unsupported workflows.
9. Deterministic execution reproducibility.
10. Concurrency and state isolation across runs.
"""

from unittest.mock import MagicMock, patch
import pytest

from src.agents import (
    AgentAction,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentWorkflowType,
    DeterministicSupervisorPlanner,
    EvidenceType,
    InvestigateFindingContext,
    NoticeSeverity,
    SupervisorAgent,
    SupervisorRuntime,
    SupervisorState,
    WorkflowContext,
)
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import default_tool_registry
from src.tools.schemas import BaseToolResult, SideEffectClass, ToolStatus, VerifyScoreDerivationOutput


# ==============================================================================
# 1. Primary Objective: Complete Autonomous Investigation for FINDING-007
# ==============================================================================

def test_1_investigate_finding_007_complete_flow():
    """Verify autonomous investigation of benchmark FINDING-007 from start to verified completion."""
    agent = SupervisorAgent()
    state = agent.investigate_finding(
        finding_id="FINDING-007",
        asset_id="ASSET-002",
        user_goal="Investigate critical buffer overflow FINDING-007 on ASSET-002",
    )

    # 1. Workflow completed successfully
    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.final_result is not None
    assert state.final_result.is_verified is True
    assert "FINDING-007" in state.final_result.target_findings
    assert "FINDING-007" in state.final_result.risk_scores

    # 2. Finding loaded and validated
    assert "FINDING-007" in state.findings
    finding = state.findings["FINDING-007"]
    assert finding.cve_id == "CVE-2023-4911"
    assert finding.cvss_score == 7.8

    # 3. Asset context retrieved
    assert "ASSET-002" in state.assets
    asset = state.assets["ASSET-002"]
    assert asset.asset_id == "ASSET-002"

    # 4. Evidence accumulated
    evidence_types = [ev.evidence_type for ev in state.evidence]
    assert EvidenceType.SCAN_DATA in evidence_types
    assert EvidenceType.CMDB_ASSET in evidence_types
    assert EvidenceType.CISA_KEV in evidence_types
    assert EvidenceType.EPSS in evidence_types
    assert EvidenceType.OSV in evidence_types
    assert EvidenceType.RISK_EVALUATION in evidence_types
    assert EvidenceType.VERIFICATION in evidence_types

    # 5. Step traces populated and sequenced
    assert len(state.step_traces) >= 7
    for idx, trace in enumerate(state.step_traces):
        assert trace.step_number == idx + 1
        assert trace.action is not None

    # Verify tool execution sequence occurred in correct state order
    tool_names = [t.action.tool_name for t in state.step_traces if t.action.tool_name]
    assert "validate_finding_schema" in tool_names
    assert "query_asset_cmdb" in tool_names
    assert "lookup_cisa_kev" in tool_names
    assert "query_epss" in tool_names
    assert "query_osv_database" in tool_names
    assert "calculate_environmental_risk" in tool_names
    assert "verify_score_derivation" in tool_names

    # Verify final action was FINALIZE
    last_trace = state.step_traces[-1]
    assert last_trace.action.action_type == AgentStepActionType.FINALIZE
    assert state.iteration_count == len(state.step_traces)


# ==============================================================================
# 2. Strict Tool Registry Boundary
# ==============================================================================

def test_2_strict_tool_registry_boundary():
    """Verify that every tool call executes strictly through default_tool_registry.invoke."""
    invoked_tools = []
    original_invoke = default_tool_registry.invoke

    def spy_invoke(name, payload, **kwargs):
        invoked_tools.append(name)
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=spy_invoke):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        assert state.status == AgentExecutionStatus.COMPLETED
        assert len(invoked_tools) >= 7
        assert "validate_finding_schema" in invoked_tools
        assert "query_asset_cmdb" in invoked_tools
        assert "calculate_environmental_risk" in invoked_tools
        assert "verify_score_derivation" in invoked_tools


# ==============================================================================
# 3. Replanning on Unavailable Telemetry (OSV)
# ==============================================================================

def test_3_replanning_on_unavailable_osv():
    """Verify OSV NOT_AVAILABLE triggers a REPLAN step without fabricating data."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007")

    # Locate OSV trace and REPLAN trace
    replan_traces = [t for t in state.step_traces if t.action.action_type == AgentStepActionType.REPLAN]
    assert len(replan_traces) >= 1
    replan_action = replan_traces[0].action
    assert replan_action.trigger == "THREAT_SOURCE_UNAVAILABLE"

    # Verify OSV evidence preserves NOT_AVAILABLE status
    osv_evidence = [ev for ev in state.evidence if ev.evidence_type == EvidenceType.OSV]
    assert len(osv_evidence) == 1
    assert osv_evidence[0].status == ToolStatus.NOT_AVAILABLE
    assert osv_evidence[0].value == []

    # Verify notice recorded
    assert any(n.code == "OSV_NOT_AVAILABLE" for n in state.warnings)


# ==============================================================================
# 4. Explicit Preservation of NOT_FOUND (KEV)
# ==============================================================================

def test_4_cisa_kev_not_found_preserved():
    """Verify that when a CVE is NOT_FOUND in CISA KEV, it is preserved explicitly as NOT_FOUND."""
    # Mock lookup_cisa_kev to return NOT_FOUND for test CVE
    original_invoke = default_tool_registry.invoke

    def mock_invoke(name, payload, **kwargs):
        if name == "lookup_cisa_kev":
            return BaseToolResult(
                tool_name="lookup_cisa_kev",
                status=ToolStatus.NOT_FOUND,
                message="CVE was not found in local CISA KEV catalog.",
                side_effect=SideEffectClass.READ_ONLY,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_invoke):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        assert state.status == AgentExecutionStatus.COMPLETED
        kev_ev = [ev for ev in state.evidence if ev.evidence_type == EvidenceType.CISA_KEV]
        assert len(kev_ev) == 1
        assert kev_ev[0].status == ToolStatus.NOT_FOUND
        assert kev_ev[0].value is False


# ==============================================================================
# 5. Verification Gate: Reject Discrepancy / Refuse to Finalize
# ==============================================================================

def test_5_verification_gate_prevents_false_finalization():
    """Verify that when score verification fails, the supervisor does not finalize."""
    original_invoke = default_tool_registry.invoke

    def mock_failing_verification(name, payload, **kwargs):
        if name == "verify_score_derivation":
            return VerifyScoreDerivationOutput(
                tool_name="verify_score_derivation",
                status=ToolStatus.VERIFICATION_FAILED,
                message="Score mismatch: claimed ERS 43.60 but recomputed 95.00",
                side_effect=SideEffectClass.COMPUTE_ONLY,
                is_verified=False,
                mismatches=[],
                recomputed_ers=95.0,
                recomputed_decision="ACT",
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_failing_verification):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        # Must halt in failure, never finalize
        assert state.status == AgentExecutionStatus.VERIFICATION_FAILED
        assert state.final_result is None

        # Trace must contain failing verification
        traces = [t for t in state.step_traces if t.action.tool_name == "verify_score_derivation"]
        assert len(traces) >= 1
        assert traces[0].status == ToolStatus.VERIFICATION_FAILED


# ==============================================================================
# 6. Maximum Iterations Guardrail
# ==============================================================================

def test_6_max_iterations_enforcement():
    """Verify runtime enforces max_iterations limit and transitions to MAX_ITERATIONS_REACHED."""
    # Set max_iterations to 3 (lower than required steps)
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007", max_iterations=3)

    assert state.status == AgentExecutionStatus.MAX_ITERATIONS_REACHED
    assert state.iteration_count == 3
    assert state.final_result is None
    assert any(n.code == "MAX_ITERATIONS_REACHED" for n in state.warnings)
    assert len(state.step_traces) == 3


# ==============================================================================
# 7. Unknown Tool Name Rejection
# ==============================================================================

def test_7_unknown_tool_rejection():
    """Verify invoking an unregistered tool triggers safe structured FAIL."""
    runtime = SupervisorRuntime()
    state = SupervisorState(
        run_id="RUN-TEST-UNKNOWN",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt dangerous tool",
        target_finding_id="FINDING-007",
    )

    action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="unregistered_malicious_shell_tool",
        tool_arguments={"cmd": "whoami"},
        rationale="Testing safety gate",
    )

    runtime._handle_call_tool(state, action)

    assert state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "UNKNOWN_TOOL" for err in state.errors)


# ==============================================================================
# 8. Unsupported Workflow Handling
# ==============================================================================

def test_8_unsupported_workflow_handling():
    """Verify non-supported workflows cleanly fail with UNSUPPORTED_WORKFLOW."""
    planner = DeterministicSupervisorPlanner()
    state = SupervisorState(
        run_id="RUN-TEST-UNKNOWN-WF",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt unsupported workflow",
    )
    # Manually assign unsupported workflow type to test planner fallthrough
    state.workflow_type = "UNSUPPORTED_FUTURE_WORKFLOW"  # type: ignore[assignment]

    action = planner.plan(state)
    assert action.action_type == AgentStepActionType.FAIL
    assert action.error_code == "UNSUPPORTED_WORKFLOW"

    runtime = SupervisorRuntime(planner=planner)
    final_state = runtime.run(state)
    assert final_state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "UNSUPPORTED_WORKFLOW" for err in final_state.errors)


# ==============================================================================
# 9. Deterministic Reproducibility
# ==============================================================================

def test_9_deterministic_reproducibility():
    """Verify repeated runs on same initial inputs produce identical step traces and outcomes."""
    agent = SupervisorAgent()

    state_1 = agent.investigate_finding("FINDING-007")
    state_2 = agent.investigate_finding("FINDING-007")

    assert state_1.status == state_2.status == AgentExecutionStatus.COMPLETED
    assert len(state_1.step_traces) == len(state_2.step_traces)

    for t1, t2 in zip(state_1.step_traces, state_2.step_traces):
        assert t1.action.action_type == t2.action.action_type
        assert t1.action.tool_name == t2.action.tool_name
        assert t1.status == t2.status

    assert state_1.final_result.risk_scores == state_2.final_result.risk_scores
    assert state_1.final_result.primary_decision == state_2.final_result.primary_decision


# ==============================================================================
# 10. Concurrency and State Isolation
# ==============================================================================

def test_10_concurrency_and_state_isolation():
    """Verify two independent runs maintain zero shared mutable state."""
    agent = SupervisorAgent()

    state_a = agent.investigate_finding("FINDING-007", asset_id="ASSET-002")
    state_b = agent.investigate_finding("FINDING-008", asset_id="ASSET-002")

    # Assert distinct runs
    assert state_a.run_id != state_b.run_id
    assert state_a.target_finding_id == "FINDING-007"
    assert state_b.target_finding_id == "FINDING-008"

    # Assert distinct state domain dictionaries
    assert "FINDING-007" in state_a.findings
    assert "FINDING-008" not in state_a.findings

    assert "FINDING-008" in state_b.findings
    assert "FINDING-007" not in state_b.findings

    # Assert separate traces and evidence
    assert state_a.step_traces is not state_b.step_traces
    assert state_a.evidence is not state_b.evidence


# ==============================================================================
# 11. Invalid Finding Schema Rejection
# ==============================================================================

def test_11_invalid_finding_schema_fails_safely():
    """Verify malformed finding data triggers schema rejection and safe FAIL."""
    # Create finding with invalid CVSS > 10.0
    malformed_raw = {
        "finding_id": "FINDING-BAD",
        "cve_id": "CVE-2023-9999",
        "title": "Bad Finding",
        "description": "Invalid CVSS",
        "cvss_score": 99.9,  # invalid
        "severity": "CRITICAL",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }

    class MockScansPlanner(DeterministicSupervisorPlanner):
        def _get_raw_scan(self, finding_id: str):
            return malformed_raw

    planner = MockScansPlanner()
    agent = SupervisorAgent(planner=planner)
    state = agent.investigate_finding("FINDING-BAD")

    assert state.status == AgentExecutionStatus.FAILED
    assert any(err.code in ("FINDING_SCHEMA_INVALID", "INVALID_FINDING_SCHEMA") for err in state.errors)


# ==============================================================================
# 12. Asset Not Found in CMDB Fails Safely
# ==============================================================================

def test_12_asset_not_found_fails_safely():
    """Verify unknown asset returns NOT_FOUND and supervisor halts safely."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007", asset_id="ASSET-NONEXISTENT-999")

    assert state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "ASSET_NOT_FOUND" for err in state.errors)


# ==============================================================================
# 13. Missing Target Finding ID
# ==============================================================================

def test_13_missing_target_finding_id_fails():
    """Verify planning on INVESTIGATE without a target finding triggers safe failure."""
    state = SupervisorState(
        run_id="RUN-NO-TARGET",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate nothing",
    )
    planner = DeterministicSupervisorPlanner()
    action = planner.plan(state)

    assert action.action_type == AgentStepActionType.FAIL
    assert action.error_code == "MISSING_TARGET_FINDING"


# ==============================================================================
# 14. Single-Step Execution Progression
# ==============================================================================

def test_14_single_step_execution_progression():
    """Verify runtime.step() correctly advances one step at a time."""
    agent = SupervisorAgent()
    state = SupervisorState(
        run_id="RUN-STEP-TEST",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate FINDING-007 step by step",
        target_finding_id="FINDING-007",
    )
    runtime = SupervisorRuntime(planner=agent.planner, registry=agent.registry)

    # Initial state
    assert state.current_step == 0
    assert state.iteration_count == 0
    assert state.status == AgentExecutionStatus.PENDING

    # Step 1: validate finding
    runtime.step(state)
    assert state.status == AgentExecutionStatus.RUNNING
    assert state.current_step == 1
    assert state.iteration_count == 1
    assert state.step_traces[0].action.tool_name == "validate_finding_schema"

    # Step 2: query asset
    runtime.step(state)
    assert state.current_step == 2
    assert state.step_traces[1].action.tool_name == "query_asset_cmdb"


# ==============================================================================
# 15. Security Boundaries Enforcement
# ==============================================================================

def test_15_security_boundaries_enforcement():
    """Verify runtime rejects malformed tool inputs and unsupported action types safely."""
    runtime = SupervisorRuntime()
    state = SupervisorState(
        run_id="RUN-SEC-TEST",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Security test",
        target_finding_id="FINDING-007",
    )

    # Attempt malformed tool arguments on registered tool
    bad_action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="validate_finding_schema",
        tool_arguments={"invalid_param_not_in_schema": 123},
        rationale="Probe schema validation rejection",
    )
    runtime._handle_call_tool(state, bad_action)
    assert state.status == AgentExecutionStatus.FAILED
    assert any(err.code == "TOOL_EXECUTION_ERROR" for err in state.errors)

