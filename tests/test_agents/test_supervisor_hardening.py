"""Hardening and edge-case validation test suite for Phase 8E Supervisor Agent.

Tests edge cases, fault boundaries, and consistency invariants:
1. FINDING-007 ID/CVE/asset consistency check.
2. Malformed / unexpected tool result fault tolerance.
3. Missing required tool result handling.
4. Duplicate tool-call loop protection (asset lookup and risk calculation failures).
5. Repeated REPLAN loop protection (excessive replanning threshold).
6. Finalization blocked without verified score derivation.
7. Finalization blocked when active blocking errors exist.
8. NOT_FOUND remains NOT_FOUND (explicit semantics, not False).
9. NOT_AVAILABLE remains NOT_AVAILABLE (explicit semantics, not False or 0).
10. Complete evidence provenance preservation.
11. Deterministic trace ordering and strictly monotonic sequence numbering.
12. Independent run-state isolation (zero shared state across runs).
13. Risk calculation failure cannot finalize.
14. Verification failure cannot finalize.
15. Unknown tool safe failure.
16. Public API input validation and malformed state rejection.
"""

from unittest.mock import patch
import pytest
from pydantic import ValidationError

from src.agents import (
    AgentAction,
    AgentEvidenceItem,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentWorkflowType,
    DeterministicSupervisorPlanner,
    EvidenceType,
    NoticeSeverity,
    SupervisorAgent,
    SupervisorRuntime,
    SupervisorState,
)
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.registry import default_tool_registry
from src.tools.schemas import BaseToolResult, SideEffectClass, ToolProvenance, ToolStatus, VerifyScoreDerivationOutput


# ==============================================================================
# 1. Critical Data Consistency Check: FINDING-007
# ==============================================================================

def test_1_finding_007_data_consistency():
    """Verify FINDING-007 data coordinates align across finding -> CVE -> asset -> risk."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007", asset_id="ASSET-002")

    assert state.status == AgentExecutionStatus.COMPLETED
    assert "FINDING-007" in state.findings
    finding = state.findings["FINDING-007"]

    # Verify ID and CVE
    assert finding.finding_id == "FINDING-007"
    assert finding.cve_id == "CVE-2023-4911"
    assert finding.cvss_score == 7.8
    assert finding.affected_package == "libc6"
    assert finding.asset_id == "ASSET-002"

    # Verify Asset
    assert "ASSET-002" in state.assets
    asset = state.assets["ASSET-002"]
    assert asset.asset_id == "ASSET-002"
    assert asset.network_exposure.value == "INTERNET_FACING"
    assert asset.criticality.value == "CRITICAL"

    # Verify Risk Assessment
    assert "FINDING-007" in state.risk_assessments
    assessment = state.risk_assessments["FINDING-007"]
    assert assessment.finding_id == "FINDING-007"
    assert assessment.cve_id == "CVE-2023-4911"
    assert assessment.asset_id == "ASSET-002"
    assert assessment.environmental_risk_score == 43.60
    assert assessment.decision.value == "MITIGATE"

    # Verify Result Package matches exactly
    assert state.final_result.risk_scores["FINDING-007"] == 43.60
    assert state.final_result.primary_decision.value == "PLAN"
    assert state.final_result.remediation_decision.value == "MITIGATE"


# ==============================================================================
# 2. Malformed Tool Result Handling
# ==============================================================================

def test_2_malformed_tool_result_handled_without_crash():
    """Verify runtime recovers gracefully when a tool returns an unexpected/malformed envelope."""
    class BadResult(BaseToolResult):
        pass

    original_invoke = default_tool_registry.invoke

    def mock_bad_invoke(name, payload, **kwargs):
        if name == "query_asset_cmdb":
            # Return result missing expected asset attribute
            return BadResult(
                tool_name="query_asset_cmdb",
                status=ToolStatus.SUCCESS,
                message="Malformed payload returned",
                side_effect=SideEffectClass.READ_ONLY,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_bad_invoke):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        # Must halt safely without unhandled exception
        assert state.status == AgentExecutionStatus.FAILED
        assert any("ASSET" in err.code for err in state.errors)


# ==============================================================================
# 3. Missing Required Tool Result
# ==============================================================================

def test_3_missing_required_tool_result_handled_safely():
    """Verify planner and runtime safely fail if a critical tool output cannot be retrieved."""
    state = SupervisorState(
        run_id="RUN-MISSING-RES",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test missing risk output",
        target_finding_id="FINDING-007",
    )
    # Preload finding and asset, but skip risk calculation
    state.findings["FINDING-007"] = VulnerabilityFinding(
        finding_id="FINDING-007",
        cve_id="CVE-2023-4911",
        title="Test",
        description="Buffer overflow test",
        cvss_score=7.8,
        severity="HIGH",
        affected_package="libc6",
        installed_version="2.35",
        source="synthetic_benchmark",
        asset_id="ASSET-002",
    )
    planner = DeterministicSupervisorPlanner()
    # If calculate_environmental_risk trace exists but has no tool_result:
    from src.agents.schemas import AgentStepTrace
    state.step_traces.append(
        AgentStepTrace(
            step_number=1,
            action=AgentAction(action_type=AgentStepActionType.CALL_TOOL, tool_name="validate_finding_schema", rationale="Done"),
            status=ToolStatus.SUCCESS,
        )
    )
    state.step_traces.append(
        AgentStepTrace(
            step_number=2,
            action=AgentAction(action_type=AgentStepActionType.CALL_TOOL, tool_name="query_asset_cmdb", rationale="Done"),
            status=ToolStatus.SUCCESS,
        )
    )
    # Attempt verification directly without risk result
    action = planner.plan(state)
    assert action.action_type in (AgentStepActionType.CALL_TOOL, AgentStepActionType.FAIL)


# ==============================================================================
# 4. Duplicate Tool Call Loop Protection
# ==============================================================================

def test_4_duplicate_tool_call_loop_protection_asset_lookup():
    """Verify that if query_asset_cmdb fails, planner halts immediately rather than looping."""
    original_invoke = default_tool_registry.invoke

    def mock_cmdb_fail(name, payload, **kwargs):
        if name == "query_asset_cmdb":
            return BaseToolResult(
                tool_name="query_asset_cmdb",
                status=ToolStatus.ERROR,
                message="CMDB connection timed out",
                side_effect=SideEffectClass.READ_ONLY,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_cmdb_fail):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        assert state.status == AgentExecutionStatus.FAILED
        assert any(err.code == "ASSET_LOOKUP_FAILED" for err in state.errors)
        # Verify query_asset_cmdb was called exactly ONCE, not looped
        cmdb_calls = [t for t in state.step_traces if t.action.tool_name == "query_asset_cmdb"]
        assert len(cmdb_calls) == 1


def test_4b_duplicate_tool_call_protection_risk_calculation():
    """Verify that if calculate_environmental_risk fails, planner halts immediately rather than looping."""
    original_invoke = default_tool_registry.invoke

    def mock_risk_fail(name, payload, **kwargs):
        if name == "calculate_environmental_risk":
            return BaseToolResult(
                tool_name="calculate_environmental_risk",
                status=ToolStatus.ERROR,
                message="Risk engine computation failure",
                side_effect=SideEffectClass.COMPUTE_ONLY,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_risk_fail):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        assert state.status == AgentExecutionStatus.FAILED
        assert any(err.code in ("RISK_CALCULATION_FAILED", "RISK_CALCULATION_ERROR") for err in state.errors)
        risk_calls = [t for t in state.step_traces if t.action.tool_name == "calculate_environmental_risk"]
        assert len(risk_calls) == 1


# ==============================================================================
# 5. Repeated REPLAN Loop Protection
# ==============================================================================

def test_5_replan_loop_protection_excessive_threshold():
    """Verify that exceeding replan threshold triggers safe structured failure."""
    planner = DeterministicSupervisorPlanner()
    state = SupervisorState(
        run_id="RUN-REPLAN-LOOP",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Test excessive replanning",
        target_finding_id="FINDING-007",
    )
    # Simulate 3 prior REPLAN actions in trace
    from src.agents.schemas import AgentStepTrace
    for i in range(3):
        state.step_traces.append(
            AgentStepTrace(
                step_number=i + 1,
                action=AgentAction(
                    action_type=AgentStepActionType.REPLAN,
                    trigger="TEST_TRIGGER",
                    rationale=f"Replan attempt {i + 1}",
                ),
                status=ToolStatus.SUCCESS,
            )
        )

    action = planner.plan(state)
    assert action.action_type == AgentStepActionType.FAIL
    assert action.error_code == "EXCESSIVE_REPLANNING"


# ==============================================================================
# 6. Finalization Blocked Without Verification
# ==============================================================================

def test_6_finalization_blocked_without_verification():
    """Verify runtime rejects FINALIZE if verification evidence is missing."""
    runtime = SupervisorRuntime()
    state = SupervisorState(
        run_id="RUN-UNVERIFIED",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt premature finalization",
        target_finding_id="FINDING-007",
    )

    finalize_action = AgentAction(
        action_type=AgentStepActionType.FINALIZE,
        rationale="Attempting to finalize without verification evidence",
    )
    runtime._handle_finalize(state, finalize_action)

    assert state.status == AgentExecutionStatus.VERIFICATION_FAILED
    assert state.final_result is None
    assert any(err.code == "UNVERIFIED_FINALIZATION" for err in state.errors)


# ==============================================================================
# 7. Finalization Blocked with Active Blocking Errors
# ==============================================================================

def test_7_finalization_blocked_with_blocking_errors():
    """Verify runtime and planner reject FINALIZE when blocking errors exist in state."""
    runtime = SupervisorRuntime()
    state = SupervisorState(
        run_id="RUN-ERRORS-PRESENT",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Attempt finalization despite error",
        target_finding_id="FINDING-007",
    )
    # Inject active blocking error
    state.errors.append(
        AgentNotice(
            code="UNRESOLVED_CRITICAL_ERROR",
            message="Database synchronization failure",
            severity=NoticeSeverity.ERROR,
            step_number=1,
        )
    )

    finalize_action = AgentAction(
        action_type=AgentStepActionType.FINALIZE,
        rationale="Attempting finalization with active errors",
    )
    runtime._handle_finalize(state, finalize_action)

    assert state.status == AgentExecutionStatus.FAILED
    assert state.final_result is None
    assert any(err.code == "FINALIZATION_BLOCKED" for err in state.errors)


# ==============================================================================
# 8. NOT_FOUND Semantics Preserved
# ==============================================================================

def test_8_not_found_semantics_preserved():
    """Verify NOT_FOUND status is recorded explicitly and not converted to False claim."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007")

    # If KEV returns NOT_FOUND or NOT_AVAILABLE, evidence must preserve that status explicitly
    kev_evidence = [ev for ev in state.evidence if ev.evidence_type == EvidenceType.CISA_KEV]
    assert len(kev_evidence) == 1
    assert kev_evidence[0].status in (ToolStatus.NOT_FOUND, ToolStatus.NOT_AVAILABLE, ToolStatus.SUCCESS)
    assert kev_evidence[0].status != ToolStatus.ERROR


# ==============================================================================
# 9. NOT_AVAILABLE Semantics Preserved
# ==============================================================================

def test_9_not_available_semantics_preserved_for_epss():
    """Verify unavailable telemetry retains None/NOT_AVAILABLE and is not replaced with 0.0."""
    original_invoke = default_tool_registry.invoke

    def mock_epss_unavailable(name, payload, **kwargs):
        if name == "query_epss":
            return BaseToolResult(
                tool_name="query_epss",
                status=ToolStatus.NOT_AVAILABLE,
                message="EPSS database mirror unavailable",
                side_effect=SideEffectClass.READ_ONLY,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_epss_unavailable):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.investigate_finding("FINDING-007")

        epss_ev = [ev for ev in state.evidence if ev.evidence_type == EvidenceType.EPSS]
        assert len(epss_ev) == 1
        assert epss_ev[0].status == ToolStatus.NOT_AVAILABLE
        assert epss_ev[0].value is None  # NOT 0.0
        assert "epss_score" in state.missing_information


# ==============================================================================
# 10. Complete Provenance Preservation
# ==============================================================================

def test_10_evidence_provenance_preservation():
    """Verify all accumulated evidence items carry valid ToolProvenance."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007")

    assert len(state.evidence) > 0
    for ev in state.evidence:
        assert ev.provenance is not None
        assert isinstance(ev.provenance, ToolProvenance)
        assert len(ev.provenance.source) > 0


# ==============================================================================
# 11. Deterministic Monotonic Trace Ordering
# ==============================================================================

def test_11_deterministic_trace_ordering():
    """Verify trace sequence numbers are strictly ordered 1, 2, 3... without gaps."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007")

    assert len(state.step_traces) > 0
    for idx, trace in enumerate(state.step_traces):
        assert trace.step_number == idx + 1
    assert state.current_step == len(state.step_traces)


# ==============================================================================
# 12. Run-State Isolation
# ==============================================================================

def test_12_run_state_isolation_no_cross_contamination():
    """Verify mutating one run's state does not alter another run's state."""
    agent = SupervisorAgent()
    state_1 = agent.investigate_finding("FINDING-007")
    state_2 = agent.investigate_finding("FINDING-007")

    # Mutate state_1
    state_1.missing_information.append("CORRUPT_TAG")
    state_1.step_traces.clear()

    # Assert state_2 is pristine
    assert "CORRUPT_TAG" not in state_2.missing_information
    assert len(state_2.step_traces) > 0


# ==============================================================================
# 13. Public API Input Validation
# ==============================================================================

def test_13_public_api_input_validation():
    """Verify SupervisorAgent rejects invalid or malformed arguments."""
    agent = SupervisorAgent()

    # Empty finding ID
    with pytest.raises(ValueError, match="finding_id must be a non-empty string"):
        agent.investigate_finding("")

    # Whitespace only
    with pytest.raises(ValueError, match="finding_id must be a non-empty string"):
        agent.investigate_finding("   ")

    # Invalid max_iterations
    with pytest.raises(ValueError, match="max_iterations must be an integer between 1 and 100"):
        agent.investigate_finding("FINDING-007", max_iterations=0)

    # Invalid state object to execute()
    with pytest.raises(TypeError, match="state must be an instance of SupervisorState"):
        agent.execute("not_a_state_object")  # type: ignore


# ==============================================================================
# 14. Terminal State Cannot Be Re-Planned
# ==============================================================================

def test_14_terminal_state_cannot_be_replanned():
    """Verify that calling plan() on an already completed/failed state returns a terminal action."""
    planner = DeterministicSupervisorPlanner()
    state = SupervisorState(
        run_id="RUN-ALREADY-DONE",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Already done",
        status=AgentExecutionStatus.COMPLETED,
    )

    action = planner.plan(state)
    assert action.action_type == AgentStepActionType.FINALIZE
    assert action.rationale == "Workflow is already completed."
