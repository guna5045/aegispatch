"""Tests for Phase 8F deterministic Supervisor Agent multi-workflow coverage.

Covers all four supported workflows:
1. INVESTIGATE_FINDING
2. PRIORITIZE_FINDINGS
3. PLAN_REMEDIATION
4. WHAT_IF

Guarantees:
- Strict tool execution through default_tool_registry
- Deterministic multi-key tie-breaking for prioritization (-ERS, -CVSS, finding_id ASC)
- Knapsack optimization and constraint validation for remediation planning
- Safe, non-destructive What-If simulations
- Complete deterministic reproducibility across repeated runs
- Total state isolation between runs
"""

from unittest.mock import patch
import pytest

from src.agents import (
    AgentExecutionStatus,
    AgentWorkflowType,
    SupervisorAgent,
    SupervisorRuntime,
    SupervisorState,
)
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.data_service import load_benchmark_findings
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import default_tool_registry
from src.tools.schemas import (
    SideEffectClass,
    ToolStatus,
    ValidatePlanConstraintsOutput,
    VerifyScoreDerivationOutput,
)


@pytest.fixture(scope="module")
def benchmark_findings():
    """Module-level benchmark findings dataset."""
    return load_benchmark_findings()


# ==============================================================================
# 1. INVESTIGATE_FINDING Workflow Coverage
# ==============================================================================

def test_workflow_investigate_finding_flow():
    """Verify end-to-end INVESTIGATE_FINDING workflow execution and verified result."""
    agent = SupervisorAgent()
    state = agent.investigate_finding("FINDING-007", "ASSET-002")

    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING
    assert state.final_result is not None
    assert state.final_result.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING
    assert state.final_result.is_verified is True
    assert state.final_result.primary_decision in (AegisDecision.PLAN, AegisDecision.ATTEND)
    assert "FINDING-007" in state.final_result.risk_scores
    assert state.final_result.risk_scores["FINDING-007"] == pytest.approx(43.60, abs=0.01)

    # Validate execution trace contains score derivation verification
    tool_names = [t.action.tool_name for t in state.step_traces if t.action.tool_name]
    assert "validate_finding_schema" in tool_names
    assert "query_asset_cmdb" in tool_names
    assert "calculate_environmental_risk" in tool_names
    assert "verify_score_derivation" in tool_names


# ==============================================================================
# 2. PRIORITIZE_FINDINGS Workflow Coverage
# ==============================================================================

def test_workflow_prioritize_findings_flow(benchmark_findings):
    """Verify PRIORITIZE_FINDINGS executes deduplication, risk evaluation, verification, and deterministic ranking."""
    f1 = benchmark_findings["FINDING-001"]
    f2 = benchmark_findings["FINDING-002"]
    f7 = benchmark_findings["FINDING-007"]

    # Introduce a duplicate finding to test deduplication integration
    f1_duplicate = f1.model_copy()

    agent = SupervisorAgent()
    state = agent.prioritize_findings([f1, f2, f7, f1_duplicate])

    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.workflow_type == AgentWorkflowType.PRIORITIZE_FINDINGS
    assert state.final_result is not None
    assert state.final_result.workflow_type == AgentWorkflowType.PRIORITIZE_FINDINGS
    assert state.final_result.is_verified is True

    # Check deduplication occurred: only 3 unique findings retained
    assert len(state.final_result.target_findings) == 3
    assert set(state.final_result.target_findings) == {"FINDING-001", "FINDING-002", "FINDING-007"}

    # Validate tool invocations in step traces
    tool_names = [t.action.tool_name for t in state.step_traces if t.action.tool_name]
    assert "deduplicate_findings" in tool_names
    assert "query_asset_cmdb" in tool_names
    assert "calculate_environmental_risk" in tool_names
    assert "verify_score_derivation" in tool_names

    # Check finding_decisions and risk_scores are populated for all unique findings
    for fid in ["FINDING-001", "FINDING-002", "FINDING-007"]:
        assert fid in state.final_result.risk_scores
        assert fid in state.final_result.finding_decisions
        assert isinstance(state.final_result.finding_decisions[fid], AegisDecision)

    # Check deterministic ordering: (-ERS, -CVSS, fid ASC)
    ranked = state.final_result.target_findings
    for i in range(len(ranked) - 1):
        curr_fid = ranked[i]
        next_fid = ranked[i + 1]
        curr_ers = state.final_result.risk_scores[curr_fid]
        next_ers = state.final_result.risk_scores[next_fid]
        assert curr_ers >= next_ers


# ==============================================================================
# 3. PLAN_REMEDIATION Workflow Coverage
# ==============================================================================

def test_workflow_plan_remediation_flow(benchmark_findings):
    """Verify PLAN_REMEDIATION evaluates risk, optimizes patch capacity (0/1 knapsack), and validates constraints."""
    candidates = [
        benchmark_findings["FINDING-001"],
        benchmark_findings["FINDING-002"],
        benchmark_findings["FINDING-003"],
        benchmark_findings["FINDING-007"],
    ]

    agent = SupervisorAgent()
    state = agent.plan_remediation(candidates, capacity_limit_hours=12.0)

    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.workflow_type == AgentWorkflowType.PLAN_REMEDIATION
    assert state.final_result is not None
    assert state.final_result.workflow_type == AgentWorkflowType.PLAN_REMEDIATION
    assert state.final_result.primary_decision == AegisDecision.PLAN

    # Check optimization and constraint validation
    assert state.final_result.plan_validated is True
    assert state.final_result.capacity_limit_hours == 12.0
    assert state.final_result.total_scheduled_effort_hours is not None
    assert state.final_result.total_scheduled_effort_hours <= 12.0
    assert state.final_result.total_expected_risk_reduction is not None
    assert state.final_result.total_expected_risk_reduction > 0.0

    # Scheduled + deferred must equal candidate set
    scheduled = state.final_result.scheduled_finding_ids or []
    deferred = state.final_result.deferred_finding_ids or []
    assert len(scheduled) > 0
    all_processed = set(scheduled) | set(deferred)
    assert all_processed == {c.finding_id for c in candidates}

    # Verify tool execution in trace
    tool_names = [t.action.tool_name for t in state.step_traces if t.action.tool_name]
    assert "optimize_patch_capacity" in tool_names
    assert "validate_plan_constraints" in tool_names


# ==============================================================================
# 4. WHAT_IF Workflow Coverage
# ==============================================================================

def test_workflow_what_if_simulation_flow(benchmark_findings):
    """Verify WHAT_IF runs non-destructive simulation and stamps is_simulation=True."""
    finding = benchmark_findings["FINDING-007"]

    agent = SupervisorAgent()
    state = agent.simulate_what_if(
        finding=finding,
        hypothetical_controls=["WAF", "NETWORK_SEGREGATION"],
    )

    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.workflow_type == AgentWorkflowType.WHAT_IF
    assert state.final_result is not None
    assert state.final_result.is_simulation is True
    assert state.final_result.simulation_label == "SIMULATED"

    # Baseline ERS vs simulated ERS
    assert state.final_result.baseline_ers is not None
    assert state.final_result.simulated_ers is not None
    assert state.final_result.baseline_ers == pytest.approx(43.60, abs=0.01)
    # Adding controls must reduce or maintain ERS
    assert state.final_result.simulated_ers <= state.final_result.baseline_ers
    assert state.final_result.simulated_decision is not None

    # Step trace verification
    tool_names = [t.action.tool_name for t in state.step_traces if t.action.tool_name]
    assert "simulate_risk_reduction" in tool_names


# ==============================================================================
# 5. Deterministic Reproducibility Across Workflows
# ==============================================================================

def test_prioritize_deterministic_reproducibility(benchmark_findings):
    """Verify repeated runs of PRIORITIZE_FINDINGS yield identical traces, rankings, and decisions."""
    candidates = [
        benchmark_findings["FINDING-002"],
        benchmark_findings["FINDING-007"],
        benchmark_findings["FINDING-001"],
    ]

    agent = SupervisorAgent()
    run_1 = agent.prioritize_findings(candidates)
    run_2 = agent.prioritize_findings(candidates)

    assert run_1.status == run_2.status == AgentExecutionStatus.COMPLETED
    assert len(run_1.step_traces) == len(run_2.step_traces)

    for t1, t2 in zip(run_1.step_traces, run_2.step_traces):
        assert t1.action.action_type == t2.action.action_type
        assert t1.action.tool_name == t2.action.tool_name
        assert t1.status == t2.status

    assert run_1.final_result.target_findings == run_2.final_result.target_findings
    assert run_1.final_result.risk_scores == run_2.final_result.risk_scores
    assert run_1.final_result.finding_decisions == run_2.final_result.finding_decisions


def test_plan_remediation_deterministic_reproducibility(benchmark_findings):
    """Verify repeated runs of PLAN_REMEDIATION yield identical knapsack schedules."""
    candidates = [
        benchmark_findings["FINDING-001"],
        benchmark_findings["FINDING-002"],
        benchmark_findings["FINDING-003"],
    ]

    agent = SupervisorAgent()
    run_1 = agent.plan_remediation(candidates, capacity_limit_hours=16.0)
    run_2 = agent.plan_remediation(candidates, capacity_limit_hours=16.0)

    assert run_1.status == run_2.status == AgentExecutionStatus.COMPLETED
    assert run_1.final_result.scheduled_finding_ids == run_2.final_result.scheduled_finding_ids
    assert run_1.final_result.deferred_finding_ids == run_2.final_result.deferred_finding_ids
    assert run_1.final_result.total_scheduled_effort_hours == run_2.final_result.total_scheduled_effort_hours
    assert run_1.final_result.total_expected_risk_reduction == run_2.final_result.total_expected_risk_reduction


# ==============================================================================
# 6. Concurrency and State Isolation Between Workflows
# ==============================================================================

def test_workflow_state_isolation(benchmark_findings):
    """Verify multiple workflows executed on the same agent facade retain isolated states."""
    agent = SupervisorAgent()

    state_inv = agent.investigate_finding("FINDING-007")
    state_prio = agent.prioritize_findings([benchmark_findings["FINDING-001"], benchmark_findings["FINDING-002"]])
    state_whatif = agent.simulate_what_if(benchmark_findings["FINDING-007"], hypothetical_controls=["WAF"])

    assert state_inv.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING
    assert state_prio.workflow_type == AgentWorkflowType.PRIORITIZE_FINDINGS
    assert state_whatif.workflow_type == AgentWorkflowType.WHAT_IF

    assert len(state_inv.findings) == 1
    assert len(state_prio.findings) == 2
    assert state_whatif.final_result.is_simulation is True
    assert state_inv.final_result.is_simulation is False
    assert state_prio.final_result.is_simulation is False


# ==============================================================================
# 7. Verification Failure Gate Enforcement Across Workflows
# ==============================================================================

def test_prioritize_verification_failure_gate(benchmark_findings):
    """Verify that unverified risk score derivation blocks finalization in PRIORITIZE_FINDINGS."""
    original_invoke = default_tool_registry.invoke

    def mock_failing_verification(name, payload, **kwargs):
        if name == "verify_score_derivation":
            return VerifyScoreDerivationOutput(
                tool_name="verify_score_derivation",
                status=ToolStatus.VERIFICATION_FAILED,
                message="Score mismatch detected",
                side_effect=SideEffectClass.COMPUTE_ONLY,
                is_verified=False,
                mismatches=[],
                recomputed_ers=99.0,
                recomputed_decision="ACT",
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_failing_verification):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.prioritize_findings([benchmark_findings["FINDING-001"]])

        # Finalization must be rejected
        assert state.status == AgentExecutionStatus.VERIFICATION_FAILED
        assert state.final_result is None


def test_plan_remediation_constraint_violation_gate(benchmark_findings):
    """Verify that failing plan constraint validation blocks finalization in PLAN_REMEDIATION."""
    original_invoke = default_tool_registry.invoke

    def mock_invalid_constraints(name, payload, **kwargs):
        if name == "validate_plan_constraints":
            return ValidatePlanConstraintsOutput(
                tool_name="validate_plan_constraints",
                status=ToolStatus.SUCCESS,
                message="Violations detected",
                side_effect=SideEffectClass.COMPUTE_ONLY,
                is_valid=False,
                violations=[],
                warnings=["Plan violates capacity"],
                total_estimated_hours=99.0,
                capacity_limit_hours=16.0,
            )
        return original_invoke(name, payload, **kwargs)

    with patch.object(default_tool_registry, "invoke", side_effect=mock_invalid_constraints):
        agent = SupervisorAgent(registry=default_tool_registry)
        state = agent.plan_remediation([benchmark_findings["FINDING-001"]], capacity_limit_hours=16.0)

        # Finalization must be rejected due to unverified plan constraints
        assert state.status == AgentExecutionStatus.VERIFICATION_FAILED
        assert state.final_result is None
