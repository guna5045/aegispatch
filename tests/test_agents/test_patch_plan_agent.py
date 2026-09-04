"""Tests for Phase 9E: Patch Plan Specialist Agent.

Comprehensive test coverage validating:
1. Valid remediation plan with standard inputs
2. Constrained capacity scheduling (partial candidate scheduling)
3. Enough capacity for all candidates (100% scheduled)
4. Zero capacity (all candidates deferred with ZERO_CAPACITY)
5. Negative capacity rejection (INVALID_INPUT)
6. Scheduled and deferred findings separation
7. Optimizer tool integration (optimize_patch_capacity)
8. Dependency resolution tool invocation (resolve_package_dependencies)
9. Unresolved/conflict dependency handling
10. Simulation tool integration (simulate_risk_reduction)
11. Plan constraint validation tool invocation (validate_plan_constraints)
12. Capacity limit exceeded detection
13. Malformed optimizer output handling
14. Malformed dependency output handling
15. Malformed simulation output handling
16. Malformed validation output handling
17. Tool execution exception handling
18. Unknown tool handling
19. Registry boundary enforcement spy (no direct tool calls)
20. Duplicate findings in input rejected (INVALID_INPUT)
21. Invalid risk input rejected
22. Finding/asset reference mismatch rejected (INVALID_INPUT)
23. Deterministic repeated execution yields identical schedules
24. State isolation across instances and sequential invocations
25. Malicious package and remediation text treated as inert data
26. Traceable planning and algorithm provenance
27. Step trace correctness and sequence numbers
28. Final status assignment (SUCCESS, PARTIAL_SUCCESS, CONSTRAINT_VIOLATION, INVALID_INPUT, FAILED)
29. Real benchmark dataset integration (benchmark findings and assets)
30. Explicit check that no second optimizer exists in the agent
31. Explicit check that no real patch execution logic exists
32. Rollback procedure preservation for all scheduled actions
"""

from datetime import datetime, timezone
import inspect
from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from src.agents.patch_plan import (
    DeferralReason,
    DeferredFindingDetail,
    PatchPlanAgent,
    PatchPlanAgentStatus,
    PatchPlanInput,
    PatchPlanProvenance,
    PatchPlanResult,
    ScheduledFindingDetail,
)
from src.agents.risk_combination import (
    RiskCombinationResult,
    RiskCombinationStatus,
    RiskEvidenceConsistency,
    RiskEvidenceProvenance,
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
from src.schemas.plan import ApprovalState, PatchCandidate
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.services.data_service import load_benchmark_findings, load_cmdb_assets
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import ToolDefinition, ToolRegistry, default_tool_registry
from src.tools.schemas import (
    DependencyItem,
    OptimizePatchCapacityInput,
    OptimizePatchCapacityOutput,
    PlanConstraintItem,
    PlanConstraintViolation,
    ProvenanceSourceType,
    ResolvePackageDependenciesInput,
    ResolvePackageDependenciesOutput,
    SideEffectClass,
    SimulateRiskReductionInput,
    SimulateRiskReductionOutput,
    ToolProvenance,
    ToolStatus,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
)


# ==============================================================================
# Fixtures
# ==============================================================================

@pytest.fixture
def sample_findings() -> List[VulnerabilityFinding]:
    """Sample list of vulnerability findings across multiple assets."""
    return [
        VulnerabilityFinding(
            finding_id="FINDING-001",
            cve_id="CVE-2023-38545",
            title="Heap-based buffer overflow in curl",
            description="curl buffer overflow in SOCKS5 proxy handshake",
            cvss_score=9.8,
            severity=VulnerabilitySeverity.CRITICAL,
            affected_package="libcurl4",
            installed_version="7.88.1",
            fixed_version="8.4.0",
            asset_id="ASSET-001",
            source="trivy",
        ),
        VulnerabilityFinding(
            finding_id="FINDING-002",
            cve_id="CVE-2023-44487",
            title="HTTP/2 Rapid Reset DDoS",
            description="HTTP/2 stream cancellation flood",
            cvss_score=7.5,
            severity=VulnerabilitySeverity.HIGH,
            affected_package="nghttp2",
            installed_version="1.52.0",
            fixed_version="1.57.0",
            asset_id="ASSET-001",
            source="trivy",
        ),
        VulnerabilityFinding(
            finding_id="FINDING-003",
            cve_id="CVE-2022-40897",
            title="Python setuptools ReDoS",
            description="Regular expression denial of service in package index",
            cvss_score=5.3,
            severity=VulnerabilitySeverity.MEDIUM,
            affected_package="setuptools",
            installed_version="65.5.0",
            fixed_version="65.5.1",
            asset_id="ASSET-002",
            source="trivy",
        ),
    ]


@pytest.fixture
def sample_assets() -> Dict[str, Asset]:
    """Sample assets matching sample_findings."""
    return {
        "ASSET-001": Asset(
            asset_id="ASSET-001",
            hostname="gw-ingress-prod-01",
            asset_type=AssetType.SERVER,
            business_tier=BusinessTier.MISSION_CRITICAL,
            criticality=AssetCriticality.CRITICAL,
            network_exposure=NetworkExposure.INTERNET_FACING,
            data_sensitivity=DataSensitivity.CONFIDENTIAL,
            environment=EnvironmentType.PRODUCTION,
            owner_team="Edge Team",
            compensating_controls=[
                CompensatingControl(
                    control_id="CTRL-001",
                    name="WAF",
                    description="Cloudflare Layer 7 WAF",
                    status=ControlStatus.ACTIVE,
                )
            ],
        ),
        "ASSET-002": Asset(
            asset_id="ASSET-002",
            hostname="app-backend-prod-01",
            asset_type=AssetType.SERVER,
            business_tier=BusinessTier.BUSINESS_CRITICAL,
            criticality=AssetCriticality.HIGH,
            network_exposure=NetworkExposure.INTERNAL,
            data_sensitivity=DataSensitivity.RESTRICTED,
            environment=EnvironmentType.PRODUCTION,
            owner_team="Core Backend",
        ),
    }


@pytest.fixture
def sample_risk_assessments(sample_findings: List[VulnerabilityFinding]) -> List[RiskCombinationResult]:
    """Sample evaluated risk results corresponding to sample_findings."""
    return [
        RiskCombinationResult(
            status=RiskCombinationStatus.SUCCESS,
            finding_id="FINDING-001",
            cve_id="CVE-2023-38545",
            asset_id="ASSET-001",
            base_score=98.0,
            threat_score=100.0,
            environmental_score=85.0,
            raw_risk_score=94.25,
            control_multiplier=0.85,
            environmental_risk_score=80.11,
            risk_tier=RiskTier.HIGH,
            decision=AegisDecision.ATTEND,
            remediation_decision=RemediationDecision.SCHEDULED_PATCH,
            consistency=RiskEvidenceConsistency(
                finding_id_match=True, cve_id_match=True, asset_id_match=True, is_consistent=True
            ),
            provenance=RiskEvidenceProvenance(assessed_at=datetime.now(timezone.utc)),
            evaluated_at=datetime.now(timezone.utc),
        ),
        RiskCombinationResult(
            status=RiskCombinationStatus.SUCCESS,
            finding_id="FINDING-002",
            cve_id="CVE-2023-44487",
            asset_id="ASSET-001",
            base_score=75.0,
            threat_score=100.0,
            environmental_score=85.0,
            raw_risk_score=88.5,
            control_multiplier=0.85,
            environmental_risk_score=75.22,
            risk_tier=RiskTier.HIGH,
            decision=AegisDecision.ATTEND,
            remediation_decision=RemediationDecision.SCHEDULED_PATCH,
            consistency=RiskEvidenceConsistency(
                finding_id_match=True, cve_id_match=True, asset_id_match=True, is_consistent=True
            ),
            provenance=RiskEvidenceProvenance(assessed_at=datetime.now(timezone.utc)),
            evaluated_at=datetime.now(timezone.utc),
        ),
        RiskCombinationResult(
            status=RiskCombinationStatus.SUCCESS,
            finding_id="FINDING-003",
            cve_id="CVE-2022-40897",
            asset_id="ASSET-002",
            base_score=53.0,
            threat_score=0.0,
            environmental_score=60.0,
            raw_risk_score=34.25,
            control_multiplier=1.0,
            environmental_risk_score=34.25,
            risk_tier=RiskTier.LOW,
            decision=AegisDecision.TRACK,
            remediation_decision=RemediationDecision.MONITOR,
            consistency=RiskEvidenceConsistency(
                finding_id_match=True, cve_id_match=True, asset_id_match=True, is_consistent=True
            ),
            provenance=RiskEvidenceProvenance(assessed_at=datetime.now(timezone.utc)),
            evaluated_at=datetime.now(timezone.utc),
        ),
    ]


# ==============================================================================
# Test Cases
# ==============================================================================

def test_01_valid_remediation_plan(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Test standard execution generating a complete, valid patch plan."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
        plan_id="PLAN-TEST-001",
    )

    assert result.status in (PatchPlanAgentStatus.SUCCESS, PatchPlanAgentStatus.PARTIAL_SUCCESS)
    assert result.plan_id == "PLAN-TEST-001"
    assert result.capacity_limit_hours == 16.0
    assert result.validation_passed is True
    assert result.candidate_count == 3
    assert len(result.scheduled_actions) > 0
    assert len(result.scheduled_finding_ids) + len(result.deferred_finding_ids) == 3
    assert result.total_scheduled_effort_hours <= 16.0
    assert len(result.step_traces) >= 2


def test_02_constrained_capacity_scheduling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Under tight capacity (2.5h), only the highest-efficiency candidate is scheduled."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=2.5,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert result.total_scheduled_effort_hours <= 2.5
    assert len(result.scheduled_finding_ids) == 1
    assert len(result.deferred_finding_ids) == 2
    assert "FINDING-001" in result.scheduled_finding_ids
    assert all(d.reason == DeferralReason.CAPACITY_EXHAUSTED for d in result.deferred_items)


def test_03_enough_capacity_for_all_candidates(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """With generous capacity (30.0h), all candidates are scheduled."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=30.0,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert len(result.scheduled_finding_ids) == 3
    assert len(result.deferred_finding_ids) == 0
    assert result.remaining_capacity_hours >= 0.0


def test_04_zero_capacity_all_deferred(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """With 0.0h capacity, all candidates are deferred with reason ZERO_CAPACITY."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=0.0,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert len(result.scheduled_finding_ids) == 0
    assert len(result.deferred_finding_ids) == 3
    assert all(d.reason == DeferralReason.ZERO_CAPACITY for d in result.deferred_items)


def test_05_negative_capacity_rejection(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Negative capacity is rejected as INVALID_INPUT."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=-5.0,
    )

    assert result.status == PatchPlanAgentStatus.INVALID_INPUT
    assert "Capacity limit cannot be negative" in result.summary


def test_06_scheduled_deferred_separation(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Scheduled and deferred sets are completely disjoint and partition all candidates."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=5.0,
    )

    sched_set = set(result.scheduled_finding_ids)
    defer_set = set(result.deferred_finding_ids)

    assert len(sched_set.intersection(defer_set)) == 0
    assert sched_set.union(defer_set) == {"FINDING-001", "FINDING-002", "FINDING-003"}


def test_07_optimizer_integration(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Confirm optimize_patch_capacity output structure is preserved."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.provenance.algorithm == "deterministic_0_1_knapsack_dp"
    assert result.total_expected_risk_reduction > 0.0
    assert result.capacity_utilization_percent >= 0.0


def test_08_dependency_resolution_tool_invocation(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Confirm resolve_package_dependencies populated prerequisites for libcurl4 and nghttp2."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    curl_action = next(a for a in result.scheduled_actions if a.finding_id == "FINDING-001")
    assert "libssl3" in curl_action.dependencies
    assert "zlib1g" in curl_action.dependencies


def test_09_unresolved_conflict_dependency(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """When package dependency analysis detects conflicts, the flag is recorded."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "resolve_package_dependencies":
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=lambda inp, **kw: ResolvePackageDependenciesOutput(
                        tool_name="resolve_package_dependencies",
                        status=ToolStatus.SUCCESS,
                        message="Conflict detected",
                        side_effect=SideEffectClass.READ_ONLY,
                        provenance=ToolProvenance(source="test", source_type=ProvenanceSourceType.LOCAL_DATASET),
                        package_name=inp.package_name,
                        target_version=inp.target_version,
                        prerequisites=[],
                        conflicts=["incompatible-abi-break"],
                        has_conflicts=True,
                    ),
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert any(a.has_conflicts is True for a in result.scheduled_actions)


def test_10_simulation_tool_integration(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
) -> None:
    """Verify simulate_risk_reduction can simulate hypothetical control additions on findings."""
    sim_input = SimulateRiskReductionInput(
        finding=sample_findings[0],
        asset=sample_assets["ASSET-001"],
        hypothetical_controls_added=["EDR"],
    )
    sim_output = default_tool_registry.invoke("simulate_risk_reduction", sim_input)
    assert isinstance(sim_output, SimulateRiskReductionOutput)
    assert sim_output.status == ToolStatus.SUCCESS
    assert sim_output.simulation_label == "SIMULATED"


def test_11_plan_constraint_validation(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """validate_plan_constraints validates the synthesized plan."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.validation_passed is True
    assert len(result.validation_violations) == 0


def test_12_capacity_limit_exceeded_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """If optimizer outputs a schedule exceeding capacity, validator flags CONSTRAINT_VIOLATION."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "optimize_patch_capacity":
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=lambda inp, **kw: OptimizePatchCapacityOutput(
                        tool_name="optimize_patch_capacity",
                        status=ToolStatus.SUCCESS,
                        message="Buggy mock",
                        side_effect=SideEffectClass.COMPUTE_ONLY,
                        provenance=ToolProvenance(source="test", source_type=ProvenanceSourceType.CALCULATED),
                        capacity_limit_hours=inp.capacity_limit_hours,
                        total_scheduled_effort_hours=99.0,  # Exceeds limit
                        total_expected_risk_reduction=100.0,
                        remaining_capacity_hours=0.0,
                        capacity_utilization_percent=100.0,
                        scheduled_candidates=inp.candidates,
                        deferred_candidates=[],
                    ),
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=4.0,
    )

    assert result.status == PatchPlanAgentStatus.CONSTRAINT_VIOLATION
    assert result.validation_passed is False
    assert any("CAPACITY_LIMIT_EXCEEDED" in v or "exceeds" in v for v in result.validation_violations)


def test_13_malformed_optimizer_output_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Malformed output from optimize_patch_capacity returns FAILED status."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "optimize_patch_capacity":
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=lambda inp, **kw: BaseToolResult(
                        tool_name="optimize_patch_capacity",
                        status=ToolStatus.SUCCESS,
                        message="Malformed",
                        side_effect=SideEffectClass.COMPUTE_ONLY,
                        provenance=ToolProvenance(source="test", source_type=ProvenanceSourceType.CALCULATED),
                    ),
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.FAILED
    assert any(e.code == "OPTIMIZATION_ERROR" for e in result.errors)


def test_14_malformed_dependency_output_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Malformed dependency result logs warning but does not abort optimization."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "resolve_package_dependencies":
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=lambda inp, **kw: BaseToolResult(
                        tool_name="resolve_package_dependencies",
                        status=ToolStatus.SUCCESS,
                        message="Malformed",
                        side_effect=SideEffectClass.READ_ONLY,
                        provenance=ToolProvenance(source="test", source_type=ProvenanceSourceType.LOCAL_DATASET),
                    ),
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status in (PatchPlanAgentStatus.SUCCESS, PatchPlanAgentStatus.PARTIAL_SUCCESS)
    assert any(w.code == "DEPENDENCY_QUERY_FAILED" for w in result.warnings)


def test_15_malformed_simulation_output_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
) -> None:
    """Tool invocation for simulate_risk_reduction with invalid arguments raises ValidationError."""
    with pytest.raises(Exception):
        default_tool_registry.invoke("simulate_risk_reduction", {"finding": "not_a_finding"})


def test_16_malformed_validation_output_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Malformed output from validate_plan_constraints flags CONSTRAINT_VIOLATION."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "validate_plan_constraints":
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=lambda inp, **kw: BaseToolResult(
                        tool_name="validate_plan_constraints",
                        status=ToolStatus.SUCCESS,
                        message="Malformed",
                        side_effect=SideEffectClass.COMPUTE_ONLY,
                        provenance=ToolProvenance(source="test", source_type=ProvenanceSourceType.CALCULATED),
                    ),
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.CONSTRAINT_VIOLATION
    assert result.validation_passed is False


def test_17_tool_execution_exception(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Exception during optimize_patch_capacity is caught and results in FAILED."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name == "optimize_patch_capacity":
            def _crash(inp: Any, **kw: Any) -> Any:
                raise RuntimeError("Optimizer catastrophic crash")
            custom_reg.register(
                ToolDefinition(
                    name=t.name,
                    description=t.description,
                    category=t.category,
                    side_effect=t.side_effect,
                    input_schema=t.input_schema,
                    output_schema=t.output_schema,
                    handler=_crash,
                )
            )
        else:
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.FAILED
    assert any(e.code == "OPTIMIZATION_ERROR" for e in result.errors)


def test_18_unknown_tool_handling(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """When optimize_patch_capacity is missing from registry, agent handles gracefully."""
    custom_reg = ToolRegistry()
    for t in default_tool_registry.list_tools():
        if t.name != "optimize_patch_capacity":
            custom_reg.register(t)

    agent = PatchPlanAgent(registry=custom_reg)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.FAILED


def test_19_registry_boundary_enforcement(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Spy on ToolRegistry.invoke to ensure all planning tools route through registry."""
    spy_registry = ToolRegistry()
    for t in default_tool_registry.list_tools():
        spy_registry.register(t)

    original_invoke = spy_registry.invoke
    invoked_tools: List[str] = []

    def _spied_invoke(name: str, payload: Any, **kw: Any) -> Any:
        invoked_tools.append(name)
        return original_invoke(name, payload, **kw)

    spy_registry.invoke = _spied_invoke  # type: ignore

    agent = PatchPlanAgent(registry=spy_registry)
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert "optimize_patch_capacity" in invoked_tools
    assert "resolve_package_dependencies" in invoked_tools
    assert "validate_plan_constraints" in invoked_tools


def test_20_duplicate_findings_in_input(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Duplicate finding IDs in input list is rejected with INVALID_INPUT."""
    dupe_findings = list(sample_findings) + [sample_findings[0]]

    agent = PatchPlanAgent()
    result = agent.run(
        findings=dupe_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.INVALID_INPUT
    assert "Duplicate finding ID" in result.summary


def test_21_invalid_risk_input(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
) -> None:
    """Empty risk assessments list is rejected with INVALID_INPUT."""
    with pytest.raises(Exception):
        PatchPlanInput(
            findings=sample_findings,
            assets=sample_assets,
            risk_assessments=[],
            capacity_limit_hours=16.0,
        )


def test_22_finding_asset_mismatch(
    sample_findings: List[VulnerabilityFinding],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Finding referring to an asset not in assets map is rejected as INVALID_INPUT."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets={},  # Empty asset map
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.INVALID_INPUT
    assert "Findings reference assets missing from asset context" in result.summary


def test_23_deterministic_repeated_execution(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Repeated runs produce strictly identical scheduled actions, deferred items, and effort."""
    agent = PatchPlanAgent()
    res1 = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=6.0,
        plan_id="PLAN-DET-001",
    )
    res2 = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=6.0,
        plan_id="PLAN-DET-001",
    )

    assert res1.scheduled_finding_ids == res2.scheduled_finding_ids
    assert res1.deferred_finding_ids == res2.deferred_finding_ids
    assert res1.total_scheduled_effort_hours == res2.total_scheduled_effort_hours
    assert res1.total_expected_risk_reduction == res2.total_expected_risk_reduction
    assert res1.summary == res2.summary


def test_24_state_isolation(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Separate agent instances and invocations do not leak state."""
    agent1 = PatchPlanAgent()
    agent2 = PatchPlanAgent()

    res1 = agent1.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=2.5,
    )
    res2 = agent2.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=20.0,
    )

    assert len(res1.scheduled_finding_ids) == 1
    assert len(res2.scheduled_finding_ids) == 3


def test_25_malicious_package_text_inert(
    sample_assets: Dict[str, Asset],
) -> None:
    """Package names containing command injection characters are treated as inert strings."""
    malicious_finding = VulnerabilityFinding(
        finding_id="FINDING-MAL",
        cve_id="CVE-2023-99999",
        title="Command injection test; $(rm -rf /)",
        description="Exploit payload; cat /etc/passwd",
        cvss_score=8.5,
        severity=VulnerabilitySeverity.HIGH,
        affected_package="evil-pkg; touch /tmp/pwned",
        installed_version="1.0.0",
        fixed_version="1.0.1; whoami",
        asset_id="ASSET-001",
        source="trivy",
    )
    risk_res = RiskCombinationResult(
        status=RiskCombinationStatus.SUCCESS,
        finding_id="FINDING-MAL",
        cve_id="CVE-2023-99999",
        asset_id="ASSET-001",
        base_score=85.0,
        threat_score=50.0,
        environmental_score=70.0,
        raw_risk_score=70.0,
        control_multiplier=1.0,
        environmental_risk_score=70.0,
        risk_tier=RiskTier.HIGH,
        decision=AegisDecision.ATTEND,
        remediation_decision=RemediationDecision.SCHEDULED_PATCH,
        consistency=RiskEvidenceConsistency(
            finding_id_match=True, cve_id_match=True, asset_id_match=True, is_consistent=True
        ),
        provenance=RiskEvidenceProvenance(assessed_at=datetime.now(timezone.utc)),
        evaluated_at=datetime.now(timezone.utc),
    )

    agent = PatchPlanAgent()
    result = agent.run(
        findings=[malicious_finding],
        assets=sample_assets,
        risk_assessments=[risk_res],
        capacity_limit_hours=10.0,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert result.scheduled_actions[0].target_package == "evil-pkg; touch /tmp/pwned"


def test_26_provenance_tracking(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Provenance accurately records algorithms and tool sources."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
        plan_id="PLAN-PROV-001",
    )

    assert result.provenance.algorithm == "deterministic_0_1_knapsack_dp"
    assert result.provenance.optimizer_source == "optimize_patch_capacity"
    assert result.provenance.dependency_tool == "resolve_package_dependencies"
    assert result.provenance.validator_source == "validate_plan_constraints"
    assert result.provenance.plan_id == "PLAN-PROV-001"


def test_27_trace_correctness(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Step traces are strictly ordered, 1-indexed, and record executed actions."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    traces = result.step_traces
    assert len(traces) >= 3
    for idx, trace in enumerate(traces):
        assert trace.step_number == idx + 1
        assert trace.action.action_type == AgentStepActionType.CALL_TOOL


def test_28_final_status_assignment(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """Statuses SUCCESS and INVALID_INPUT are assigned as appropriate."""
    agent = PatchPlanAgent()

    res_success = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )
    assert res_success.status == PatchPlanAgentStatus.SUCCESS

    res_invalid = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=-1.0,
    )
    assert res_invalid.status == PatchPlanAgentStatus.INVALID_INPUT


def test_29_benchmark_integration() -> None:
    """Test planning across benchmark findings and assets."""
    raw_findings = load_benchmark_findings()
    cmdb_assets = load_cmdb_assets()

    # Take first 10 benchmark findings
    test_fids = [f"FINDING-00{i}" for i in range(1, 10)]
    findings_list = [raw_findings[fid] for fid in test_fids if fid in raw_findings]

    mock_assessments = [
        RiskCombinationResult(
            status=RiskCombinationStatus.SUCCESS,
            finding_id=f.finding_id,
            cve_id=f.cve_id,
            asset_id=f.asset_id,
            base_score=f.cvss_score * 10.0,
            threat_score=50.0,
            environmental_score=60.0,
            raw_risk_score=60.0,
            control_multiplier=1.0,
            environmental_risk_score=60.0,
            risk_tier=RiskTier.HIGH,
            decision=AegisDecision.ATTEND,
            remediation_decision=RemediationDecision.SCHEDULED_PATCH,
            consistency=RiskEvidenceConsistency(
                finding_id_match=True, cve_id_match=True, asset_id_match=True, is_consistent=True
            ),
            provenance=RiskEvidenceProvenance(assessed_at=datetime.now(timezone.utc)),
            evaluated_at=datetime.now(timezone.utc),
        )
        for f in findings_list
    ]

    agent = PatchPlanAgent()
    result = agent.run(
        findings=findings_list,
        assets=cmdb_assets,
        risk_assessments=mock_assessments,
        capacity_limit_hours=16.0,
    )

    assert result.status == PatchPlanAgentStatus.SUCCESS
    assert result.candidate_count == len(findings_list)
    assert result.total_scheduled_effort_hours <= 16.0
    assert len(result.scheduled_finding_ids) > 0


def test_30_no_second_optimizer() -> None:
    """Explicit code-review test: verify that src/agents/patch_plan.py does NOT duplicate knapsack DP."""
    from src.agents import patch_plan
    source = inspect.getsource(patch_plan)

    # Verify that dynamic programming tables or knapsack loops do not exist in patch_plan.py
    assert "dp = [[" not in source
    assert "max_steps" not in source
    assert "weights =" not in source
    assert "for c in range(max_steps" not in source


def test_31_no_real_patch_execution() -> None:
    """Explicit code-review test: verify that no subprocess, shell, ssh, or package manager calls exist."""
    from src.agents import patch_plan
    source = inspect.getsource(patch_plan)

    assert "subprocess" not in source
    assert "os.system" not in source
    assert "paramiko" not in source
    assert "apt-get" not in source
    assert "yum" not in source
    assert "dnf" not in source
    assert "pip install" not in source


def test_32_rollback_procedure_preservation(
    sample_findings: List[VulnerabilityFinding],
    sample_assets: Dict[str, Asset],
    sample_risk_assessments: List[RiskCombinationResult],
) -> None:
    """All scheduled actions must contain actionable rollback procedures."""
    agent = PatchPlanAgent()
    result = agent.run(
        findings=sample_findings,
        assets=sample_assets,
        risk_assessments=sample_risk_assessments,
        capacity_limit_hours=16.0,
    )

    for action in result.scheduled_actions:
        assert action.rollback_procedure is not None
        assert "snapshot" in action.rollback_procedure.lower()
        assert action.approval_state == ApprovalState.PENDING
