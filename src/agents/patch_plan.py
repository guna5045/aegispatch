"""Patch Plan Specialist Agent for Aegis Patch.

Phase 9E: Transforms contextual risk assessments into an optimal, capacity-aware,
and constraint-validated remediation plan.

Architectural Guarantees:
1. Authoritative Optimizer: Contains ZERO knapsack or optimization formulas.
   All capacity scheduling delegates strictly to `optimize_patch_capacity`.
2. Hard Capacity Constraints: Total scheduled effort must never exceed maintenance
   window capacity.
3. Strict Human-in-the-Loop Safety: Contains ZERO live patching, package managers,
   shell execution, SSH commands, or infrastructure mutations. All actions require approval.
4. Mandatory Validation Gate: Every plan is validated via `validate_plan_constraints`
   for non-negative effort, unique findings, capacity bounds, and rollback procedures.
5. Tool Registry Boundary: All tool calls route strictly through ToolRegistry.invoke.
6. Determinism & State Isolation: 100% reproducible ordering and execution with zero
   shared mutable module-level state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field

from src.agents.risk_combination import RiskCombinationResult
from src.agents.schemas import (
    AgentAction,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    NoticeSeverity,
)
from src.schemas.asset import Asset
from src.schemas.plan import (
    ApprovalState,
    PatchAction,
    PatchCandidate,
    PatchPlan,
    RollbackPlan,
)
from src.schemas.risk import RiskAssessment, RiskTier
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.scenario_service import estimate_patch_effort_hours
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.schemas import (
    BaseToolResult,
    DependencyItem,
    OptimizePatchCapacityInput,
    OptimizePatchCapacityOutput,
    PlanConstraintItem,
    PlanConstraintViolation,
    ResolvePackageDependenciesInput,
    ResolvePackageDependenciesOutput,
    SimulateRiskReductionInput,
    SimulateRiskReductionOutput,
    ToolProvenance,
    ToolStatus,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
)


class PatchPlanAgentStatus(str, Enum):
    """Categorical outcome status of the Patch Plan Agent workflow."""

    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    INVALID_INPUT = "INVALID_INPUT"
    FAILED = "FAILED"


class DeferralReason(str, Enum):
    """Structured explanation code justifying why a vulnerability finding was deferred."""

    CAPACITY_EXHAUSTED = "CAPACITY_EXHAUSTED"
    DEPENDENCY_UNRESOLVED = "DEPENDENCY_UNRESOLVED"
    ZERO_CAPACITY = "ZERO_CAPACITY"
    LOW_RISK_PRIORITY = "LOW_RISK_PRIORITY"
    VALIDATION_FAILED = "VALIDATION_FAILED"


class DeferredFindingDetail(BaseModel):
    """Detailed audit representation of a deferred remediation candidate."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., description="Deferred finding identifier")
    cve_id: str = Field(..., description="Target CVE identifier")
    asset_id: str = Field(..., description="Target asset identifier")
    reason: DeferralReason = Field(..., description="Categorical reason for deferral")
    explanation: str = Field(..., description="Human-readable justification for deferral")
    estimated_hours: float = Field(..., ge=0.0, description="Estimated effort in engineering hours")
    expected_risk_reduction: float = Field(..., ge=0.0, description="Potential environmental risk reduction")


class ScheduledFindingDetail(BaseModel):
    """Detailed representation of an action scheduled within maintenance capacity."""

    model_config = ConfigDict(extra="forbid")

    sequence_order: int = Field(..., ge=1, description="Recommended execution sequence index")
    candidate_id: str = Field(..., description="Source candidate identifier")
    finding_id: str = Field(..., description="Scheduled finding identifier")
    cve_id: str = Field(..., description="Target CVE identifier")
    asset_id: str = Field(..., description="Target asset identifier")
    target_package: str = Field(..., description="Software package or component to patch")
    installed_version: str = Field(..., description="Currently installed version")
    target_version: str = Field(..., description="Target patched version")
    estimated_hours: float = Field(..., ge=0.0, description="Estimated effort in engineering hours")
    expected_risk_reduction: float = Field(..., ge=0.0, description="Projected ERS risk reduction points")
    dependencies: List[str] = Field(default_factory=list, description="Direct prerequisite dependencies")
    has_conflicts: bool = Field(default=False, description="Whether package conflicts were detected")
    rollback_procedure: str = Field(..., description="Detailed safe rollback procedure")
    approval_state: ApprovalState = Field(default=ApprovalState.PENDING, description="Human review approval state")


class PatchPlanProvenance(BaseModel):
    """Provenance tracking metadata for the synthesized remediation plan."""

    model_config = ConfigDict(extra="forbid")

    algorithm: str = Field(default="deterministic_0_1_knapsack_dp", description="Optimization algorithm")
    optimizer_source: str = Field(default="optimize_patch_capacity", description="Invoked optimization tool")
    dependency_tool: str = Field(default="resolve_package_dependencies", description="Invoked dependency tool")
    validator_source: str = Field(default="validate_plan_constraints", description="Invoked constraint validator")
    plan_id: str = Field(..., description="Unique plan identifier")
    generated_at: datetime = Field(..., description="Timestamp of plan synthesis")


class PatchPlanInput(BaseModel):
    """Strongly typed input specification for the Patch Plan Specialist Agent."""

    model_config = ConfigDict(extra="forbid")

    findings: List[VulnerabilityFinding] = Field(
        ...,
        min_length=1,
        description="List of normalized vulnerability findings to consider for remediation",
    )
    assets: Dict[str, Asset] = Field(
        ...,
        description="Mapping of asset_id -> Asset operational and infrastructure context",
    )
    risk_assessments: List[Union[RiskAssessment, RiskCombinationResult]] = Field(
        ...,
        min_length=1,
        description="Evaluated contextual risk assessments backing the findings",
    )
    capacity_limit_hours: float = Field(
        default=16.0,
        description="Available engineering maintenance window capacity in hours",
    )
    plan_id: Optional[str] = Field(
        default=None,
        description="Optional custom identifier for the generated remediation plan",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-evaluative contextual metadata",
    )


class PatchPlanResult(BaseModel):
    """Authoritative capacity-aware remediation plan delivered by Patch Plan Agent."""

    model_config = ConfigDict(extra="forbid")

    status: PatchPlanAgentStatus = Field(
        ...,
        description="Overall execution status of the patch planning workflow",
    )
    plan_id: str = Field(
        ...,
        description="Unique patch plan identifier",
    )
    capacity_limit_hours: float = Field(
        ...,
        ge=0.0,
        description="Configured maintenance window capacity limit in hours",
    )
    total_scheduled_effort_hours: float = Field(
        ...,
        ge=0.0,
        description="Total engineering effort scheduled within capacity",
    )
    remaining_capacity_hours: float = Field(
        ...,
        ge=0.0,
        description="Unutilized maintenance window capacity in hours",
    )
    capacity_utilization_percent: float = Field(
        ...,
        ge=0.0,
        le=100.0,
        description="Capacity utilization percentage",
    )
    total_expected_risk_reduction: float = Field(
        ...,
        ge=0.0,
        description="Cumulative expected environmental risk reduction points",
    )
    candidate_count: int = Field(
        ...,
        ge=0,
        description="Total number of evaluated candidates",
    )
    scheduled_finding_ids: List[str] = Field(
        default_factory=list,
        description="IDs of findings scheduled for remediation in this window",
    )
    deferred_finding_ids: List[str] = Field(
        default_factory=list,
        description="IDs of findings deferred to subsequent maintenance windows",
    )
    scheduled_actions: List[ScheduledFindingDetail] = Field(
        default_factory=list,
        description="Ordered sequence of recommended remediation actions",
    )
    deferred_items: List[DeferredFindingDetail] = Field(
        default_factory=list,
        description="Detailed audit justifications for deferred findings",
    )
    validation_passed: bool = Field(
        ...,
        description="Whether the synthesized plan satisfied all operational constraints",
    )
    validation_violations: List[str] = Field(
        default_factory=list,
        description="Constraint violation messages if validation failed",
    )
    summary: str = Field(
        ...,
        description="Concise deterministic executive summary of the remediation schedule",
    )
    provenance: PatchPlanProvenance = Field(
        ...,
        description="Traceable planning tools and algorithm provenance",
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list,
        description="Actionable diagnostic warnings logged during plan generation",
    )
    errors: List[AgentNotice] = Field(
        default_factory=list,
        description="Errors or constraint violations encountered during plan generation",
    )
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list,
        description="Chronological audit traces of each tool execution step",
    )
    generated_at: datetime = Field(
        ...,
        description="Timestamp when the patch plan was synthesized",
    )


class PatchPlanAgent:
    """Specialist agent responsible for capacity-constrained remediation planning.

    Transforms contextual risk assessments into an optimal, auditable, and constraint-checked
    remediation plan. Enforces maintenance window limits and separates scheduled findings
    from deferred findings without executing any real patches.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry or default_tool_registry

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def run(
        self,
        findings: Union[List[VulnerabilityFinding], PatchPlanInput, Dict[str, Any]],
        assets: Optional[Dict[str, Asset]] = None,
        risk_assessments: Optional[List[Union[RiskAssessment, RiskCombinationResult]]] = None,
        capacity_limit_hours: float = 16.0,
        plan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> PatchPlanResult:
        """Convenience invocation accepting individual parameters or input object."""
        if isinstance(findings, (PatchPlanInput, dict)):
            return self.assess(findings)
        try:
            plan_input = PatchPlanInput(
                findings=findings,
                assets=assets or {},
                risk_assessments=risk_assessments or [],
                capacity_limit_hours=capacity_limit_hours,
                plan_id=plan_id,
                metadata=metadata or {},
            )
        except Exception as val_err:
            return self._create_invalid_input_result(
                plan_id=plan_id or "PLAN-INVALID",
                capacity=capacity_limit_hours if isinstance(capacity_limit_hours, (int, float)) else 0.0,
                error_message=f"Agent input validation failed: {val_err}",
                step_counter=1,
                now_utc=datetime.now(timezone.utc),
            )
        return self.assess(plan_input)

    def assess(
        self,
        input_data: Union[PatchPlanInput, Dict[str, Any]],
    ) -> PatchPlanResult:
        """Execute the deterministic patch planning pipeline with isolated local state.

        Steps:
        1. Validate input data (non-empty, non-negative capacity, reference checks, unique findings).
        2. Build PatchCandidate items using authoritative effort estimation and ERS scores.
        3. Check package dependencies for candidates via `resolve_package_dependencies`.
        4. Run 0/1 knapsack capacity optimization via `optimize_patch_capacity`.
        5. Validate proposed plan constraints via `validate_plan_constraints`.
        6. Separate scheduled and deferred findings with transparent audit reasons.
        7. Assemble and return comprehensive PatchPlanResult.
        """
        step_traces: List[AgentStepTrace] = []
        errors: List[AgentNotice] = []
        warnings: List[AgentNotice] = []
        step_counter = 1
        now_utc = datetime.now(timezone.utc)

        # ----------------------------------------------------------------------
        # 1. Validate Input Data
        # ----------------------------------------------------------------------
        if isinstance(input_data, dict):
            try:
                typed_input = PatchPlanInput.model_validate(input_data)
            except Exception as val_err:
                return self._create_invalid_input_result(
                    plan_id=str(input_data.get("plan_id", "PLAN-INVALID")),
                    capacity=float(input_data.get("capacity_limit_hours", 0.0)) if isinstance(input_data.get("capacity_limit_hours"), (int, float)) else 0.0,
                    error_message=f"Agent input validation failed: {val_err}",
                    step_counter=step_counter,
                    now_utc=now_utc,
                )
        elif isinstance(input_data, PatchPlanInput):
            typed_input = input_data
        else:
            return self._create_invalid_input_result(
                plan_id="PLAN-INVALID",
                capacity=0.0,
                error_message=f"Expected PatchPlanInput or dict, got {type(input_data).__name__}",
                step_counter=step_counter,
                now_utc=now_utc,
            )

        plan_id = typed_input.plan_id or f"PLAN-{now_utc.strftime('%Y%m%d%H%M%S')}"
        capacity_limit = typed_input.capacity_limit_hours

        # Enforce non-negative capacity
        if capacity_limit < 0.0:
            return self._create_invalid_input_result(
                plan_id=plan_id,
                capacity=capacity_limit,
                error_message=f"Capacity limit cannot be negative, got {capacity_limit}h.",
                step_counter=step_counter,
                now_utc=now_utc,
            )

        # Enforce unique findings in input
        seen_finding_ids: Set[str] = set()
        for f in typed_input.findings:
            if f.finding_id in seen_finding_ids:
                return self._create_invalid_input_result(
                    plan_id=plan_id,
                    capacity=capacity_limit,
                    error_message=f"Duplicate finding ID '{f.finding_id}' in input findings list.",
                    step_counter=step_counter,
                    now_utc=now_utc,
                )
            seen_finding_ids.add(f.finding_id)

        # Build lookup maps
        findings_map: Dict[str, VulnerabilityFinding] = {f.finding_id: f for f in typed_input.findings}
        assets_map: Dict[str, Asset] = dict(typed_input.assets)
        assessments_map: Dict[str, Union[RiskAssessment, RiskCombinationResult]] = {
            getattr(r, "finding_id"): r for r in typed_input.risk_assessments
        }

        # Validate that all findings have corresponding asset and risk assessment
        missing_assets = [f.finding_id for f in typed_input.findings if f.asset_id not in assets_map]
        if missing_assets:
            return self._create_invalid_input_result(
                plan_id=plan_id,
                capacity=capacity_limit,
                error_message=f"Findings reference assets missing from asset context: {missing_assets}",
                step_counter=step_counter,
                now_utc=now_utc,
            )

        missing_assessments = [f.finding_id for f in typed_input.findings if f.finding_id not in assessments_map]
        if missing_assessments:
            return self._create_invalid_input_result(
                plan_id=plan_id,
                capacity=capacity_limit,
                error_message=f"Findings lack corresponding risk assessments: {missing_assessments}",
                step_counter=step_counter,
                now_utc=now_utc,
            )

        # ----------------------------------------------------------------------
        # 2. Build Patch Candidates
        # ----------------------------------------------------------------------
        candidates: List[PatchCandidate] = []
        for fid in sorted(findings_map.keys()):
            f = findings_map[fid]
            a = assets_map[f.asset_id]
            r = assessments_map[fid]

            ers = getattr(r, "environmental_risk_score", 0.0)
            tier = getattr(r, "risk_tier", RiskTier.LOW)
            effort = estimate_patch_effort_hours(f, a)

            candidates.append(
                PatchCandidate(
                    candidate_id=f"CAND-{f.finding_id.replace('FINDING-', '')}",
                    finding_id=f.finding_id,
                    cve_id=f.cve_id,
                    asset_id=f.asset_id,
                    risk_tier=tier,
                    expected_risk_reduction=round(ers, 2),
                    estimated_cost_hours=effort,
                    dependencies=[],
                )
            )

        # ----------------------------------------------------------------------
        # 3. Analyze Package Dependencies via Tool Registry
        # ----------------------------------------------------------------------
        candidate_deps: Dict[str, List[str]] = {}
        candidate_conflicts: Dict[str, bool] = {}

        for f in typed_input.findings:
            dep_action = AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="resolve_package_dependencies",
                tool_arguments={"package_name": f.affected_package, "target_version": f.fixed_version or "latest"},
                rationale=f"Check package prerequisites and conflicts for '{f.affected_package}' on finding '{f.finding_id}'",
                target_finding_id=f.finding_id,
                target_asset_id=f.asset_id,
            )
            try:
                dep_input = ResolvePackageDependenciesInput(
                    package_name=f.affected_package,
                    target_version=f.fixed_version or "latest",
                    installed_version=f.installed_version,
                    asset_id=f.asset_id,
                )
                raw_dep_output = self._registry.invoke("resolve_package_dependencies", dep_input)
                if not isinstance(raw_dep_output, ResolvePackageDependenciesOutput):
                    raise ValueError(f"Malformed output from resolve_package_dependencies: {raw_dep_output}")

                if raw_dep_output.status == ToolStatus.SUCCESS:
                    dep_names = [p.package_name for p in raw_dep_output.prerequisites]
                    candidate_deps[f.finding_id] = dep_names
                    candidate_conflicts[f.finding_id] = raw_dep_output.has_conflicts
                else:
                    candidate_deps[f.finding_id] = []
                    candidate_conflicts[f.finding_id] = False

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=dep_action,
                        tool_result=raw_dep_output,
                        status=raw_dep_output.status,
                        notes=f"Dependency status for {f.affected_package}: {raw_dep_output.status.value}",
                    )
                )
            except Exception as dep_err:
                warnings.append(
                    AgentNotice(
                        code="DEPENDENCY_QUERY_FAILED",
                        message=f"Failed to query dependencies for package '{f.affected_package}': {dep_err}",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=dep_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=f"Exception querying dependencies for {f.affected_package}: {dep_err}",
                    )
                )
                candidate_deps[f.finding_id] = []
                candidate_conflicts[f.finding_id] = False
            step_counter += 1

        # ----------------------------------------------------------------------
        # 4. Run Knapsack Optimization via Tool Registry
        # ----------------------------------------------------------------------
        opt_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="optimize_patch_capacity",
            tool_arguments={"capacity_limit_hours": capacity_limit, "candidate_count": len(candidates)},
            rationale=f"Deterministically schedule patch candidates under {capacity_limit:.1f}h capacity limit via 0/1 knapsack DP",
        )

        opt_output: Optional[OptimizePatchCapacityOutput] = None
        try:
            opt_input = OptimizePatchCapacityInput(
                candidates=candidates,
                capacity_limit_hours=capacity_limit,
            )
            raw_opt_output = self._registry.invoke("optimize_patch_capacity", opt_input)
            if not isinstance(raw_opt_output, OptimizePatchCapacityOutput):
                raise ValueError(f"Malformed output from optimize_patch_capacity: {raw_opt_output}")

            opt_output = raw_opt_output
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=opt_action,
                    tool_result=opt_output,
                    status=opt_output.status,
                    notes=f"Optimized schedule: {len(opt_output.scheduled_candidates)} scheduled, {len(opt_output.deferred_candidates)} deferred",
                )
            )
        except Exception as opt_err:
            errors.append(
                AgentNotice(
                    code="OPTIMIZATION_ERROR",
                    message=f"Optimization tool 'optimize_patch_capacity' failed: {opt_err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=opt_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during optimize_patch_capacity: {opt_err}",
                )
            )
            return PatchPlanResult(
                status=PatchPlanAgentStatus.FAILED,
                plan_id=plan_id,
                capacity_limit_hours=capacity_limit,
                total_scheduled_effort_hours=0.0,
                remaining_capacity_hours=capacity_limit,
                capacity_utilization_percent=0.0,
                total_expected_risk_reduction=0.0,
                candidate_count=len(candidates),
                scheduled_finding_ids=[],
                deferred_finding_ids=[c.finding_id for c in candidates],
                scheduled_actions=[],
                deferred_items=[],
                validation_passed=False,
                validation_violations=["Optimization tool failed"],
                summary=f"Remediation planning failed: {opt_err}",
                provenance=PatchPlanProvenance(plan_id=plan_id, generated_at=now_utc),
                warnings=warnings,
                errors=errors,
                step_traces=step_traces,
                generated_at=now_utc,
            )
        step_counter += 1

        # ----------------------------------------------------------------------
        # 5. Validate Plan Constraints via Tool Registry
        # ----------------------------------------------------------------------
        scheduled_cands = opt_output.scheduled_candidates
        deferred_cands = opt_output.deferred_candidates

        validation_items: List[PlanConstraintItem] = []
        for idx, cand in enumerate(scheduled_cands, start=1):
            validation_items.append(
                PlanConstraintItem(
                    finding_id=cand.finding_id,
                    sequence_order=idx,
                    estimated_hours=cand.estimated_cost_hours,
                    has_rollback_plan=True,  # We generate safe rollback procedures for all scheduled actions
                )
            )

        val_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="validate_plan_constraints",
            tool_arguments={"plan_id": plan_id, "capacity_limit_hours": capacity_limit, "item_count": len(validation_items)},
            rationale=f"Validate proposed plan '{plan_id}' against capacity, uniqueness, references, and rollback constraints",
        )

        val_output: Optional[ValidatePlanConstraintsOutput] = None
        is_plan_valid = True
        violations_list: List[str] = []

        if len(validation_items) > 0:
            try:
                val_input = ValidatePlanConstraintsInput(
                    plan_id=plan_id,
                    capacity_limit_hours=capacity_limit,
                    items=validation_items,
                    known_finding_ids=list(findings_map.keys()),
                )
                raw_val_output = self._registry.invoke("validate_plan_constraints", val_input)
                if not isinstance(raw_val_output, ValidatePlanConstraintsOutput):
                    raise ValueError(f"Malformed output from validate_plan_constraints: {raw_val_output}")

                val_output = raw_val_output
                is_plan_valid = val_output.is_valid
                violations_list = [v.violation_message for v in val_output.violations]

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=val_action,
                        tool_result=val_output,
                        status=val_output.status,
                        notes=f"Constraint validation result: is_valid={is_plan_valid}, violations={len(violations_list)}",
                    )
                )
                if not is_plan_valid:
                    errors.append(
                        AgentNotice(
                            code="PLAN_CONSTRAINT_VIOLATION",
                            message=f"Plan violates operational constraints: {'; '.join(violations_list)}",
                            severity=NoticeSeverity.ERROR,
                            step_number=step_counter,
                        )
                    )
            except Exception as val_err:
                errors.append(
                    AgentNotice(
                        code="VALIDATION_TOOL_ERROR",
                        message=f"Tool 'validate_plan_constraints' execution failed: {val_err}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=val_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=f"Exception during validate_plan_constraints: {val_err}",
                    )
                )
                is_plan_valid = False
                violations_list.append(f"Validation exception: {val_err}")
            step_counter += 1
        else:
            # Zero scheduled items (e.g. capacity = 0.0) is a valid, empty schedule
            is_plan_valid = True

        # ----------------------------------------------------------------------
        # 6. Separate Scheduled and Deferred Findings
        # ----------------------------------------------------------------------
        scheduled_actions: List[ScheduledFindingDetail] = []
        for idx, cand in enumerate(scheduled_cands, start=1):
            f = findings_map[cand.finding_id]
            a = assets_map[cand.asset_id]
            pkg = f.affected_package
            target_v = f.fixed_version or "latest_stable"
            cur_v = f.installed_version

            rollback_desc = (
                f"Capture filesystem and package state snapshot of '{a.hostname}'. "
                f"If post-patch validation tests fail, restore package '{pkg}' back to version '{cur_v}'."
            )

            scheduled_actions.append(
                ScheduledFindingDetail(
                    sequence_order=idx,
                    candidate_id=cand.candidate_id,
                    finding_id=cand.finding_id,
                    cve_id=cand.cve_id,
                    asset_id=cand.asset_id,
                    target_package=pkg,
                    installed_version=cur_v,
                    target_version=target_v,
                    estimated_hours=cand.estimated_cost_hours,
                    expected_risk_reduction=cand.expected_risk_reduction,
                    dependencies=candidate_deps.get(cand.finding_id, []),
                    has_conflicts=candidate_conflicts.get(cand.finding_id, False),
                    rollback_procedure=rollback_desc,
                    approval_state=ApprovalState.PENDING,
                )
            )

        deferred_items: List[DeferredFindingDetail] = []
        for cand in deferred_cands:
            f = findings_map[cand.finding_id]
            if capacity_limit <= 0:
                reason = DeferralReason.ZERO_CAPACITY
                expl = "No engineering maintenance capacity was allocated (capacity = 0.0h)."
            elif candidate_conflicts.get(cand.finding_id, False):
                reason = DeferralReason.DEPENDENCY_UNRESOLVED
                expl = f"Package '{f.affected_package}' has unresolved conflicts requiring architectural review."
            else:
                reason = DeferralReason.CAPACITY_EXHAUSTED
                expl = (
                    f"Deferred to respect maintenance window limit ({capacity_limit:.1f}h). "
                    f"Requires {cand.estimated_cost_hours:.1f}h effort which exceeds remaining capacity."
                )

            deferred_items.append(
                DeferredFindingDetail(
                    finding_id=cand.finding_id,
                    cve_id=cand.cve_id,
                    asset_id=cand.asset_id,
                    reason=reason,
                    explanation=expl,
                    estimated_hours=cand.estimated_cost_hours,
                    expected_risk_reduction=cand.expected_risk_reduction,
                )
            )

        # ----------------------------------------------------------------------
        # 7. Final Summary & Status
        # ----------------------------------------------------------------------
        sched_fids = [c.finding_id for c in scheduled_cands]
        defer_fids = [c.finding_id for c in deferred_cands]

        if not is_plan_valid:
            status = PatchPlanAgentStatus.CONSTRAINT_VIOLATION
            summary = (
                f"Remediation plan '{plan_id}' violated operational constraints: {'; '.join(violations_list)}."
            )
        elif len(warnings) > 0:
            status = PatchPlanAgentStatus.PARTIAL_SUCCESS
            summary = (
                f"Remediation plan '{plan_id}' scheduled {len(sched_fids)} finding(s) utilizing "
                f"{opt_output.total_scheduled_effort_hours:.1f}h / {capacity_limit:.1f}h "
                f"({opt_output.capacity_utilization_percent}%) with {len(defer_fids)} deferred with diagnostic notices."
            )
        else:
            status = PatchPlanAgentStatus.SUCCESS
            summary = (
                f"Remediation plan '{plan_id}' scheduled {len(sched_fids)} finding(s) utilizing "
                f"{opt_output.total_scheduled_effort_hours:.1f}h / {capacity_limit:.1f}h "
                f"({opt_output.capacity_utilization_percent}%) maximizing expected risk reduction "
                f"by +{opt_output.total_expected_risk_reduction:.2f} points ({len(defer_fids)} deferred)."
            )

        return PatchPlanResult(
            status=status,
            plan_id=plan_id,
            capacity_limit_hours=capacity_limit,
            total_scheduled_effort_hours=opt_output.total_scheduled_effort_hours,
            remaining_capacity_hours=opt_output.remaining_capacity_hours,
            capacity_utilization_percent=opt_output.capacity_utilization_percent,
            total_expected_risk_reduction=opt_output.total_expected_risk_reduction,
            candidate_count=len(candidates),
            scheduled_finding_ids=sched_fids,
            deferred_finding_ids=defer_fids,
            scheduled_actions=scheduled_actions,
            deferred_items=deferred_items,
            validation_passed=is_plan_valid,
            validation_violations=violations_list,
            summary=summary,
            provenance=PatchPlanProvenance(
                algorithm=opt_output.algorithm,
                optimizer_source="optimize_patch_capacity",
                dependency_tool="resolve_package_dependencies",
                validator_source="validate_plan_constraints",
                plan_id=plan_id,
                generated_at=now_utc,
            ),
            warnings=warnings,
            errors=errors,
            step_traces=step_traces,
            generated_at=now_utc,
        )

    def _create_invalid_input_result(
        self,
        plan_id: str,
        capacity: float,
        error_message: str,
        step_counter: int,
        now_utc: datetime,
    ) -> PatchPlanResult:
        """Standardized INVALID_INPUT result envelope."""
        notice = AgentNotice(
            code="INVALID_INPUT_SCHEMA",
            message=error_message,
            severity=NoticeSeverity.ERROR,
            step_number=step_counter,
        )
        trace = AgentStepTrace(
            step_number=step_counter,
            action=AgentAction(
                action_type=AgentStepActionType.FAIL,
                rationale=error_message,
                error_code="INVALID_INPUT_SCHEMA",
            ),
            tool_result=None,
            status=ToolStatus.ERROR,
            notes=error_message,
        )
        return PatchPlanResult(
            status=PatchPlanAgentStatus.INVALID_INPUT,
            plan_id=plan_id,
            capacity_limit_hours=max(0.0, capacity),
            total_scheduled_effort_hours=0.0,
            remaining_capacity_hours=max(0.0, capacity),
            capacity_utilization_percent=0.0,
            total_expected_risk_reduction=0.0,
            candidate_count=0,
            scheduled_finding_ids=[],
            deferred_finding_ids=[],
            scheduled_actions=[],
            deferred_items=[],
            validation_passed=False,
            validation_violations=[error_message],
            summary=f"Patch plan creation rejected: {error_message}",
            provenance=PatchPlanProvenance(plan_id=plan_id, generated_at=now_utc),
            warnings=[],
            errors=[notice],
            step_traces=[trace],
            generated_at=now_utc,
        )
