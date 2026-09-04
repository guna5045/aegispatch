"""Supervisor Agent high-level orchestrator for Aegis Patch.

Serves as the primary public entry point for invoking the autonomous Supervisor Agent.
Separates orchestration concerns from runtime execution and deterministic planning.
"""

from __future__ import annotations

from typing import List, Optional
import uuid

from src.agents.planner import AgentPlanner, DeterministicSupervisorPlanner
from src.agents.runtime import SupervisorRuntime
from src.agents.schemas import (
    AgentExecutionStatus,
    AgentNotice,
    AgentWorkflowType,
    InvestigateFindingContext,
    NoticeSeverity,
    PlanRemediationContext,
    PrioritizeFindingsContext,
    SupervisorState,
    WhatIfContext,
    WorkflowContext,
)
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.registry import ToolRegistry, default_tool_registry


class SupervisorAgent:
    """Public orchestration facade for the Aegis Patch Supervisor Agent.

    Encapsulates state initialization and lifecycle execution. Guarantees complete
    state isolation across concurrent invocations (zero shared mutable state).
    """

    def __init__(
        self,
        planner: Optional[AgentPlanner] = None,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        self._planner = planner or DeterministicSupervisorPlanner()
        self._registry = registry or default_tool_registry

    @property
    def planner(self) -> AgentPlanner:
        """Active planner engine."""
        return self._planner

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def execute(self, state: SupervisorState) -> SupervisorState:
        """Execute the agent loop for an already initialized SupervisorState.

        Args:
            state: Pre-configured supervisor state.

        Returns:
            Terminal or halted supervisor state.
        """
        if not isinstance(state, SupervisorState):
            raise TypeError(f"state must be an instance of SupervisorState, got {type(state).__name__}")

        runtime = SupervisorRuntime(planner=self._planner, registry=self._registry)
        try:
            return runtime.run(state)
        except Exception as err:
            state.status = AgentExecutionStatus.FAILED
            state.errors.append(
                AgentNotice(
                    code="UNHANDLED_RUNTIME_ERROR",
                    message=f"Supervisor execution failed with unhandled exception: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            return state

    def investigate_finding(
        self,
        finding_id: str,
        asset_id: Optional[str] = None,
        user_goal: Optional[str] = None,
        max_iterations: int = 20,
    ) -> SupervisorState:
        """Investigate a specific vulnerability finding autonomously.

        Args:
            finding_id: Target finding identifier (e.g. FINDING-007).
            asset_id: Optional target asset identifier if known upfront.
            user_goal: Optional custom natural language goal prompt.
            max_iterations: Execution safety iteration limit (1-100).

        Returns:
            Finalized or halted SupervisorState.
        """
        if not finding_id or not isinstance(finding_id, str) or not finding_id.strip():
            raise ValueError("finding_id must be a non-empty string.")

        if not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 100:
            raise ValueError("max_iterations must be an integer between 1 and 100.")

        clean_finding_id = finding_id.strip()
        clean_asset_id = asset_id.strip() if asset_id and isinstance(asset_id, str) else None

        run_id = f"RUN-INV-{uuid.uuid4().hex[:8]}"
        goal = user_goal or f"Investigate vulnerability finding {clean_finding_id} and calculate environmental risk."

        investigate_ctx = InvestigateFindingContext(
            target_finding_id=clean_finding_id,
            target_asset_id=clean_asset_id,
        )

        wf_ctx = WorkflowContext(
            workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
            investigate=investigate_ctx,
        )

        state = SupervisorState(
            run_id=run_id,
            workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
            user_goal=goal,
            context=wf_ctx,
            target_finding_id=clean_finding_id,
            target_asset_id=clean_asset_id,
            max_iterations=max_iterations,
            status=AgentExecutionStatus.PENDING,
        )

        return self.execute(state)

    def prioritize_findings(
        self,
        findings: List[VulnerabilityFinding],
        user_goal: Optional[str] = None,
        max_iterations: int = 50,
    ) -> SupervisorState:
        """Prioritize a collection of vulnerability findings deterministically.

        Args:
            findings: List of candidate vulnerability findings.
            user_goal: Optional custom natural language goal prompt.
            max_iterations: Safety iteration limit (1-100).

        Returns:
            Finalized or halted SupervisorState.
        """
        if not findings or not isinstance(findings, list):
            raise ValueError("findings must be a non-empty list of VulnerabilityFinding objects.")

        for item in findings:
            if not isinstance(item, VulnerabilityFinding):
                raise TypeError("All items in findings must be VulnerabilityFinding instances.")

        if not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 100:
            raise ValueError("max_iterations must be an integer between 1 and 100.")

        run_id = f"RUN-PRIO-{uuid.uuid4().hex[:8]}"
        goal = user_goal or f"Prioritize and rank {len(findings)} vulnerability findings by contextual risk."

        f_ids = [f.finding_id for f in findings]
        a_ids = list({f.asset_id for f in findings})

        prioritize_ctx = PrioritizeFindingsContext(
            selected_finding_ids=f_ids,
            target_asset_ids=a_ids,
        )

        wf_ctx = WorkflowContext(
            workflow_type=AgentWorkflowType.PRIORITIZE_FINDINGS,
            prioritize=prioritize_ctx,
        )

        findings_dict = {f.finding_id: f for f in findings}

        state = SupervisorState(
            run_id=run_id,
            workflow_type=AgentWorkflowType.PRIORITIZE_FINDINGS,
            user_goal=goal,
            context=wf_ctx,
            findings=findings_dict,
            max_iterations=max_iterations,
            status=AgentExecutionStatus.PENDING,
        )

        return self.execute(state)

    def plan_remediation(
        self,
        findings: List[VulnerabilityFinding],
        capacity_limit_hours: float = 16.0,
        require_rollback_plans: bool = True,
        user_goal: Optional[str] = None,
        max_iterations: int = 50,
    ) -> SupervisorState:
        """Construct an optimized remediation plan under capacity limits.

        Args:
            findings: Candidate findings for inclusion in patch plan.
            capacity_limit_hours: Engineering capacity limit in hours.
            require_rollback_plans: Whether each scheduled patch requires a rollback procedure.
            user_goal: Optional custom natural language goal prompt.
            max_iterations: Safety iteration limit (1-100).

        Returns:
            Finalized or halted SupervisorState.
        """
        if not findings or not isinstance(findings, list):
            raise ValueError("findings must be a non-empty list of VulnerabilityFinding objects.")

        for item in findings:
            if not isinstance(item, VulnerabilityFinding):
                raise TypeError("All items in findings must be VulnerabilityFinding instances.")

        if not isinstance(capacity_limit_hours, (int, float)) or capacity_limit_hours <= 0.0:
            raise ValueError("capacity_limit_hours must be a positive float.")

        if not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 100:
            raise ValueError("max_iterations must be an integer between 1 and 100.")

        run_id = f"RUN-PLAN-{uuid.uuid4().hex[:8]}"
        goal = user_goal or f"Generate capacity-constrained patch plan for {len(findings)} findings ({capacity_limit_hours}h limit)."

        f_ids = [f.finding_id for f in findings]

        plan_ctx = PlanRemediationContext(
            capacity_limit_hours=float(capacity_limit_hours),
            target_finding_ids=f_ids,
            require_rollback_plans=require_rollback_plans,
        )

        wf_ctx = WorkflowContext(
            workflow_type=AgentWorkflowType.PLAN_REMEDIATION,
            plan_remediation=plan_ctx,
        )

        findings_dict = {f.finding_id: f for f in findings}

        state = SupervisorState(
            run_id=run_id,
            workflow_type=AgentWorkflowType.PLAN_REMEDIATION,
            user_goal=goal,
            context=wf_ctx,
            findings=findings_dict,
            max_iterations=max_iterations,
            status=AgentExecutionStatus.PENDING,
        )

        return self.execute(state)

    def simulate_what_if(
        self,
        finding: VulnerabilityFinding,
        hypothetical_controls: Optional[List[str]] = None,
        hypothetical_capacity_hours: Optional[float] = None,
        user_goal: Optional[str] = None,
        max_iterations: int = 20,
    ) -> SupervisorState:
        """Simulate hypothetical control additions or capacity variations safely.

        Args:
            finding: Target vulnerability finding.
            hypothetical_controls: Control names assumed to be active (e.g. ['WAF', 'NETWORK_SEGREGATION']).
            hypothetical_capacity_hours: Optional hypothetical maintenance window hours.
            user_goal: Optional custom natural language goal prompt.
            max_iterations: Safety iteration limit (1-100).

        Returns:
            Finalized or halted SupervisorState.
        """
        if not finding or not isinstance(finding, VulnerabilityFinding):
            raise TypeError("finding must be an instance of VulnerabilityFinding.")

        if not isinstance(max_iterations, int) or max_iterations < 1 or max_iterations > 100:
            raise ValueError("max_iterations must be an integer between 1 and 100.")

        controls = list(hypothetical_controls or [])

        run_id = f"RUN-SIM-{uuid.uuid4().hex[:8]}"
        goal = user_goal or f"Simulate hypothetical risk reduction for {finding.finding_id} with controls {controls}."

        what_if_ctx = WhatIfContext(
            finding_id=finding.finding_id,
            asset_id=finding.asset_id,
            hypothetical_controls=controls,
            hypothetical_capacity_hours=hypothetical_capacity_hours,
        )

        wf_ctx = WorkflowContext(
            workflow_type=AgentWorkflowType.WHAT_IF,
            what_if=what_if_ctx,
        )

        state = SupervisorState(
            run_id=run_id,
            workflow_type=AgentWorkflowType.WHAT_IF,
            user_goal=goal,
            context=wf_ctx,
            target_finding_id=finding.finding_id,
            target_asset_id=finding.asset_id,
            findings={finding.finding_id: finding},
            max_iterations=max_iterations,
            status=AgentExecutionStatus.PENDING,
        )

        return self.execute(state)
