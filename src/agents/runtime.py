"""Bounded runtime engine for Aegis Patch agents.

Executes the state-driven agent loop:
STATE -> PLAN -> ACTION -> EXECUTE -> OBSERVE -> UPDATE STATE -> REPLAN/CONTINUE -> VERIFY -> FINALIZE.

Guarantees:
- Tool execution strictly through ToolRegistry (default_tool_registry)
- Bounded loop iteration enforcement (max_iterations)
- Complete, transparent audit step tracing
- Hardened finalization and verification gates
- Fault-tolerant handling of malformed/unexpected tool results
- Explicit preservation of NOT_FOUND and NOT_AVAILABLE statuses
- No shell, subprocess, SSH, raw SQL, or live network calls
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Optional, Union

from src.agents.planner import AgentPlanner, DeterministicSupervisorPlanner
from src.agents.schemas import (
    AgentAction,
    AgentEvidenceItem,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    EvidenceType,
    NoticeSeverity,
    PlannerDecision,
    SupervisorFinalResult,
    SupervisorState,
    SupervisorWorkflowType,
)
from src.schemas.threat import ThreatConfidence, ThreatEvidence
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import BaseToolResult, ProvenanceSourceType, ToolProvenance, ToolStatus


class SupervisorRuntime:
    """Bounded runtime executor driving the Supervisor Agent decision loop."""

    def __init__(
        self,
        planner: Optional[AgentPlanner] = None,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        self._planner = planner or DeterministicSupervisorPlanner()
        self._registry = registry or default_tool_registry

    @property
    def planner(self) -> AgentPlanner:
        """The active planning engine."""
        return self._planner

    @property
    def registry(self) -> ToolRegistry:
        """The active tool registry."""
        return self._registry

    def step(self, state: SupervisorState) -> SupervisorState:
        """Execute a single discrete state-driven step.

        1. Inspect state with planner.
        2. Execute the decided action.
        3. Observe results and update state.

        Args:
            state: Current supervisor state.

        Returns:
            Updated supervisor state.
        """
        if state.status not in (AgentExecutionStatus.PENDING, AgentExecutionStatus.RUNNING):
            return state

        if state.status == AgentExecutionStatus.PENDING:
            state.status = AgentExecutionStatus.RUNNING

        if state.iteration_count >= state.max_iterations:
            state.status = AgentExecutionStatus.MAX_ITERATIONS_REACHED
            state.warnings.append(
                AgentNotice(
                    code="MAX_ITERATIONS_REACHED",
                    message=f"Workflow halted after reaching maximum iterations limit ({state.max_iterations}).",
                    severity=NoticeSeverity.WARNING,
                    step_number=state.current_step,
                )
            )
            return state

        # 1. Ask planner for next action
        try:
            decision = self._planner.plan(state)
        except Exception as err:
            state.current_step += 1
            state.iteration_count += 1
            state.errors.append(
                AgentNotice(
                    code="PLANNER_EXCEPTION",
                    message=f"Planner raised unhandled exception: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED
            return state

        action: AgentAction
        if isinstance(decision, PlannerDecision):
            action = decision.action
        elif isinstance(decision, AgentAction):
            action = decision
        else:
            state.current_step += 1
            state.iteration_count += 1
            state.errors.append(
                AgentNotice(
                    code="INVALID_PLANNER_OUTPUT",
                    message=f"Planner returned invalid output type: {type(decision).__name__}. Expected AgentAction or PlannerDecision.",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED
            return state

        state.next_action = action

        # 2. Execute decided action
        if action.action_type == AgentStepActionType.FINALIZE:
            self._handle_finalize(state, action)
        elif action.action_type == AgentStepActionType.FAIL:
            self._handle_fail(state, action)
        elif action.action_type == AgentStepActionType.REPLAN:
            self._handle_replan(state, action)
        elif action.action_type == AgentStepActionType.CALL_TOOL:
            self._handle_call_tool(state, action)
        else:
            self._handle_unknown_action(state, action)

        return state

    def run(self, state: SupervisorState) -> SupervisorState:
        """Execute bounded loop until terminal status or max iterations.

        Args:
            state: Initial supervisor state.

        Returns:
            Terminal or halted supervisor state.
        """
        if state.status == AgentExecutionStatus.PENDING:
            state.status = AgentExecutionStatus.RUNNING

        while state.status == AgentExecutionStatus.RUNNING and state.iteration_count < state.max_iterations:
            self.step(state)

        # Enforce max iterations if loop terminated without terminal status
        if state.status == AgentExecutionStatus.RUNNING and state.iteration_count >= state.max_iterations:
            state.status = AgentExecutionStatus.MAX_ITERATIONS_REACHED
            state.warnings.append(
                AgentNotice(
                    code="MAX_ITERATIONS_REACHED",
                    message=f"Workflow halted after reaching maximum iterations limit ({state.max_iterations}).",
                    severity=NoticeSeverity.WARNING,
                    step_number=state.current_step,
                )
            )

        return state

    # ----------------------------------------------------------------------
    # Action Handlers
    # ----------------------------------------------------------------------

    def _handle_finalize(self, state: SupervisorState, action: AgentAction) -> None:
        """Process terminal FINALIZE action with strict gate checks."""
        state.current_step += 1
        state.iteration_count += 1

        # Hardened Gate 1: Reject finalization if blocking errors exist in state
        blocking_errors = [e for e in state.errors if e.severity == NoticeSeverity.ERROR]
        if blocking_errors:
            trace = AgentStepTrace(
                step_number=state.current_step,
                action=action,
                tool_result=None,
                status=ToolStatus.ERROR,
                notes=f"Finalization rejected: {len(blocking_errors)} active blocking error(s) in state.",
            )
            state.step_traces.append(trace)
            state.errors.append(
                AgentNotice(
                    code="FINALIZATION_BLOCKED",
                    message=f"Finalization blocked due to active errors: {blocking_errors[0].message}",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED
            return

        # Hardened Gate 2: Reject finalization without verified evidence
        if state.workflow_type in (SupervisorWorkflowType.INVESTIGATE_FINDING, SupervisorWorkflowType.PRIORITIZE_FINDINGS):
            has_verified_evidence = any(
                ev.evidence_type == EvidenceType.VERIFICATION
                and ev.status == ToolStatus.SUCCESS
                and ev.value is True
                for ev in state.evidence
            )
        elif state.workflow_type == SupervisorWorkflowType.PLAN_REMEDIATION:
            has_verified_evidence = any(
                ev.evidence_type == EvidenceType.VERIFICATION
                and ev.claim_or_property == "plan_constraints_valid"
                and ev.value is True
                for ev in state.evidence
            )
        elif state.workflow_type == SupervisorWorkflowType.WHAT_IF:
            has_verified_evidence = any(
                ev.evidence_type == EvidenceType.SIMULATION
                and ev.status == ToolStatus.SUCCESS
                for ev in state.evidence
            )
        else:
            has_verified_evidence = any(
                ev.evidence_type == EvidenceType.VERIFICATION
                and ev.status == ToolStatus.SUCCESS
                and ev.value is True
                for ev in state.evidence
            )

        if not has_verified_evidence:
            trace = AgentStepTrace(
                step_number=state.current_step,
                action=action,
                tool_result=None,
                status=ToolStatus.VERIFICATION_FAILED,
                notes="Finalization rejected: verification evidence requirement not satisfied for workflow.",
            )
            state.step_traces.append(trace)
            state.errors.append(
                AgentNotice(
                    code="UNVERIFIED_FINALIZATION",
                    message="Cannot finalize workflow without independent verification evidence.",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.VERIFICATION_FAILED
            return

        # Hardened Gate 3: Reject finalization if required evaluations/simulations are missing
        if state.workflow_type == SupervisorWorkflowType.WHAT_IF:
            has_sim = "simulation_result" in state.scratchpad or any(
                ev.evidence_type == EvidenceType.SIMULATION and ev.status == ToolStatus.SUCCESS for ev in state.evidence
            )
            if not has_sim:
                trace = AgentStepTrace(
                    step_number=state.current_step,
                    action=action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes="Finalization rejected: no simulation result found in working memory.",
                )
                state.step_traces.append(trace)
                state.errors.append(
                    AgentNotice(
                        code="MISSING_SIMULATION_RESULT",
                        message="Cannot finalize what-if workflow without simulation outcome.",
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )
                state.status = AgentExecutionStatus.FAILED
                return
        else:
            if not state.risk_assessments:
                trace = AgentStepTrace(
                    step_number=state.current_step,
                    action=action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes="Finalization rejected: no risk assessments found in working memory.",
                )
                state.step_traces.append(trace)
                state.errors.append(
                    AgentNotice(
                        code="MISSING_RISK_ASSESSMENT",
                        message="Cannot finalize workflow without evaluated risk assessments.",
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )
                state.status = AgentExecutionStatus.FAILED
                return

        # Passed all finalization gates
        trace = AgentStepTrace(
            step_number=state.current_step,
            action=action,
            tool_result=None,
            status=ToolStatus.SUCCESS,
            notes=action.rationale,
        )
        state.step_traces.append(trace)

        # Determine primary decision and risk scores
        target_fids = list(state.risk_assessments.keys())
        if not target_fids and state.target_finding_id:
            target_fids = [state.target_finding_id]

        risk_scores: Dict[str, float] = {}
        finding_decisions: Dict[str, AegisDecision] = {}
        primary_dec = None
        remed_dec = None

        for fid, assessment in state.risk_assessments.items():
            risk_scores[fid] = assessment.environmental_risk_score
            dec_str = assessment.calculation_metadata.get("aegis_decision", AegisDecision.TRACK.value)
            try:
                dec_enum = AegisDecision(dec_str)
            except Exception:
                dec_enum = AegisDecision.TRACK
            finding_decisions[fid] = dec_enum
            if primary_dec is None:
                primary_dec = dec_enum
            if remed_dec is None:
                remed_dec = assessment.decision

        # Workflow-specific population
        scheduled_fids = None
        deferred_fids = None
        capacity_limit = None
        scheduled_effort = None
        expected_risk_red = None
        plan_val = None
        is_sim = False
        sim_label = None
        base_ers = None
        sim_ers = None
        sim_dec = None

        if state.workflow_type == SupervisorWorkflowType.PRIORITIZE_FINDINGS:
            # Deterministic multi-key tie-breaking:
            # (-environmental_risk_score, -cvss_score, finding_id ASC)
            target_fids = sorted(
                target_fids,
                key=lambda fid: (
                    -risk_scores.get(fid, 0.0),
                    -(state.findings[fid].cvss_score if fid in state.findings else 0.0),
                    fid,
                ),
            )
            if target_fids and target_fids[0] in state.risk_assessments:
                top_assessment = state.risk_assessments[target_fids[0]]
                try:
                    primary_dec = AegisDecision(
                        top_assessment.calculation_metadata.get("aegis_decision", AegisDecision.TRACK.value)
                    )
                except Exception:
                    primary_dec = AegisDecision.TRACK
                remed_dec = top_assessment.decision

        elif state.workflow_type == SupervisorWorkflowType.PLAN_REMEDIATION:
            opt_data = state.scratchpad.get("optimized_plan")
            if opt_data:
                scheduled_fids = [item["finding_id"] for item in opt_data.get("scheduled_patches", [])]
                deferred_fids = [item["finding_id"] for item in opt_data.get("deferred_patches", [])]
                capacity_limit = opt_data.get("capacity_limit_hours")
                scheduled_effort = opt_data.get("total_scheduled_effort_hours")
                expected_risk_red = opt_data.get("total_expected_risk_reduction")
            plan_val = any(
                ev.evidence_type == EvidenceType.VERIFICATION
                and ev.claim_or_property == "plan_constraints_valid"
                and ev.value is True
                for ev in state.evidence
            )
            primary_dec = AegisDecision.PLAN

        elif state.workflow_type == SupervisorWorkflowType.WHAT_IF:
            is_sim = True
            sim_label = "SIMULATED"
            sim_data = state.scratchpad.get("simulation_result")
            if sim_data:
                base_ers = sim_data.get("baseline_environmental_risk_score")
                sim_ers = sim_data.get("simulated_environmental_risk_score")
                sim_dec = sim_data.get("simulated_decision")
                if sim_dec:
                    try:
                        primary_dec = AegisDecision(sim_dec)
                    except Exception:
                        pass
                fid = state.target_finding_id or "FINDING-SIMULATED"
                target_fids = [fid]
                risk_scores[fid] = sim_ers or 0.0
                if primary_dec:
                    finding_decisions[fid] = primary_dec

        final_res = SupervisorFinalResult(
            summary=action.rationale,
            workflow_type=state.workflow_type,
            primary_decision=primary_dec,
            remediation_decision=remed_dec,
            target_findings=target_fids,
            risk_scores=risk_scores,
            is_verified=has_verified_evidence,
            notices_count=len(state.warnings) + len(state.errors),
            finding_decisions=finding_decisions,
            scheduled_finding_ids=scheduled_fids,
            deferred_finding_ids=deferred_fids,
            capacity_limit_hours=capacity_limit,
            total_scheduled_effort_hours=scheduled_effort,
            total_expected_risk_reduction=expected_risk_red,
            plan_validated=plan_val,
            is_simulation=is_sim,
            simulation_label=sim_label,
            baseline_ers=base_ers,
            simulated_ers=sim_ers,
            simulated_decision=sim_dec,
        )

        state.final_result = final_res
        state.status = AgentExecutionStatus.COMPLETED

    def _handle_fail(self, state: SupervisorState, action: AgentAction) -> None:
        """Process terminal FAIL action."""
        state.current_step += 1
        state.iteration_count += 1

        trace = AgentStepTrace(
            step_number=state.current_step,
            action=action,
            tool_result=None,
            status=ToolStatus.ERROR,
            notes=action.rationale,
        )
        state.step_traces.append(trace)

        err_code = action.error_code or "EXECUTION_FAILED"
        state.errors.append(
            AgentNotice(
                code=err_code,
                message=action.rationale,
                severity=NoticeSeverity.ERROR,
                step_number=state.current_step,
            )
        )

        if err_code == "VERIFICATION_FAILED":
            state.status = AgentExecutionStatus.VERIFICATION_FAILED
        else:
            state.status = AgentExecutionStatus.FAILED

    def _handle_replan(self, state: SupervisorState, action: AgentAction) -> None:
        """Process non-terminal REPLAN action."""
        state.current_step += 1
        state.iteration_count += 1

        trace = AgentStepTrace(
            step_number=state.current_step,
            action=action,
            tool_result=None,
            status=ToolStatus.SUCCESS,
            notes=f"Replanning triggered: {action.rationale}",
        )
        state.step_traces.append(trace)

        if action.trigger == "THREAT_SOURCE_UNAVAILABLE":
            if "osv_advisories" not in state.missing_information:
                state.missing_information.append("osv_advisories")
            state.warnings.append(
                AgentNotice(
                    code="OSV_NOT_AVAILABLE",
                    message="Local OSV database cache is not provisioned; continuing with available telemetry.",
                    severity=NoticeSeverity.INFO,
                    step_number=state.current_step,
                )
            )

    def _handle_call_tool(self, state: SupervisorState, action: AgentAction) -> None:
        """Process CALL_TOOL action strictly via ToolRegistry."""
        tool_name = action.tool_name or ""
        tool_def = self._registry.get(tool_name)

        if not tool_def:
            # Unknown tool
            state.current_step += 1
            state.iteration_count += 1
            trace = AgentStepTrace(
                step_number=state.current_step,
                action=action,
                tool_result=None,
                status=ToolStatus.ERROR,
                notes=f"Tool '{tool_name}' is not registered in ToolRegistry.",
            )
            state.step_traces.append(trace)
            state.errors.append(
                AgentNotice(
                    code="UNKNOWN_TOOL",
                    message=f"Tool '{tool_name}' is not registered in ToolRegistry.",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED
            return

        # Execute registered tool
        state.current_step += 1
        state.iteration_count += 1

        try:
            tool_result = self._registry.invoke(tool_name, action.tool_arguments or {})
        except Exception as err:
            trace = AgentStepTrace(
                step_number=state.current_step,
                action=action,
                tool_result=None,
                status=ToolStatus.ERROR,
                notes=f"Tool execution failed: {err}",
            )
            state.step_traces.append(trace)
            state.errors.append(
                AgentNotice(
                    code="TOOL_EXECUTION_ERROR",
                    message=str(err),
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED
            return

        # Record step trace
        trace = AgentStepTrace(
            step_number=state.current_step,
            action=action,
            tool_result=tool_result,
            status=tool_result.status,
            notes=tool_result.message,
        )
        state.step_traces.append(trace)

        # Update domain models and evidence based on tool output
        try:
            self._update_state_from_tool_result(state, action, tool_result)
        except Exception as err:
            state.errors.append(
                AgentNotice(
                    code="STATE_UPDATE_ERROR",
                    message=f"Error updating state from tool '{tool_name}': {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=state.current_step,
                )
            )
            state.status = AgentExecutionStatus.FAILED

    def _handle_unknown_action(self, state: SupervisorState, action: AgentAction) -> None:
        """Handle unrecognized action safety violation."""
        state.current_step += 1
        state.iteration_count += 1
        trace = AgentStepTrace(
            step_number=state.current_step,
            action=action,
            tool_result=None,
            status=ToolStatus.ERROR,
            notes=f"Rejected unsupported action type '{action.action_type}'.",
        )
        state.step_traces.append(trace)
        state.errors.append(
            AgentNotice(
                code="UNSUPPORTED_ACTION",
                message=f"Action type '{action.action_type}' is not supported.",
                severity=NoticeSeverity.ERROR,
                step_number=state.current_step,
            )
        )
        state.status = AgentExecutionStatus.FAILED

    # ----------------------------------------------------------------------
    # State Update Dispatcher
    # ----------------------------------------------------------------------

    def _update_state_from_tool_result(
        self,
        state: SupervisorState,
        action: AgentAction,
        result: BaseToolResult,
    ) -> None:
        """Update domain working memory, evidence, and diagnostics from typed result."""
        tool_name = action.tool_name
        prov = result.provenance or ToolProvenance(
            source=result.tool_name,
            source_type=ProvenanceSourceType.CALCULATED,
        )

        if tool_name == "validate_finding_schema":
            if result.status == ToolStatus.SUCCESS and hasattr(result, "validated_finding") and result.validated_finding:
                finding = result.validated_finding
                state.findings[finding.finding_id] = finding
                if not state.target_asset_id:
                    state.target_asset_id = finding.asset_id
                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id=f"EVID-SCAN-{finding.finding_id}",
                        evidence_type=EvidenceType.SCAN_DATA,
                        source=result.tool_name,
                        entity_id=finding.finding_id,
                        claim_or_property="finding_schema_valid",
                        value=True,
                        status=result.status,
                        provenance=prov,
                    )
                )
            elif result.status != ToolStatus.SUCCESS:
                state.errors.append(
                    AgentNotice(
                        code="FINDING_SCHEMA_INVALID",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "query_asset_cmdb":
            if result.status == ToolStatus.SUCCESS and hasattr(result, "asset") and result.asset:
                asset = result.asset
                state.assets[asset.asset_id] = asset
                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id=f"EVID-CMDB-{asset.asset_id}",
                        evidence_type=EvidenceType.CMDB_ASSET,
                        source=result.tool_name,
                        entity_id=asset.asset_id,
                        claim_or_property="asset_context",
                        value=asset.model_dump(),
                        status=result.status,
                        provenance=prov,
                    )
                )
            elif result.status == ToolStatus.NOT_FOUND:
                aid = str(action.tool_arguments.get("asset_id", "UNKNOWN")) if action.tool_arguments else "UNKNOWN"
                if f"asset_{aid}" not in state.missing_information:
                    state.missing_information.append(f"asset_{aid}")
                state.warnings.append(
                    AgentNotice(
                        code="ASSET_NOT_FOUND",
                        message=result.message,
                        severity=NoticeSeverity.WARNING,
                        step_number=state.current_step,
                    )
                )
            elif result.status != ToolStatus.SUCCESS:
                state.errors.append(
                    AgentNotice(
                        code="ASSET_LOOKUP_ERROR",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "lookup_cisa_kev":
            cve_id = str(action.tool_arguments.get("cve_id", "")) if action.tool_arguments else ""
            is_exploited = getattr(result, "is_known_exploited", False)
            state.evidence.append(
                AgentEvidenceItem(
                    evidence_id=f"EVID-KEV-{cve_id}",
                    evidence_type=EvidenceType.CISA_KEV,
                    source=result.tool_name,
                    entity_id=cve_id,
                    claim_or_property="cisa_kev_listed",
                    value=is_exploited,
                    status=result.status,
                    provenance=prov,
                )
            )

        elif tool_name == "query_epss":
            cve_id = str(action.tool_arguments.get("cve_id", "")) if action.tool_arguments else ""
            epss_val = getattr(result, "epss_score", None)
            state.evidence.append(
                AgentEvidenceItem(
                    evidence_id=f"EVID-EPSS-{cve_id}",
                    evidence_type=EvidenceType.EPSS,
                    source=result.tool_name,
                    entity_id=cve_id,
                    claim_or_property="epss_score",
                    value=epss_val,
                    status=result.status,
                    provenance=prov,
                )
            )
            if result.status != ToolStatus.SUCCESS or epss_val is None:
                if "epss_score" not in state.missing_information:
                    state.missing_information.append("epss_score")
                state.warnings.append(
                    AgentNotice(
                        code="EPSS_NOT_AVAILABLE",
                        message=result.message,
                        severity=NoticeSeverity.WARNING,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "query_osv_database":
            pkg = str(action.tool_arguments.get("package_name", "")) if action.tool_arguments else ""
            state.evidence.append(
                AgentEvidenceItem(
                    evidence_id=f"EVID-OSV-{pkg}",
                    evidence_type=EvidenceType.OSV,
                    source=result.tool_name,
                    entity_id=pkg,
                    claim_or_property="osv_advisories",
                    value=getattr(result, "advisories", []),
                    status=result.status,
                    provenance=prov,
                )
            )

        elif tool_name == "calculate_environmental_risk":
            fid = getattr(result, "finding_id", action.target_finding_id or "")
            if result.status == ToolStatus.SUCCESS:
                finding_obj = state.findings.get(fid)
                aid = getattr(result, "asset_id", state.target_asset_id or "")
                asset_obj = state.assets.get(aid)

                if finding_obj and asset_obj and action.tool_arguments:
                    is_kev = action.tool_arguments.get("is_cisa_kev", False)
                    epss = action.tool_arguments.get("epss_score")
                    poc = action.tool_arguments.get("public_poc_available", False)

                    threat_ev = ThreatEvidence(
                        evidence_id=f"EV-{finding_obj.cve_id}",
                        cve_id=finding_obj.cve_id,
                        is_cisa_kev=is_kev,
                        epss_score=epss,
                        public_poc_available=poc,
                        threat_source="threat_tools_intake",
                        retrieved_at=datetime.now(timezone.utc),
                        confidence=ThreatConfidence.HIGH,
                    )
                    assessment = evaluate_risk(finding=finding_obj, asset=asset_obj, threat=threat_ev)
                    state.risk_assessments[fid] = assessment

                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id=f"EVID-RISK-{fid}",
                        evidence_type=EvidenceType.RISK_EVALUATION,
                        source=result.tool_name,
                        entity_id=fid,
                        claim_or_property="environmental_risk_score",
                        value=getattr(result, "environmental_risk_score", 0.0),
                        status=result.status,
                        provenance=prov,
                    )
                )
            else:
                state.errors.append(
                    AgentNotice(
                        code="RISK_CALCULATION_ERROR",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "verify_score_derivation":
            is_ver = getattr(result, "is_verified", False)
            fid = action.target_finding_id or state.target_finding_id or "UNKNOWN"
            state.evidence.append(
                AgentEvidenceItem(
                    evidence_id=f"EVID-VERIFY-{fid}",
                    evidence_type=EvidenceType.VERIFICATION,
                    source=result.tool_name,
                    entity_id=fid,
                    claim_or_property="score_derivation_verified",
                    value=is_ver,
                    status=result.status,
                    provenance=prov,
                )
            )
            if not is_ver:
                state.warnings.append(
                    AgentNotice(
                        code="SCORE_VERIFICATION_MISMATCH",
                        message=result.message,
                        severity=NoticeSeverity.WARNING,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "deduplicate_findings":
            if result.status == ToolStatus.SUCCESS:
                unique_findings = getattr(result, "unique_findings", [])
                for f in unique_findings:
                    state.findings[f.finding_id] = f
                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id="EVID-DEDUP-SCAN",
                        evidence_type=EvidenceType.SCAN_DATA,
                        source=result.tool_name,
                        entity_id="findings_batch",
                        claim_or_property="deduplicated_findings_count",
                        value=len(unique_findings),
                        status=result.status,
                        provenance=prov,
                    )
                )
            else:
                state.errors.append(
                    AgentNotice(
                        code="DEDUPLICATION_ERROR",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "optimize_patch_capacity":
            if result.status == ToolStatus.SUCCESS:
                sched = getattr(result, "scheduled_candidates", [])
                defer = getattr(result, "deferred_candidates", [])
                state.scratchpad["optimized_plan"] = {
                    "scheduled_patches": [c.model_dump() if hasattr(c, "model_dump") else c for c in sched],
                    "deferred_patches": [c.model_dump() if hasattr(c, "model_dump") else c for c in defer],
                    "capacity_limit_hours": getattr(result, "capacity_limit_hours", 16.0),
                    "total_scheduled_effort_hours": getattr(result, "total_scheduled_effort_hours", 0.0),
                    "total_expected_risk_reduction": getattr(result, "total_expected_risk_reduction", 0.0),
                }
                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id="EVID-OPTIMIZE-PLAN",
                        evidence_type=EvidenceType.CAPACITY_SCHEDULE,
                        source=result.tool_name,
                        entity_id="remediation_schedule",
                        claim_or_property="scheduled_candidates_count",
                        value=len(sched),
                        status=result.status,
                        provenance=prov,
                    )
                )
            else:
                state.errors.append(
                    AgentNotice(
                        code="OPTIMIZATION_ERROR",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "validate_plan_constraints":
            is_valid = getattr(result, "is_valid", False)
            state.evidence.append(
                AgentEvidenceItem(
                    evidence_id="EVID-PLAN-VALIDATE",
                    evidence_type=EvidenceType.VERIFICATION,
                    source=result.tool_name,
                    entity_id="plan_constraints",
                    claim_or_property="plan_constraints_valid",
                    value=is_valid,
                    status=result.status,
                    provenance=prov,
                )
            )
            if not is_valid:
                violations = getattr(result, "violations", [])
                msg = "; ".join([v.violation_message for v in violations]) if violations else result.message
                state.warnings.append(
                    AgentNotice(
                        code="PLAN_CONSTRAINT_VIOLATION",
                        message=f"Remediation plan constraint validation failed: {msg}",
                        severity=NoticeSeverity.WARNING,
                        step_number=state.current_step,
                    )
                )

        elif tool_name == "simulate_risk_reduction":
            fid = action.target_finding_id or state.target_finding_id or "UNKNOWN"
            if result.status == ToolStatus.SUCCESS:
                cur_dec = getattr(result, "current_decision", AegisDecision.TRACK)
                sim_dec = getattr(result, "simulated_decision", AegisDecision.TRACK)
                state.scratchpad["simulation_result"] = {
                    "baseline_environmental_risk_score": getattr(result, "current_ers", 0.0),
                    "simulated_environmental_risk_score": getattr(result, "simulated_ers", 0.0),
                    "current_decision": cur_dec.value if hasattr(cur_dec, "value") else str(cur_dec),
                    "simulated_decision": sim_dec.value if hasattr(sim_dec, "value") else str(sim_dec),
                    "projected_risk_reduction": getattr(result, "projected_risk_reduction", 0.0),
                    "simulation_label": getattr(result, "simulation_label", "SIMULATED"),
                }
                state.evidence.append(
                    AgentEvidenceItem(
                        evidence_id=f"EVID-SIMULATE-{fid}",
                        evidence_type=EvidenceType.SIMULATION,
                        source=result.tool_name,
                        entity_id=fid,
                        claim_or_property="simulated_ers",
                        value=getattr(result, "simulated_ers", 0.0),
                        status=result.status,
                        provenance=prov,
                    )
                )
            else:
                state.errors.append(
                    AgentNotice(
                        code="SIMULATION_ERROR",
                        message=result.message,
                        severity=NoticeSeverity.ERROR,
                        step_number=state.current_step,
                    )
                )
