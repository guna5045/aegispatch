"""Planner abstraction and deterministic multi-workflow planner for Aegis Patch agents.

Supports all four canonical Aegis Patch agent workflows:
- INVESTIGATE_FINDING: In-depth analysis of a single vulnerability finding.
- PRIORITIZE_FINDINGS: Multi-finding triage, contextual risk evaluation, and deterministic ranking.
- PLAN_REMEDIATION: Capacity-constrained patch scheduling via knapsack DP and constraint validation.
- WHAT_IF: Safe, non-destructive simulation of hypothetical controls or capacity changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from src.agents.schemas import (
    ActionTraceSummary,
    AgentAction,
    AgentEvidenceItem,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentWorkflowType,
    AssetSummary,
    EvidenceSummary,
    FailAction,
    FinalizeAction,
    FindingSummary,
    NoticeSeverity,
    PlannerDecision,
    ReplanAction,
    SupervisorLLMContext,
    SupervisorState,
)
from src.tools.registry import default_tool_registry
from src.tools.schemas import ToolStatus

DEFAULT_BENCHMARK_SCANS_PATH = (
    Path(__file__).resolve().parent.parent.parent / "data" / "synthetic" / "benchmark_60_scans.json"
)


class AgentPlanner(ABC):
    """Abstract interface for agent action planning."""

    @abstractmethod
    def plan(self, state: SupervisorState) -> Union[AgentAction, PlannerDecision]:
        """Analyze current state and determine the next discrete AgentAction or PlannerDecision.

        Args:
            state: Current strongly-typed supervisor state snapshot.

        Returns:
            Chosen AgentAction or PlannerDecision envelope.
        """
        raise NotImplementedError


# Alias for backward and architectural compatibility
SupervisorPlanner = AgentPlanner


class DeterministicSupervisorPlanner(AgentPlanner):
    """Deterministic, state-driven multi-workflow planner for the Supervisor Agent.

    Evaluates the current state snapshot to determine the exact next action.
    Dispatches to workflow-specific planning methods for INVESTIGATE_FINDING,
    PRIORITIZE_FINDINGS, PLAN_REMEDIATION, and WHAT_IF.
    """

    def __init__(self, scans_path: Optional[Path] = None) -> None:
        self._scans_path = scans_path or DEFAULT_BENCHMARK_SCANS_PATH
        self._raw_scans_cache: Optional[Dict[str, Dict[str, Any]]] = None

    def _get_raw_scan(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Load candidate raw scan data for finding_id if available."""
        if self._raw_scans_cache is None:
            self._raw_scans_cache = {}
            if self._scans_path.is_file():
                try:
                    with open(self._scans_path, "r", encoding="utf-8") as f:
                        scans = json.load(f)
                        if isinstance(scans, list):
                            for item in scans:
                                if isinstance(item, dict) and "finding_id" in item:
                                    self._raw_scans_cache[item["finding_id"]] = item
                except Exception:
                    pass
        return self._raw_scans_cache.get(finding_id)

    def plan(self, state: SupervisorState) -> AgentAction:
        """Inspect state and determine next discrete AgentAction.

        Args:
            state: Current strongly-typed supervisor state.

        Returns:
            Next AgentAction (CALL_TOOL, REPLAN, FINALIZE, or FAIL).
        """
        # 0. Guard already terminated states
        if state.status in (
            AgentExecutionStatus.COMPLETED,
            AgentExecutionStatus.FAILED,
            AgentExecutionStatus.MAX_ITERATIONS_REACHED,
            AgentExecutionStatus.VERIFICATION_FAILED,
        ):
            if state.status == AgentExecutionStatus.COMPLETED:
                return AgentAction(
                    action_type=AgentStepActionType.FINALIZE,
                    rationale="Workflow is already completed.",
                )
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="WORKFLOW_ALREADY_HALTED",
                rationale=f"Workflow is already in terminal status {state.status.value}.",
            )

        # Guard against excessive replanning cycles across all workflows
        replan_count = sum(1 for t in state.step_traces if t.action.action_type == AgentStepActionType.REPLAN)
        if replan_count >= 3:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="EXCESSIVE_REPLANNING",
                rationale=f"Exceeded maximum allowed replanning threshold ({replan_count}) without resolving missing evidence.",
            )

        # 1. Route to workflow-specific planning strategy
        if state.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING:
            return self._plan_investigate(state)
        elif state.workflow_type == AgentWorkflowType.PRIORITIZE_FINDINGS:
            return self._plan_prioritize(state)
        elif state.workflow_type == AgentWorkflowType.PLAN_REMEDIATION:
            return self._plan_remediation(state)
        elif state.workflow_type == AgentWorkflowType.WHAT_IF:
            return self._plan_what_if(state)
        else:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="UNSUPPORTED_WORKFLOW",
                rationale=f"Workflow '{state.workflow_type}' is not supported.",
            )

    # ==========================================================================
    # WORKFLOW 1: INVESTIGATE_FINDING
    # ==========================================================================

    def _plan_investigate(self, state: SupervisorState) -> AgentAction:
        """Plan progression for single-finding investigation."""
        finding_id = state.target_finding_id
        if not finding_id and state.context and state.context.investigate:
            finding_id = state.context.investigate.target_finding_id

        if not finding_id:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="MISSING_TARGET_FINDING",
                rationale="No target finding identifier was provided for investigation.",
            )

        # Stage 1: Finding Validation
        validation_trace = self._find_step_trace(state, "validate_finding_schema")
        if validation_trace is None:
            candidate_raw = None
            if finding_id in state.findings:
                candidate_raw = state.findings[finding_id].model_dump()
            else:
                candidate_raw = self._get_raw_scan(finding_id)

            if not candidate_raw:
                return AgentAction(
                    action_type=AgentStepActionType.FAIL,
                    error_code="FINDING_NOT_FOUND",
                    rationale=f"Target finding '{finding_id}' could not be located in working memory or scan repository.",
                    target_finding_id=finding_id,
                )

            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="validate_finding_schema",
                tool_arguments={"finding_data": candidate_raw},
                rationale=f"Validate finding schema for '{finding_id}' against authoritative contract.",
                target_finding_id=finding_id,
            )

        if validation_trace.status != ToolStatus.SUCCESS or finding_id not in state.findings:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="INVALID_FINDING_SCHEMA",
                rationale=f"Finding '{finding_id}' failed schema validation.",
                target_finding_id=finding_id,
            )

        finding = state.findings[finding_id]
        asset_id = state.target_asset_id or finding.asset_id

        # Stage 2: Retrieve Asset Context
        if asset_id not in state.assets:
            cmdb_trace = self._find_step_trace(state, "query_asset_cmdb")
            if cmdb_trace:
                if cmdb_trace.status == ToolStatus.NOT_FOUND:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="ASSET_NOT_FOUND",
                        rationale=f"Asset '{asset_id}' not found in enterprise CMDB; cannot calculate environmental risk.",
                        target_finding_id=finding_id,
                        target_asset_id=asset_id,
                    )
                elif cmdb_trace.status != ToolStatus.SUCCESS:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="ASSET_LOOKUP_FAILED",
                        rationale=f"CMDB lookup for asset '{asset_id}' failed with status {cmdb_trace.status.value}.",
                        target_finding_id=finding_id,
                        target_asset_id=asset_id,
                    )
                else:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="ASSET_LOOKUP_MALFORMED",
                        rationale=f"CMDB query for asset '{asset_id}' succeeded but did not populate asset context.",
                        target_finding_id=finding_id,
                        target_asset_id=asset_id,
                    )
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="query_asset_cmdb",
                tool_arguments={"asset_id": asset_id},
                rationale=f"Asset context is required before environmental risk calculation.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        asset = state.assets[asset_id]

        # Stage 3: Threat Intelligence Evidence Collection
        cve_id = finding.cve_id

        # 3a. CISA KEV
        kev_trace = self._find_step_trace(state, "lookup_cisa_kev")
        if kev_trace is None:
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="lookup_cisa_kev",
                tool_arguments={"cve_id": cve_id},
                rationale=f"Query local CISA KEV catalog for active exploitation telemetry on {cve_id}.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        # 3b. EPSS
        epss_trace = self._find_step_trace(state, "query_epss")
        if epss_trace is None:
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="query_epss",
                tool_arguments={"cve_id": cve_id},
                rationale=f"Retrieve EPSS exploit probability score for {cve_id}.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        # 3c. OSV Database (and Replanning check)
        osv_trace = self._find_step_trace(state, "query_osv_database")
        if osv_trace is None and finding.affected_package:
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="query_osv_database",
                tool_arguments={
                    "package_name": finding.affected_package,
                    "version": finding.installed_version,
                    "cve_id": cve_id,
                },
                rationale=f"Query local OSV dataset for package advisories on {finding.affected_package}.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        if osv_trace and osv_trace.status == ToolStatus.NOT_AVAILABLE:
            if not self._has_replanned_for(state, "THREAT_SOURCE_UNAVAILABLE"):
                return AgentAction(
                    action_type=AgentStepActionType.REPLAN,
                    trigger="THREAT_SOURCE_UNAVAILABLE",
                    rationale="OSV package database is unavailable offline; replanning to proceed with CISA KEV and EPSS telemetry.",
                    target_finding_id=finding_id,
                    target_asset_id=asset_id,
                )

        # Stage 4: Environmental Risk Calculation
        if finding_id not in state.risk_assessments:
            risk_trace = self._find_step_trace(state, "calculate_environmental_risk")
            if risk_trace:
                if risk_trace.status != ToolStatus.SUCCESS:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="RISK_CALCULATION_FAILED",
                        rationale=f"Environmental risk calculation failed for '{finding_id}': {risk_trace.notes or 'Calculation error'}.",
                        target_finding_id=finding_id,
                        target_asset_id=asset_id,
                    )
                else:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="RISK_CALCULATION_MALFORMED",
                        rationale=f"Risk calculation succeeded but did not populate risk assessment for '{finding_id}'.",
                        target_finding_id=finding_id,
                        target_asset_id=asset_id,
                    )

            is_cisa_kev = self._extract_cisa_kev_flag(state, cve_id)
            epss_score = self._extract_epss_score(state, cve_id)
            public_poc = self._extract_public_poc_flag(finding)

            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="calculate_environmental_risk",
                tool_arguments={
                    "finding": finding.model_dump(),
                    "asset": asset.model_dump(),
                    "is_cisa_kev": is_cisa_kev,
                    "epss_score": epss_score,
                    "public_poc_available": public_poc,
                },
                rationale=f"Calculate environmental risk score using Phase 3 risk engine with gathered evidence.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        # Stage 5: Score Derivation Verification Gate
        verify_trace = self._find_step_trace(state, "verify_score_derivation")
        if verify_trace is None:
            risk_trace = self._find_step_trace(state, "calculate_environmental_risk")
            if not risk_trace or not risk_trace.tool_result:
                return AgentAction(
                    action_type=AgentStepActionType.FAIL,
                    error_code="RISK_EVALUATION_MISSING",
                    rationale="Cannot verify score: risk evaluation output is missing.",
                    target_finding_id=finding_id,
                )

            res_dict = risk_trace.tool_result.model_dump()
            is_cisa_kev = self._extract_cisa_kev_flag(state, cve_id)
            epss_score = self._extract_epss_score(state, cve_id)
            public_poc = self._extract_public_poc_flag(finding)

            raw_decision = res_dict.get("decision", "TRACK")
            claimed_decision = raw_decision.value if hasattr(raw_decision, "value") else str(raw_decision)
            if claimed_decision.startswith("AegisDecision."):
                claimed_decision = claimed_decision.split(".", 1)[1]

            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="verify_score_derivation",
                tool_arguments={
                    "finding": finding.model_dump(),
                    "asset": asset.model_dump(),
                    "claimed_base_score": res_dict.get("base_score", 0.0),
                    "claimed_threat_score": res_dict.get("threat_score", 0.0),
                    "claimed_environmental_score": res_dict.get("environmental_score", 0.0),
                    "claimed_control_multiplier": res_dict.get("control_multiplier", 1.0),
                    "claimed_ers": res_dict.get("environmental_risk_score", 0.0),
                    "claimed_decision": claimed_decision,
                    "is_cisa_kev": is_cisa_kev,
                    "epss_score": epss_score,
                    "public_poc_available": public_poc,
                },
                rationale="Independently verify mathematical score derivation before finalization.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        verify_passed = False
        if verify_trace.tool_result and hasattr(verify_trace.tool_result, "is_verified"):
            verify_passed = bool(verify_trace.tool_result.is_verified)
        elif verify_trace.tool_result and isinstance(verify_trace.tool_result, dict):
            verify_passed = bool(verify_trace.tool_result.get("is_verified", False))

        if not verify_passed:
            if not self._has_replanned_for(state, "VERIFICATION_FAILED"):
                return AgentAction(
                    action_type=AgentStepActionType.REPLAN,
                    trigger="VERIFICATION_FAILED",
                    rationale="Mathematical score derivation verification failed; replanning required.",
                    target_finding_id=finding_id,
                    target_asset_id=asset_id,
                )
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="VERIFICATION_FAILED",
                rationale="Score derivation verification failed discrepancy check; refusing to finalize incorrect score.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        # Stage 6: Finalize Gate Hardening
        blocking_errors = [e for e in state.errors if e.severity == NoticeSeverity.ERROR]
        if blocking_errors:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="BLOCKING_ERRORS_PRESENT",
                rationale=f"Cannot finalize workflow: {len(blocking_errors)} blocking error(s) recorded in state.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        if finding_id not in state.findings:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="MISSING_VALIDATED_FINDING",
                rationale=f"Cannot finalize: finding '{finding_id}' is not in working memory.",
                target_finding_id=finding_id,
            )

        if asset_id not in state.assets:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="MISSING_ASSET_CONTEXT",
                rationale=f"Cannot finalize: asset '{asset_id}' is not in working memory.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        if finding_id not in state.risk_assessments:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="MISSING_RISK_ASSESSMENT",
                rationale=f"Cannot finalize: risk assessment for '{finding_id}' is missing.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        assessment = state.risk_assessments.get(finding_id)
        ers_val = assessment.environmental_risk_score if assessment else 0.0
        decision_val = assessment.decision.value if assessment else "TRACK"

        return AgentAction(
            action_type=AgentStepActionType.FINALIZE,
            rationale=f"Investigation for '{finding_id}' complete with verified ERS {ers_val:.2f} ({decision_val}).",
            target_finding_id=finding_id,
            target_asset_id=asset_id,
        )

    # ==========================================================================
    # WORKFLOW 2: PRIORITIZE_FINDINGS
    # ==========================================================================

    def _plan_prioritize(self, state: SupervisorState) -> AgentAction:
        """Plan progression for multi-finding prioritization and ranking."""
        scope_fids = list(state.selected_finding_ids)
        if not scope_fids and state.context and state.context.prioritize:
            scope_fids = list(state.context.prioritize.selected_finding_ids)
        if not scope_fids and state.findings:
            scope_fids = list(state.findings.keys())

        # If still empty, attempt to select canonical benchmark findings
        if not scope_fids:
            scope_fids = ["FINDING-001", "FINDING-002", "FINDING-003", "FINDING-004", "FINDING-005"]

        # Step 1: Validate/Ingest findings in scope
        for fid in scope_fids:
            if fid not in state.findings:
                candidate_raw = self._get_raw_scan(fid)
                if not candidate_raw:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="FINDING_NOT_FOUND",
                        rationale=f"Prioritization candidate finding '{fid}' could not be located in scans.",
                        target_finding_id=fid,
                    )
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="validate_finding_schema",
                    tool_arguments={"finding_data": candidate_raw},
                    rationale=f"Validate finding schema for '{fid}' in prioritization scope.",
                    target_finding_id=fid,
                )

        # Step 2: Deduplicate scoped findings if multiple exist
        if len(state.findings) >= 2 and self._find_step_trace(state, "deduplicate_findings") is None:
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="deduplicate_findings",
                tool_arguments={"findings": [f.model_dump() for f in state.findings.values()]},
                rationale="Deduplicate scoped candidate findings to identify unique vulnerabilities.",
            )

        # Step 3: Retrieve CMDB asset context for each finding
        for finding in state.findings.values():
            aid = finding.asset_id
            if aid not in state.assets:
                cmdb_trace = self._find_step_trace_for_asset(state, "query_asset_cmdb", aid)
                if cmdb_trace:
                    if cmdb_trace.status == ToolStatus.NOT_FOUND:
                        return AgentAction(
                            action_type=AgentStepActionType.FAIL,
                            error_code="ASSET_NOT_FOUND",
                            rationale=f"Asset '{aid}' not found in CMDB for finding '{finding.finding_id}'.",
                            target_asset_id=aid,
                        )
                    elif cmdb_trace.status != ToolStatus.SUCCESS:
                        return AgentAction(
                            action_type=AgentStepActionType.FAIL,
                            error_code="ASSET_LOOKUP_FAILED",
                            rationale=f"CMDB lookup for asset '{aid}' failed with status {cmdb_trace.status.value}.",
                            target_asset_id=aid,
                        )
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="query_asset_cmdb",
                    tool_arguments={"asset_id": aid},
                    rationale=f"Retrieve operational CMDB context for asset '{aid}'.",
                    target_asset_id=aid,
                )

        # Step 4: Gather threat telemetry (CISA KEV & EPSS)
        for finding in state.findings.values():
            cve = finding.cve_id
            if self._find_step_trace_for_cve(state, "lookup_cisa_kev", cve) is None:
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="lookup_cisa_kev",
                    tool_arguments={"cve_id": cve},
                    rationale=f"Check CISA KEV catalog for active exploitation on {cve}.",
                    target_finding_id=finding.finding_id,
                )
            if self._find_step_trace_for_cve(state, "query_epss", cve) is None:
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="query_epss",
                    tool_arguments={"cve_id": cve},
                    rationale=f"Retrieve EPSS exploit probability score for {cve}.",
                    target_finding_id=finding.finding_id,
                )

        # Step 5: Calculate Environmental Risk Score for each finding
        for finding in state.findings.values():
            fid = finding.finding_id
            if fid not in state.risk_assessments:
                risk_trace = self._find_step_trace_for_finding(state, "calculate_environmental_risk", fid)
                if risk_trace and risk_trace.status != ToolStatus.SUCCESS:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="RISK_CALCULATION_FAILED",
                        rationale=f"Risk calculation failed for '{fid}'.",
                        target_finding_id=fid,
                    )
                is_kev = self._extract_cisa_kev_flag(state, finding.cve_id)
                epss = self._extract_epss_score(state, finding.cve_id)
                poc = self._extract_public_poc_flag(finding)
                asset = state.assets[finding.asset_id]
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="calculate_environmental_risk",
                    tool_arguments={
                        "finding": finding.model_dump(),
                        "asset": asset.model_dump(),
                        "is_cisa_kev": is_kev,
                        "epss_score": epss,
                        "public_poc_available": poc,
                    },
                    rationale=f"Evaluate environmental risk score for finding '{fid}' on {asset.asset_id}.",
                    target_finding_id=fid,
                    target_asset_id=asset.asset_id,
                )

        # Step 6: Verify score derivation for each calculated finding
        for finding in state.findings.values():
            fid = finding.finding_id
            if self._find_step_trace_for_finding(state, "verify_score_derivation", fid) is None:
                assessment = state.risk_assessments[fid]
                res_dict = assessment.calculation_metadata
                is_kev = self._extract_cisa_kev_flag(state, finding.cve_id)
                epss = self._extract_epss_score(state, finding.cve_id)
                poc = self._extract_public_poc_flag(finding)
                raw_decision = res_dict.get("aegis_decision", assessment.decision.value)
                claimed_decision = raw_decision.value if hasattr(raw_decision, "value") else str(raw_decision)
                if claimed_decision.startswith("AegisDecision."):
                    claimed_decision = claimed_decision.split(".", 1)[1]

                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="verify_score_derivation",
                    tool_arguments={
                        "finding": finding.model_dump(),
                        "asset": state.assets[finding.asset_id].model_dump(),
                        "claimed_base_score": float(res_dict.get("base_score", assessment.cvss_score * 10.0)),
                        "claimed_threat_score": float(res_dict.get("threat_score", 0.0)),
                        "claimed_environmental_score": float(res_dict.get("environmental_score", 50.0)),
                        "claimed_control_multiplier": float(res_dict.get("control_multiplier", 1.0)),
                        "claimed_ers": assessment.environmental_risk_score,
                        "claimed_decision": claimed_decision,
                        "is_cisa_kev": is_kev,
                        "epss_score": epss,
                        "public_poc_available": poc,
                    },
                    rationale=f"Verify mathematical score derivation for finding '{fid}'.",
                    target_finding_id=fid,
                )

        # Step 7: Deterministic Ranking & Finalization Gate
        blocking_errors = [e for e in state.errors if e.severity == NoticeSeverity.ERROR]
        if blocking_errors:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="BLOCKING_ERRORS_PRESENT",
                rationale=f"Cannot finalize prioritization: {len(blocking_errors)} blocking error(s) present.",
            )

        # Deterministic sorting: (-ERS, -CVSS, finding_id ASC)
        ranked = sorted(
            state.findings.values(),
            key=lambda f: (
                -state.risk_assessments[f.finding_id].environmental_risk_score,
                -f.cvss_score,
                f.finding_id,
            ),
        )

        top_fid = ranked[0].finding_id
        top_ers = state.risk_assessments[top_fid].environmental_risk_score
        top_dec = state.risk_assessments[top_fid].calculation_metadata.get("aegis_decision", "PLAN")

        return AgentAction(
            action_type=AgentStepActionType.FINALIZE,
            rationale=f"Prioritized {len(ranked)} findings deterministically. Top priority: {top_fid} (ERS {top_ers:.2f}, {top_dec}).",
            target_finding_id=top_fid,
        )

    # ==========================================================================
    # WORKFLOW 3: PLAN_REMEDIATION
    # ==========================================================================

    def _plan_remediation(self, state: SupervisorState) -> AgentAction:
        """Plan progression for capacity-constrained remediation scheduling."""
        capacity_limit = 16.0
        target_fids: List[str] = []

        if state.context and state.context.plan_remediation:
            capacity_limit = state.context.plan_remediation.capacity_limit_hours
            target_fids = list(state.context.plan_remediation.target_finding_ids)

        if not target_fids and state.findings:
            target_fids = list(state.findings.keys())

        if not target_fids:
            target_fids = ["FINDING-001", "FINDING-002", "FINDING-003", "FINDING-004", "FINDING-005"]

        # Step 1: Ensure candidate findings exist, have asset context, and have risk calculated
        for fid in target_fids:
            if fid not in state.findings:
                candidate_raw = self._get_raw_scan(fid)
                if not candidate_raw:
                    return AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        error_code="FINDING_NOT_FOUND",
                        rationale=f"Remediation candidate '{fid}' could not be located in scan repository.",
                        target_finding_id=fid,
                    )
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="validate_finding_schema",
                    tool_arguments={"finding_data": candidate_raw},
                    rationale=f"Validate finding schema for '{fid}' in remediation scope.",
                    target_finding_id=fid,
                )

            finding = state.findings[fid]
            aid = finding.asset_id
            if aid not in state.assets:
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="query_asset_cmdb",
                    tool_arguments={"asset_id": aid},
                    rationale=f"Retrieve asset context for '{aid}'.",
                    target_asset_id=aid,
                )

            if fid not in state.risk_assessments:
                is_kev = self._extract_cisa_kev_flag(state, finding.cve_id)
                epss = self._extract_epss_score(state, finding.cve_id)
                poc = self._extract_public_poc_flag(finding)
                asset = state.assets[aid]
                return AgentAction(
                    action_type=AgentStepActionType.CALL_TOOL,
                    tool_name="calculate_environmental_risk",
                    tool_arguments={
                        "finding": finding.model_dump(),
                        "asset": asset.model_dump(),
                        "is_cisa_kev": is_kev,
                        "epss_score": epss,
                        "public_poc_available": poc,
                    },
                    rationale=f"Evaluate environmental risk for candidate '{fid}'.",
                    target_finding_id=fid,
                    target_asset_id=aid,
                )

        # Step 2: Knapsack 0/1 Capacity Optimization
        opt_trace = self._find_step_trace(state, "optimize_patch_capacity")
        if opt_trace is None:
            candidates = []
            for fid in target_fids:
                finding = state.findings[fid]
                assessment = state.risk_assessments[fid]
                effort = 4.0 if finding.cvss_score >= 8.0 else (3.0 if finding.cvss_score >= 6.0 else 2.0)
                candidates.append({
                    "candidate_id": f"CAND-{fid}",
                    "finding_id": fid,
                    "cve_id": finding.cve_id,
                    "asset_id": finding.asset_id,
                    "risk_tier": assessment.risk_tier.value,
                    "expected_risk_reduction": round(assessment.environmental_risk_score, 2),
                    "estimated_cost_hours": effort,
                    "dependencies": [],
                })

            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="optimize_patch_capacity",
                tool_arguments={"candidates": candidates, "capacity_limit_hours": capacity_limit},
                rationale=f"Optimize remediation schedule under {capacity_limit:.1f}h capacity limit via knapsack DP.",
            )

        if opt_trace.status != ToolStatus.SUCCESS:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="OPTIMIZATION_FAILED",
                rationale=f"Patch capacity optimization failed: {opt_trace.notes or 'Optimizer error'}.",
            )

        # Step 3: Validate Plan Constraints
        val_trace = self._find_step_trace(state, "validate_plan_constraints")
        if val_trace is None:
            scheduled_cands = getattr(opt_trace.tool_result, "scheduled_candidates", [])
            items = []
            for idx, c in enumerate(scheduled_cands):
                fid = getattr(c, "finding_id", None) or (c.get("finding_id") if isinstance(c, dict) else str(c))
                hrs = getattr(c, "estimated_cost_hours", None) or (c.get("estimated_cost_hours") if isinstance(c, dict) else 2.0)
                items.append(
                    {
                        "finding_id": fid,
                        "sequence_order": idx + 1,
                        "estimated_hours": float(hrs),
                        "has_rollback_plan": True,
                    }
                )
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="validate_plan_constraints",
                tool_arguments={
                    "plan_id": f"PLAN-{state.run_id}",
                    "capacity_limit_hours": capacity_limit,
                    "items": items,
                    "known_finding_ids": list(state.findings.keys()),
                },
                rationale="Validate proposed patch plan against capacity, uniqueness, and rollback constraints.",
            )

        # Step 4: Finalize
        is_plan_valid = getattr(val_trace.tool_result, "is_valid", False)
        if not is_plan_valid:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="VERIFICATION_FAILED",
                rationale="Proposed remediation plan violates operational safety constraints.",
            )

        scheduled_count = len(getattr(opt_trace.tool_result, "scheduled_candidates", []))
        total_effort = getattr(opt_trace.tool_result, "total_scheduled_effort_hours", 0.0)
        total_reduction = getattr(opt_trace.tool_result, "total_expected_risk_reduction", 0.0)

        return AgentAction(
            action_type=AgentStepActionType.FINALIZE,
            rationale=(
                f"Remediation plan synthesized and validated: {scheduled_count} actions scheduled "
                f"utilizing {total_effort:.1f}h of {capacity_limit:.1f}h capacity "
                f"(expected cumulative risk reduction: {total_reduction:.2f})."
            ),
        )

    # ==========================================================================
    # WORKFLOW 4: WHAT_IF
    # ==========================================================================

    def _plan_what_if(self, state: SupervisorState) -> AgentAction:
        """Plan progression for safe hypothetical risk simulation."""
        what_if_ctx = state.context.what_if if state.context else None
        finding_id = what_if_ctx.finding_id if what_if_ctx else state.target_finding_id
        asset_id = what_if_ctx.asset_id if what_if_ctx else state.target_asset_id
        hypo_controls = what_if_ctx.hypothetical_controls if what_if_ctx else []

        if not finding_id or not asset_id:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="MISSING_SIMULATION_PARAMETERS",
                rationale="What-If simulation requires both finding_id and asset_id.",
            )

        # Step 1: Ensure baseline finding and asset context are loaded
        if finding_id not in state.findings:
            candidate_raw = self._get_raw_scan(finding_id)
            if not candidate_raw:
                return AgentAction(
                    action_type=AgentStepActionType.FAIL,
                    error_code="FINDING_NOT_FOUND",
                    rationale=f"Baseline finding '{finding_id}' not found in scan repository.",
                    target_finding_id=finding_id,
                )
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="validate_finding_schema",
                tool_arguments={"finding_data": candidate_raw},
                rationale=f"Validate baseline finding schema for '{finding_id}'.",
                target_finding_id=finding_id,
            )

        if asset_id not in state.assets:
            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="query_asset_cmdb",
                tool_arguments={"asset_id": asset_id},
                rationale=f"Retrieve baseline asset context for '{asset_id}'.",
                target_asset_id=asset_id,
            )

        # Step 2: Simulate hypothetical risk reduction
        sim_trace = self._find_step_trace(state, "simulate_risk_reduction")
        if sim_trace is None:
            is_kev = self._extract_cisa_kev_flag(state, state.findings[finding_id].cve_id)
            epss = self._extract_epss_score(state, state.findings[finding_id].cve_id)
            poc = self._extract_public_poc_flag(state.findings[finding_id])

            return AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="simulate_risk_reduction",
                tool_arguments={
                    "finding": state.findings[finding_id].model_dump(),
                    "asset": state.assets[asset_id].model_dump(),
                    "hypothetical_controls_added": hypo_controls,
                    "is_cisa_kev": is_kev,
                    "epss_score": epss,
                    "public_poc_available": poc,
                },
                rationale=f"Simulate hypothetical impact of adding compensating controls {hypo_controls} on {finding_id}.",
                target_finding_id=finding_id,
                target_asset_id=asset_id,
            )

        if sim_trace.status != ToolStatus.SUCCESS:
            return AgentAction(
                action_type=AgentStepActionType.FAIL,
                error_code="SIMULATION_FAILED",
                rationale="What-If simulation tool execution failed.",
                target_finding_id=finding_id,
            )

        # Step 3: Finalize with explicit simulation markers
        res = sim_trace.tool_result
        delta = getattr(res, "projected_risk_reduction", 0.0)
        cur_ers = getattr(res, "current_ers", 0.0)
        sim_ers = getattr(res, "simulated_ers", 0.0)
        sim_dec = getattr(res, "simulated_decision", "TRACK")
        dec_str = sim_dec.value if hasattr(sim_dec, "value") else str(sim_dec)

        return AgentAction(
            action_type=AgentStepActionType.FINALIZE,
            rationale=(
                f"SIMULATION: Hypothetical addition of controls {hypo_controls} projects "
                f"ERS reduction from {cur_ers:.2f} to {sim_ers:.2f} (delta {delta:+.2f}, "
                f"projected decision: {dec_str})."
            ),
            target_finding_id=finding_id,
            target_asset_id=asset_id,
        )

    # ----------------------------------------------------------------------
    # Helper Inspection Methods
    # ----------------------------------------------------------------------

    def _find_step_trace(self, state: SupervisorState, tool_name: str) -> Optional[Any]:
        """Return the latest step trace for a tool invocation."""
        for trace in reversed(state.step_traces):
            if trace.action.tool_name == tool_name:
                return trace
        return None

    def _find_step_trace_for_finding(self, state: SupervisorState, tool_name: str, finding_id: str) -> Optional[Any]:
        """Return latest step trace for a tool invocation targeting a specific finding."""
        for trace in reversed(state.step_traces):
            if trace.action.tool_name == tool_name and trace.action.target_finding_id == finding_id:
                return trace
        return None

    def _find_step_trace_for_asset(self, state: SupervisorState, tool_name: str, asset_id: str) -> Optional[Any]:
        """Return latest step trace for a tool invocation targeting a specific asset."""
        for trace in reversed(state.step_traces):
            if trace.action.tool_name == tool_name and trace.action.target_asset_id == asset_id:
                return trace
        return None

    def _find_step_trace_for_cve(self, state: SupervisorState, tool_name: str, cve_id: str) -> Optional[Any]:
        """Return latest step trace for a tool invocation targeting a specific CVE."""
        for trace in reversed(state.step_traces):
            if trace.action.tool_name == tool_name:
                args = trace.action.tool_arguments or {}
                if args.get("cve_id") == cve_id:
                    return trace
        return None

    def _has_replanned_for(self, state: SupervisorState, trigger: str) -> bool:
        """Check if a REPLAN action with the given trigger has already occurred."""
        for trace in state.step_traces:
            if trace.action.action_type == AgentStepActionType.REPLAN and trace.action.trigger == trigger:
                return True
        return False

    def _extract_cisa_kev_flag(self, state: SupervisorState, cve_id: str) -> bool:
        """Inspect evidence to check whether CVE is listed in CISA KEV."""
        for ev in state.evidence:
            if ev.evidence_type.value == "CISA_KEV" and ev.entity_id == cve_id:
                if ev.status == ToolStatus.SUCCESS and ev.value is True:
                    return True
        return False

    def _extract_epss_score(self, state: SupervisorState, cve_id: str) -> Optional[float]:
        """Inspect evidence to extract EPSS score if available."""
        for ev in state.evidence:
            if ev.evidence_type.value == "EPSS" and ev.entity_id == cve_id:
                if ev.status == ToolStatus.SUCCESS and isinstance(ev.value, (int, float)):
                    return float(ev.value)
        return None

    def _extract_public_poc_flag(self, finding: Any) -> bool:
        """Check finding metadata for public exploit PoC availability."""
        if hasattr(finding, "raw_evidence") and isinstance(finding.raw_evidence, dict):
            if finding.raw_evidence.get("public_poc_available") is True:
                return True
        return False


# ==============================================================================
# Future LLM Planner Input Projection & Output Validation
# ==============================================================================

def build_llm_planner_input(
    state: SupervisorState,
    allowed_tools: Optional[List[str]] = None,
) -> SupervisorLLMContext:
    """Project a clean, sanitized representation of SupervisorState for LLM consumption.

    Enforces the security boundary by stripping:
    - Database sessions, connections, raw ORM instances
    - Tool callables, Python functions, code execution handles
    - API keys, credentials, secret configuration
    - Host filesystem paths and raw environment variables
    """
    findings_summaries = []
    for f in state.findings.values():
        pkg = None
        if hasattr(f, "raw_evidence") and isinstance(f.raw_evidence, dict):
            pkg = f.raw_evidence.get("package_name") or f.raw_evidence.get("component")
        findings_summaries.append(
            FindingSummary(
                finding_id=f.finding_id,
                cve_id=f.cve_id,
                severity=f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                cvss_score=f.cvss_score,
                asset_id=f.asset_id,
                package_name=pkg,
            )
        )

    assets_summaries = []
    for a in state.assets.values():
        assets_summaries.append(
            AssetSummary(
                asset_id=a.asset_id,
                asset_type=a.asset_type.value if hasattr(a.asset_type, "value") else str(a.asset_type),
                environment=a.environment.value if hasattr(a.environment, "value") else str(a.environment),
                criticality=a.criticality.value if hasattr(a.criticality, "value") else str(a.criticality),
                network_exposure=a.network_exposure.value if hasattr(a.network_exposure, "value") else str(a.network_exposure),
                data_sensitivity=a.data_sensitivity.value if hasattr(a.data_sensitivity, "value") else str(a.data_sensitivity),
            )
        )

    evidence_summaries = []
    for ev in state.evidence:
        evidence_summaries.append(
            EvidenceSummary(
                evidence_type=ev.evidence_type.value if hasattr(ev.evidence_type, "value") else str(ev.evidence_type),
                source=ev.source,
                claim=ev.claim_or_property,
                value=ev.value,
                status=ev.status.value if hasattr(ev.status, "value") else str(ev.status),
            )
        )

    risk_scores = {
        fid: assess.environmental_risk_score
        for fid, assess in state.risk_assessments.items()
    }

    action_traces = []
    for t in state.step_traces:
        action_traces.append(
            ActionTraceSummary(
                step_number=t.step_number,
                action_type=t.action.action_type.value if hasattr(t.action.action_type, "value") else str(t.action.action_type),
                tool_name=t.action.tool_name,
                status=t.status.value if hasattr(t.status, "value") else str(t.status),
                rationale=t.notes or t.action.rationale,
            )
        )

    if allowed_tools is not None:
        tools = list(allowed_tools)
    else:
        tools = [t.name for t in default_tool_registry.list_tools()]

    return SupervisorLLMContext(
        run_id=state.run_id,
        workflow_type=state.workflow_type,
        user_goal=state.user_goal,
        current_step=state.current_step,
        target_finding_id=state.target_finding_id,
        target_asset_id=state.target_asset_id,
        findings=findings_summaries,
        assets=assets_summaries,
        evidence=evidence_summaries,
        risk_scores=risk_scores,
        recent_actions=action_traces,
        allowed_tools=tools,
    )


def validate_llm_action(
    raw_action: Any,
    allowed_tools: Optional[List[str]] = None,
) -> AgentAction:
    """Validate that candidate LLM output conforms strictly to AgentAction and security constraints.

    Guarantees:
    - Output must be structurally valid AgentAction
    - CALL_TOOL action must target a registered tool in default_tool_registry
    - If allowed_tools whitelist is provided, tool_name must be in allowed_tools
    - Prohibits forbidden execution arguments (e.g. eval, exec, sql, cmd, subprocess)
    - No direct code execution, shell commands, or arbitrary callables allowed
    """
    action: AgentAction
    if isinstance(raw_action, dict):
        try:
            action = AgentAction.model_validate(raw_action)
        except Exception as err:
            raise ValueError(f"LLM output failed AgentAction validation: {err}") from err
    elif isinstance(raw_action, AgentAction):
        action = raw_action
    else:
        raise TypeError(f"Expected dict or AgentAction from LLM planner, got {type(raw_action).__name__}")

    # Tool execution safety validation
    if action.action_type == AgentStepActionType.CALL_TOOL:
        if not action.tool_name:
            raise ValueError("CALL_TOOL action must specify non-empty 'tool_name'.")

        if default_tool_registry.get(action.tool_name) is None:
            raise ValueError(
                f"CALL_TOOL action references unknown tool '{action.tool_name}'. "
                f"Must be a registered tool in default_tool_registry."
            )

        if allowed_tools is not None and action.tool_name not in allowed_tools:
            raise ValueError(
                f"Tool '{action.tool_name}' is not permitted by allowed_tools whitelist for this workflow."
            )

        # Inspect tool_arguments for forbidden injection keys
        forbidden_keys = {"__execute__", "eval", "exec", "cmd", "command", "subprocess", "shell", "raw_sql"}
        for k in action.tool_arguments.keys():
            if k.lower() in forbidden_keys:
                raise ValueError(f"Prohibited security parameter '{k}' detected in LLM tool arguments.")

    return action


# ==============================================================================
# LLM Planner Boundary & Fallback Composite
# ==============================================================================

class LLMSupervisorPlanner(AgentPlanner):
    """Placeholder contract for future LLM-based supervisor planning.

    Guarantees:
    - Fails explicitly with LLM_PLANNER_NOT_CONFIGURED when unconfigured
    - Never calls external model providers without configuration
    - Never executes fake responses or unvalidated actions
    """

    def __init__(self, model_provider: Optional[str] = None, is_configured: bool = False) -> None:
        self._model_provider = model_provider
        self._is_configured = is_configured

    @property
    def model_provider(self) -> Optional[str]:
        return self._model_provider

    @property
    def is_configured(self) -> bool:
        return self._is_configured

    def plan(self, state: SupervisorState) -> AgentAction:
        """Plan next action using LLM.

        Raises:
            RuntimeError: If planner is unconfigured.
        """
        if not self._is_configured:
            raise RuntimeError(
                "LLM_PLANNER_NOT_CONFIGURED: LLM supervisor planner is not configured or model provider is uninitialized."
            )
        raise NotImplementedError("LLM provider integration is deferred to future phase.")


class FallbackSupervisorPlanner(AgentPlanner):
    """Composite planner that delegates to primary planner with optional deterministic fallback.

    If the primary planner fails or is unconfigured, and enable_fallback is True,
    it delegates to the fallback planner (defaulting to DeterministicSupervisorPlanner)
    and records an audit notice on state.
    """

    def __init__(
        self,
        primary_planner: AgentPlanner,
        fallback_planner: Optional[AgentPlanner] = None,
        enable_fallback: bool = False,
    ) -> None:
        self._primary = primary_planner
        self._fallback = fallback_planner or DeterministicSupervisorPlanner()
        self._enable_fallback = enable_fallback

    @property
    def primary_planner(self) -> AgentPlanner:
        return self._primary

    @property
    def fallback_planner(self) -> AgentPlanner:
        return self._fallback

    @property
    def enable_fallback(self) -> bool:
        return self._enable_fallback

    def plan(self, state: SupervisorState) -> Union[AgentAction, PlannerDecision]:
        try:
            return self._primary.plan(state)
        except Exception as err:
            if self._enable_fallback:
                step_num = state.current_step if state.current_step >= 1 else 1
                state.warnings.append(
                    AgentNotice(
                        code="PLANNER_FALLBACK_TRIGGERED",
                        message=f"Primary planner failed ({err}); fell back to deterministic planner.",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_num,
                    )
                )
                return self._fallback.plan(state)
            raise
