"""Risk Combination Specialist Agent for Aegis Patch.

Phase 9D: Synthesizes vulnerability scanner findings, exploitability intelligence,
and enterprise asset context to evaluate contextual Environmental Risk Scores (ERS)
and triage decisions.

Architectural Guarantees:
1. Authoritative Engine: Contains ZERO risk formulas (B, T, E, R, M_control, ERS).
   All calculations delegate strictly to `calculate_environmental_risk` and `map_ssvc_decision`.
2. Tool Boundary: All queries route strictly through ToolRegistry.invoke.
   Never imports or calls tool functions directly or performs direct database access.
3. Evidence Consistency: Validates that finding, exploitability, and asset evidence
   all correspond to the exact same finding_id, cve_id, and asset_id.
4. State Isolation: Complete per-execution state isolation with zero mutable module-level state.
5. Determinism & Security: Untrusted input treatment; inert advisory data; no network, DB, or eval calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.agents.asset_criticality import AssetCriticalityResult, AssetCriticalityStatus
from src.agents.exploitability import (
    AssessmentConfidence,
    EvidenceStatus,
    ExploitabilityAgentStatus,
    ExploitabilityMaturity,
    ExploitabilityResult,
)
from src.agents.schemas import (
    AgentAction,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    NoticeSeverity,
)
from src.schemas.asset import Asset, CompensatingControl
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.schemas import (
    BaseToolResult,
    CalculateEnvironmentalRiskInput,
    CalculateEnvironmentalRiskOutput,
    MapSsvcDecisionInput,
    MapSsvcDecisionOutput,
    QueryAssetCmdbInput,
    QueryAssetCmdbOutput,
    ToolProvenance,
    ToolStatus,
)


class RiskCombinationStatus(str, Enum):
    """Categorical outcome status of the Risk Combination Agent workflow."""

    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    INVALID_INPUT = "INVALID_INPUT"
    FAILED = "FAILED"


class RiskEvidenceConsistency(BaseModel):
    """Integrity audit confirming agreement across multi-agent evidence sources."""

    model_config = ConfigDict(extra="forbid")

    finding_id_match: bool = Field(..., description="Whether finding_id matched across evidence")
    cve_id_match: bool = Field(..., description="Whether cve_id matched across finding and exploitability")
    asset_id_match: bool = Field(..., description="Whether asset_id matched across finding and asset context")
    is_consistent: bool = Field(..., description="Overall cross-evidence consistency flag")
    audit_notes: List[str] = Field(default_factory=list, description="Consistency validation notes")


class RiskEvidenceProvenance(BaseModel):
    """Provenance tracking for the composite risk calculation."""

    model_config = ConfigDict(extra="forbid")

    engine_version: str = Field(default="aegis_ers_deterministic_v1", description="Authoritative risk engine version")
    calculation_source: str = Field(default="calculate_environmental_risk", description="Invoked calculation tool")
    decision_source: str = Field(default="map_ssvc_decision", description="Invoked decision tool")
    exploitability_status: Optional[str] = Field(None, description="Exploitability agent evaluation status")
    asset_criticality_status: Optional[str] = Field(None, description="Asset criticality agent evaluation status")
    assessed_at: datetime = Field(..., description="Timestamp of risk combination synthesis")


class RiskCombinationInput(BaseModel):
    """Strongly typed input specification for the Risk Combination Agent."""

    model_config = ConfigDict(extra="forbid")

    finding: VulnerabilityFinding = Field(
        ...,
        description="Authoritative normalized vulnerability finding from Scan Intake / intake pipeline",
    )
    exploitability: ExploitabilityResult = Field(
        ...,
        description="Assessed exploitability intelligence result from Exploitability Specialist Agent",
    )
    asset_criticality: Optional[AssetCriticalityResult] = Field(
        default=None,
        description="Assessed asset context from Asset Criticality Specialist Agent (if evaluated)",
    )
    asset: Optional[Asset] = Field(
        default=None,
        description="Direct authoritative Asset model if asset context is already fully instantiated",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-evaluative contextual metadata tags",
    )


class RiskCombinationResult(BaseModel):
    """Authoritative contextual risk assessment delivered by Risk Combination Agent."""

    model_config = ConfigDict(extra="forbid")

    status: RiskCombinationStatus = Field(
        ...,
        description="Overall execution status of the risk combination assessment",
    )
    finding_id: str = Field(
        ...,
        description="Evaluated vulnerability finding identifier",
    )
    cve_id: str = Field(
        ...,
        description="Evaluated Common Vulnerabilities and Exposures identifier",
    )
    asset_id: str = Field(
        ...,
        description="Evaluated enterprise asset identifier",
    )
    base_score: Optional[float] = Field(
        default=None,
        description="Base vulnerability score B (CVSS scaled 0.0 - 100.0)",
    )
    threat_score: Optional[float] = Field(
        default=None,
        description="Threat telemetry score T (0.0 - 100.0)",
    )
    environmental_score: Optional[float] = Field(
        default=None,
        description="Asset environmental exposure score E (0.0 - 100.0)",
    )
    raw_risk_score: Optional[float] = Field(
        default=None,
        description="Composite unmitigated risk score R (0.0 - 100.0)",
    )
    control_multiplier: Optional[float] = Field(
        default=None,
        description="Compensating control multiplier M_control (0.60 - 1.00)",
    )
    environmental_risk_score: Optional[float] = Field(
        default=None,
        description="Final contextual Environmental Risk Score ERS (0.0 - 100.0)",
    )
    risk_tier: Optional[RiskTier] = Field(
        default=None,
        description="Assigned risk priority tier (CRITICAL, HIGH, MEDIUM, LOW)",
    )
    decision: Optional[AegisDecision] = Field(
        default=None,
        description="Aegis triage decision band (ACT, ATTEND, PLAN, TRACK)",
    )
    remediation_decision: Optional[RemediationDecision] = Field(
        default=None,
        description="Recommended operational triage decision",
    )
    explanation: Optional[str] = Field(
        default=None,
        description="Human-readable explanation from authoritative risk engine",
    )
    rationale: Optional[str] = Field(
        default=None,
        description="Evidence-grounded rationale summarizing key drivers of contextual risk",
    )
    supporting_evidence: List[str] = Field(
        default_factory=list,
        description="Specific factual statements backing the mathematical calculation",
    )
    consistency: RiskEvidenceConsistency = Field(
        ...,
        description="Evidence consistency audit results",
    )
    provenance: RiskEvidenceProvenance = Field(
        ...,
        description="Traceable computation and source provenance metadata",
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list,
        description="Actionable diagnostic warnings identified during synthesis",
    )
    errors: List[AgentNotice] = Field(
        default_factory=list,
        description="Unrecoverable or recoverable errors encountered during synthesis",
    )
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list,
        description="Chronological audit traces of tool invocations and execution steps",
    )
    evaluated_at: datetime = Field(
        ...,
        description="Timestamp when risk combination was evaluated",
    )


class RiskCombinationAgent:
    """Specialist agent responsible for contextual risk synthesis.

    Combines vulnerability baseline findings, threat exploitability intelligence,
    and asset environmental context into an authoritative contextual risk assessment
    by coordinating the Phase 3 deterministic calculation and decision mapping tools.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry or default_tool_registry

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def run(
        self,
        finding: Union[VulnerabilityFinding, RiskCombinationInput, Dict[str, Any]],
        exploitability: Optional[ExploitabilityResult] = None,
        asset_criticality: Optional[AssetCriticalityResult] = None,
        asset: Optional[Asset] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RiskCombinationResult:
        """Convenience invocation accepting individual contracts or input object."""
        if isinstance(finding, (RiskCombinationInput, dict)):
            return self.assess(finding)
        input_data = RiskCombinationInput(
            finding=finding,
            exploitability=exploitability,
            asset_criticality=asset_criticality,
            asset=asset,
            metadata=metadata or {},
        )
        return self.assess(input_data)

    def assess(
        self,
        input_data: Union[RiskCombinationInput, Dict[str, Any]],
    ) -> RiskCombinationResult:
        """Execute the deterministic risk combination workflow with isolated local state.

        Steps:
        1. Validate agent input schema.
        2. Validate cross-evidence consistency (finding_id, cve_id, asset_id).
        3. Resolve authoritative Asset entity (from input or query_asset_cmdb).
        4. Extract threat intelligence signals from ExploitabilityResult.
        5. Invoke tool `calculate_environmental_risk`.
        6. Invoke tool `map_ssvc_decision`.
        7. Synthesize evidence-grounded rationale from actual present factors.
        8. Return comprehensive RiskCombinationResult with full provenance.
        """
        step_traces: List[AgentStepTrace] = []
        errors: List[AgentNotice] = []
        warnings: List[AgentNotice] = []
        step_counter = 1
        now_utc = datetime.now(timezone.utc)

        # ----------------------------------------------------------------------
        # 1. Validate agent input schema
        # ----------------------------------------------------------------------
        if isinstance(input_data, dict):
            try:
                typed_input = RiskCombinationInput.model_validate(input_data)
            except Exception as val_err:
                return self._create_invalid_input_result(
                    finding_id=str(input_data.get("finding", {}).get("finding_id", "UNKNOWN") if isinstance(input_data.get("finding"), dict) else getattr(input_data.get("finding"), "finding_id", "UNKNOWN")),
                    cve_id=str(input_data.get("finding", {}).get("cve_id", "UNKNOWN") if isinstance(input_data.get("finding"), dict) else getattr(input_data.get("finding"), "cve_id", "UNKNOWN")),
                    asset_id=str(input_data.get("finding", {}).get("asset_id", "UNKNOWN") if isinstance(input_data.get("finding"), dict) else getattr(input_data.get("finding"), "asset_id", "UNKNOWN")),
                    error_message=f"Agent input validation failed: {val_err}",
                    step_counter=step_counter,
                    now_utc=now_utc,
                )
        elif isinstance(input_data, RiskCombinationInput):
            typed_input = input_data
        else:
            return self._create_invalid_input_result(
                finding_id="UNKNOWN",
                cve_id="UNKNOWN",
                asset_id="UNKNOWN",
                error_message=f"Expected RiskCombinationInput or dict, got {type(input_data).__name__}",
                step_counter=step_counter,
                now_utc=now_utc,
            )

        finding = typed_input.finding
        exploitability = typed_input.exploitability
        asset_crit = typed_input.asset_criticality
        direct_asset = typed_input.asset

        # ----------------------------------------------------------------------
        # 2. Validate cross-evidence consistency
        # ----------------------------------------------------------------------
        consistency_notes: List[str] = []
        finding_id_match = True
        cve_id_match = True
        asset_id_match = True

        # Finding ID cross-check
        if exploitability.finding_id and exploitability.finding_id != finding.finding_id:
            finding_id_match = False
            consistency_notes.append(
                f"Finding ID mismatch: finding has '{finding.finding_id}', but exploitability evidence specifies '{exploitability.finding_id}'."
            )

        if asset_crit and asset_crit.finding_id and asset_crit.finding_id != finding.finding_id:
            finding_id_match = False
            consistency_notes.append(
                f"Finding ID mismatch: finding has '{finding.finding_id}', but asset criticality specifies '{asset_crit.finding_id}'."
            )

        # CVE ID cross-check
        if exploitability.cve_id != finding.cve_id:
            cve_id_match = False
            consistency_notes.append(
                f"CVE ID mismatch: finding is '{finding.cve_id}', but exploitability evidence specifies '{exploitability.cve_id}'."
            )

        # Asset ID cross-check
        if direct_asset and direct_asset.asset_id != finding.asset_id:
            asset_id_match = False
            consistency_notes.append(
                f"Asset ID mismatch: finding references asset '{finding.asset_id}', but direct asset is '{direct_asset.asset_id}'."
            )

        if asset_crit and asset_crit.asset_id != finding.asset_id:
            asset_id_match = False
            consistency_notes.append(
                f"Asset ID mismatch: finding references asset '{finding.asset_id}', but asset criticality specifies '{asset_crit.asset_id}'."
            )

        is_consistent = finding_id_match and cve_id_match and asset_id_match
        consistency = RiskEvidenceConsistency(
            finding_id_match=finding_id_match,
            cve_id_match=cve_id_match,
            asset_id_match=asset_id_match,
            is_consistent=is_consistent,
            audit_notes=consistency_notes,
        )

        if not is_consistent:
            err_msg = f"Evidence consistency rejection: {'; '.join(consistency_notes)}"
            errors.append(
                AgentNotice(
                    code="EVIDENCE_INCONSISTENCY",
                    message=err_msg,
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=AgentAction(
                        action_type=AgentStepActionType.FAIL,
                        rationale="Mismatched evidence sources rejected before risk computation.",
                        error_code="EVIDENCE_INCONSISTENCY",
                        target_finding_id=finding.finding_id,
                        target_asset_id=finding.asset_id,
                    ),
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=err_msg,
                )
            )
            return RiskCombinationResult(
                status=RiskCombinationStatus.INVALID_INPUT,
                finding_id=finding.finding_id,
                cve_id=finding.cve_id,
                asset_id=finding.asset_id,
                consistency=consistency,
                provenance=RiskEvidenceProvenance(
                    assessed_at=now_utc,
                    exploitability_status=exploitability.status.value,
                    asset_criticality_status=asset_crit.status.value if asset_crit else None,
                ),
                warnings=warnings,
                errors=errors,
                step_traces=step_traces,
                evaluated_at=now_utc,
            )

        # ----------------------------------------------------------------------
        # 3. Resolve authoritative Asset entity
        # ----------------------------------------------------------------------
        target_asset: Optional[Asset] = None

        if direct_asset is not None:
            target_asset = direct_asset
        else:
            # Retrieve authoritative asset via query_asset_cmdb tool
            cmdb_action = AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="query_asset_cmdb",
                tool_arguments={"asset_id": finding.asset_id},
                rationale=f"Retrieve authoritative Asset model for asset '{finding.asset_id}' to support contextual calculation",
                target_finding_id=finding.finding_id,
                target_asset_id=finding.asset_id,
            )
            try:
                cmdb_input = QueryAssetCmdbInput(asset_id=finding.asset_id)
                cmdb_output = self._registry.invoke("query_asset_cmdb", cmdb_input)
                if not isinstance(cmdb_output, QueryAssetCmdbOutput):
                    raise ValueError(f"Malformed output from query_asset_cmdb: {cmdb_output}")

                if cmdb_output.status == ToolStatus.SUCCESS and cmdb_output.asset:
                    target_asset = cmdb_output.asset
                elif cmdb_output.status == ToolStatus.NOT_FOUND:
                    warnings.append(
                        AgentNotice(
                            code="ASSET_NOT_FOUND",
                            message=f"Asset '{finding.asset_id}' not found in CMDB.",
                            severity=NoticeSeverity.WARNING,
                            step_number=step_counter,
                        )
                    )
                else:
                    warnings.append(
                        AgentNotice(
                            code="CMDB_QUERY_FAILED",
                            message=f"CMDB query for asset '{finding.asset_id}' returned status {cmdb_output.status}",
                            severity=NoticeSeverity.WARNING,
                            step_number=step_counter,
                        )
                    )

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=cmdb_action,
                        tool_result=cmdb_output,
                        status=cmdb_output.status,
                        notes=f"Retrieved asset context for {finding.asset_id}: {cmdb_output.status.value}",
                    )
                )
            except Exception as cmdb_err:
                errors.append(
                    AgentNotice(
                        code="CMDB_TOOL_ERROR",
                        message=f"Failed to query CMDB for asset '{finding.asset_id}': {cmdb_err}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=cmdb_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=f"Exception querying CMDB: {cmdb_err}",
                    )
                )
            step_counter += 1

        if target_asset is None:
            err_msg = f"Authoritative Asset context could not be resolved for asset '{finding.asset_id}'."
            errors.append(
                AgentNotice(
                    code="MISSING_ASSET_CONTEXT",
                    message=err_msg,
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            return RiskCombinationResult(
                status=RiskCombinationStatus.FAILED,
                finding_id=finding.finding_id,
                cve_id=finding.cve_id,
                asset_id=finding.asset_id,
                consistency=consistency,
                provenance=RiskEvidenceProvenance(
                    assessed_at=now_utc,
                    exploitability_status=exploitability.status.value,
                    asset_criticality_status=asset_crit.status.value if asset_crit else None,
                ),
                warnings=warnings,
                errors=errors,
                step_traces=step_traces,
                evaluated_at=now_utc,
            )

        # ----------------------------------------------------------------------
        # 4. Extract threat intelligence signals honestly from ExploitabilityResult
        # ----------------------------------------------------------------------
        is_cisa_kev = exploitability.kev_evidence.is_known_exploited
        epss_score = exploitability.epss_evidence.epss_score

        # Check for public PoC or public exploit advisories from OSV
        public_poc_available = False
        if exploitability.osv_evidence.advisories:
            for adv in exploitability.osv_evidence.advisories:
                summary = str(adv.get("summary", "")).upper()
                details = str(adv.get("details", "")).upper()
                if "EXPLOIT" in summary or "POC" in summary or "PROOF-OF-CONCEPT" in details:
                    public_poc_available = True
                    break

        # Check for incomplete / unindexed threat intelligence
        if exploitability.kev_evidence.status in (EvidenceStatus.NOT_AVAILABLE, EvidenceStatus.ERROR):
            warnings.append(
                AgentNotice(
                    code="KEV_EVIDENCE_INCOMPLETE",
                    message=f"CISA KEV evidence status is {exploitability.kev_evidence.status.value}; threat score derivation may reflect unindexed telemetry.",
                    severity=NoticeSeverity.WARNING,
                    step_number=step_counter,
                )
            )

        if exploitability.epss_evidence.status in (EvidenceStatus.NOT_AVAILABLE, EvidenceStatus.ERROR, EvidenceStatus.NOT_FOUND):
            warnings.append(
                AgentNotice(
                    code="EPSS_EVIDENCE_INCOMPLETE",
                    message=f"EPSS evidence status is {exploitability.epss_evidence.status.value}; observed EPSS score is {epss_score}.",
                    severity=NoticeSeverity.WARNING,
                    step_number=step_counter,
                )
            )

        # Check for asset criticality warnings
        if asset_crit:
            if asset_crit.status == AssetCriticalityStatus.PARTIAL_SUCCESS:
                warnings.append(
                    AgentNotice(
                        code="ASSET_CONTEXT_PARTIAL",
                        message=f"Asset criticality assessment was partial; reachable_from_internet={asset_crit.reachable_from_internet}.",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                )

        # ----------------------------------------------------------------------
        # 5. Invoke tool: calculate_environmental_risk
        # ----------------------------------------------------------------------
        risk_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="calculate_environmental_risk",
            tool_arguments={
                "finding_id": finding.finding_id,
                "asset_id": target_asset.asset_id,
                "is_cisa_kev": is_cisa_kev,
                "epss_score": epss_score,
                "public_poc_available": public_poc_available,
            },
            rationale=f"Invoke authoritative Phase 3 risk engine for finding '{finding.finding_id}' on asset '{target_asset.asset_id}'",
            target_finding_id=finding.finding_id,
            target_asset_id=target_asset.asset_id,
        )

        calc_result: Optional[CalculateEnvironmentalRiskOutput] = None
        try:
            calc_input = CalculateEnvironmentalRiskInput(
                finding=finding,
                asset=target_asset,
                is_cisa_kev=is_cisa_kev,
                epss_score=epss_score,
                public_poc_available=public_poc_available,
            )
            raw_calc_output = self._registry.invoke("calculate_environmental_risk", calc_input)
            if not isinstance(raw_calc_output, CalculateEnvironmentalRiskOutput):
                raise ValueError(f"Malformed output from calculate_environmental_risk: {raw_calc_output}")

            calc_result = raw_calc_output
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=risk_action,
                    tool_result=calc_result,
                    status=calc_result.status,
                    notes=f"Computed ERS {calc_result.environmental_risk_score:.2f} ({calc_result.decision.value})",
                )
            )
        except Exception as calc_err:
            errors.append(
                AgentNotice(
                    code="RISK_CALCULATION_ERROR",
                    message=f"Tool 'calculate_environmental_risk' failed: {calc_err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=risk_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception in calculate_environmental_risk: {calc_err}",
                )
            )
            return RiskCombinationResult(
                status=RiskCombinationStatus.FAILED,
                finding_id=finding.finding_id,
                cve_id=finding.cve_id,
                asset_id=finding.asset_id,
                consistency=consistency,
                provenance=RiskEvidenceProvenance(
                    assessed_at=now_utc,
                    exploitability_status=exploitability.status.value,
                    asset_criticality_status=asset_crit.status.value if asset_crit else None,
                ),
                warnings=warnings,
                errors=errors,
                step_traces=step_traces,
                evaluated_at=now_utc,
            )
        step_counter += 1

        # ----------------------------------------------------------------------
        # 6. Invoke tool: map_ssvc_decision
        # ----------------------------------------------------------------------
        has_controls = len(target_asset.compensating_controls) > 0
        map_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="map_ssvc_decision",
            tool_arguments={
                "ers_score": calc_result.environmental_risk_score,
                "has_compensating_controls": has_controls,
            },
            rationale=f"Map ERS {calc_result.environmental_risk_score:.2f} to authoritative Aegis triage decision band",
            target_finding_id=finding.finding_id,
            target_asset_id=target_asset.asset_id,
        )

        map_result: Optional[MapSsvcDecisionOutput] = None
        try:
            map_input = MapSsvcDecisionInput(
                ers_score=calc_result.environmental_risk_score,
                has_compensating_controls=has_controls,
            )
            raw_map_output = self._registry.invoke("map_ssvc_decision", map_input)
            if not isinstance(raw_map_output, MapSsvcDecisionOutput):
                raise ValueError(f"Malformed output from map_ssvc_decision: {raw_map_output}")

            map_result = raw_map_output
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=map_action,
                    tool_result=map_result,
                    status=map_result.status,
                    notes=f"Mapped to decision {map_result.decision.value} ({map_result.risk_tier.value})",
                )
            )
        except Exception as map_err:
            # Non-fatal because calculate_environmental_risk already supplies decision
            warnings.append(
                AgentNotice(
                    code="DECISION_MAPPING_WARNING",
                    message=f"Tool 'map_ssvc_decision' failed: {map_err}; falling back to calculation result decision.",
                    severity=NoticeSeverity.WARNING,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=map_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception in map_ssvc_decision: {map_err}",
                )
            )
        step_counter += 1

        # ----------------------------------------------------------------------
        # 7. Synthesize evidence-grounded rationale from actual present factors
        # ----------------------------------------------------------------------
        rationale_parts: List[str] = []

        # Baseline factor
        rationale_parts.append(
            f"Vulnerability {finding.cve_id} carries a CVSS score of {finding.cvss_score:.1f} ({finding.severity.value}), "
            f"scaled to base score B={calc_result.base_score:.1f}."
        )

        # Threat factors
        if is_cisa_kev:
            rationale_parts.append(
                "Active in-the-wild exploitation is confirmed in the CISA KEV catalog, elevating threat score T to 100.0."
            )
        elif epss_score is not None and epss_score >= 0.50:
            rationale_parts.append(
                f"Elevated exploit probability observed via EPSS ({epss_score:.4f}), contributing to threat score T={calc_result.threat_score:.1f}."
            )
        elif public_poc_available:
            rationale_parts.append(
                f"Public proof-of-concept exploit code is published, contributing to threat score T={calc_result.threat_score:.1f}."
            )
        else:
            rationale_parts.append(
                f"No active KEV exploitation confirmed (threat score T={calc_result.threat_score:.1f})."
            )

        # Asset context factors
        rationale_parts.append(
            f"Deployed on {target_asset.business_tier.value} asset '{target_asset.hostname}' ({target_asset.criticality.value} criticality, "
            f"{target_asset.environment.value} environment) with {target_asset.network_exposure.value} network exposure "
            f"and {target_asset.data_sensitivity.value} data sensitivity (E={calc_result.environmental_score:.1f})."
        )

        # Compensating controls
        if calc_result.control_multiplier < 1.0:
            active_names = [c.name for c in target_asset.compensating_controls]
            rationale_parts.append(
                f"Active compensating controls ({', '.join(active_names)}) apply an effective mitigation multiplier M_control={calc_result.control_multiplier:.2f}."
            )
        else:
            rationale_parts.append("No active compensating control mitigation was applied (M_control=1.00).")

        # Decision conclusion
        final_dec = map_result.decision if map_result else calc_result.decision
        final_tier = map_result.risk_tier if map_result else calc_result.risk_tier
        rationale_parts.append(
            f"Resulting contextual Environmental Risk Score is {calc_result.environmental_risk_score:.2f} ({final_tier.value}), "
            f"placing this finding into the {final_dec.value} triage decision band."
        )

        rationale = " ".join(rationale_parts)

        # Determine overall status
        status = (
            RiskCombinationStatus.PARTIAL_SUCCESS
            if (len(warnings) > 0 or exploitability.status == ExploitabilityAgentStatus.PARTIAL_SUCCESS)
            else RiskCombinationStatus.SUCCESS
        )

        # ----------------------------------------------------------------------
        # 8. Assemble final RiskCombinationResult
        # ----------------------------------------------------------------------
        return RiskCombinationResult(
            status=status,
            finding_id=finding.finding_id,
            cve_id=finding.cve_id,
            asset_id=target_asset.asset_id,
            base_score=calc_result.base_score,
            threat_score=calc_result.threat_score,
            environmental_score=calc_result.environmental_score,
            raw_risk_score=calc_result.raw_risk_score,
            control_multiplier=calc_result.control_multiplier,
            environmental_risk_score=calc_result.environmental_risk_score,
            risk_tier=final_tier,
            decision=final_dec,
            remediation_decision=calc_result.remediation_decision,
            explanation=calc_result.explanation,
            rationale=rationale,
            supporting_evidence=calc_result.supporting_evidence,
            consistency=consistency,
            provenance=RiskEvidenceProvenance(
                engine_version=calc_result.engine_version,
                calculation_source="calculate_environmental_risk",
                decision_source="map_ssvc_decision",
                exploitability_status=exploitability.status.value,
                asset_criticality_status=asset_crit.status.value if asset_crit else None,
                assessed_at=now_utc,
            ),
            warnings=warnings,
            errors=errors,
            step_traces=step_traces,
            evaluated_at=now_utc,
        )

    def _create_invalid_input_result(
        self,
        finding_id: str,
        cve_id: str,
        asset_id: str,
        error_message: str,
        step_counter: int,
        now_utc: datetime,
    ) -> RiskCombinationResult:
        """Construct a standardized INVALID_INPUT result envelope."""
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
        consistency = RiskEvidenceConsistency(
            finding_id_match=False,
            cve_id_match=False,
            asset_id_match=False,
            is_consistent=False,
            audit_notes=[error_message],
        )
        return RiskCombinationResult(
            status=RiskCombinationStatus.INVALID_INPUT,
            finding_id=finding_id,
            cve_id=cve_id,
            asset_id=asset_id,
            consistency=consistency,
            provenance=RiskEvidenceProvenance(
                assessed_at=now_utc,
            ),
            warnings=[],
            errors=[notice],
            step_traces=[trace],
            evaluated_at=now_utc,
        )
