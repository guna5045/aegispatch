"""Verification Specialist Agent for Aegis Patch.

Phase 9F: Independently audits, challenges, and validates security conclusions
produced by other specialist agents.

Architectural Guarantees:
1. Independent Verification: Never blindly trusts upstream confidence, `verified=True`
   flags, or status codes. Re-evaluates claims using authoritative verification tools.
2. Three-State Logic: Explicitly distinguishes PASS, FAIL, NOT_APPLICABLE,
   NOT_AVAILABLE, and ERROR across each audit dimension.
3. Fail-Closed Safety: Any critical discrepancy, unsupported claim, or constraint
   violation results in REJECTED or NEEDS_REVIEW. Never fails open.
4. No Silent Repair: Reports defects with diagnostic evidence. Never alters candidate
   claims or calculations to force verification.
5. Multi-Dimensional Auditing:
   - Cross-evidence consistency (entity IDs match)
   - Mathematical score derivation (verify_score_derivation)
   - Factual claim grounding & hallucination detection (detect_hallucinated_claims)
   - Remediation plan constraint validation (validate_plan_constraints)
6. Tool Registry Boundary: All tools are invoked exclusively via ToolRegistry.invoke.
7. Determinism & Security: 100% reproducible execution with zero shared mutable state,
   no shell commands, no SSH connections, and no database mutations.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import math
from typing import Any, Dict, List, Optional, Set, Union
from pydantic import BaseModel, ConfigDict, Field

from src.agents.patch_plan import PatchPlanResult
from src.agents.risk_combination import RiskCombinationResult
from src.agents.schemas import (
    AgentAction,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    NoticeSeverity,
)
from src.schemas.asset import Asset
from src.schemas.plan import PatchPlan
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.schemas import (
    BaseToolResult,
    ClaimVerificationResult,
    ClaimVerificationStatus,
    DetectHallucinatedClaimsInput,
    DetectHallucinatedClaimsOutput,
    PlanConstraintItem,
    PlanConstraintViolation,
    ScoreMismatch,
    SecurityClaim,
    ToolProvenance,
    ToolStatus,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
    VerifyScoreDerivationInput,
    VerifyScoreDerivationOutput,
)


class VerificationAgentStatus(str, Enum):
    """Categorical outcome of the Verification Agent evaluation."""

    VERIFIED = "VERIFIED"
    REJECTED = "REJECTED"
    NEEDS_REVIEW = "NEEDS_REVIEW"
    INVALID_INPUT = "INVALID_INPUT"
    ERROR = "ERROR"


class CheckStatus(str, Enum):
    """Outcome status of an individual verification check dimension."""

    PASS = "PASS"
    FAIL = "FAIL"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    ERROR = "ERROR"


class CheckSeverity(str, Enum):
    """Severity classification of verification checks and failures."""

    CRITICAL = "CRITICAL"
    MAJOR = "MAJOR"
    MINOR = "MINOR"
    INFO = "INFO"


class VerificationCheckResult(BaseModel):
    """Detailed report for a discrete verification audit dimension."""

    model_config = ConfigDict(extra="forbid")

    check_name: str = Field(..., description="Name of the audit check (e.g. score_derivation)")
    status: CheckStatus = Field(..., description="Outcome of this specific check")
    severity: CheckSeverity = Field(default=CheckSeverity.CRITICAL, description="Check severity impact")
    details: str = Field(..., description="Summary of verification observations")
    mismatches: List[Dict[str, Any]] = Field(default_factory=list, description="Score mismatches if detected")
    violations: List[str] = Field(default_factory=list, description="Plan constraint violations if detected")
    unsupported_claims: List[Dict[str, Any]] = Field(default_factory=list, description="Unsupported claims if detected")


class VerificationProvenance(BaseModel):
    """Provenance audit trail for the verification execution."""

    model_config = ConfigDict(extra="forbid")

    verifier_version: str = Field(default="aegis_verification_specialist_v1", description="Verification agent version")
    score_verifier_tool: str = Field(default="verify_score_derivation", description="Mathematical score verification tool")
    claim_checker_tool: str = Field(default="detect_hallucinated_claims", description="Evidence grounding checker tool")
    plan_validator_tool: str = Field(default="validate_plan_constraints", description="Plan constraint validation tool")
    candidate_id: str = Field(..., description="Target candidate identifier verified")
    verified_at: datetime = Field(..., description="Timestamp of verification execution")


class VerificationInput(BaseModel):
    """Strongly typed input specification for the Verification Specialist Agent."""

    model_config = ConfigDict(extra="forbid")

    candidate_id: Optional[str] = Field(
        default=None,
        description="Candidate identifier being verified",
    )
    finding: Optional[VulnerabilityFinding] = Field(
        default=None,
        description="Target normalized vulnerability finding",
    )
    asset: Optional[Asset] = Field(
        default=None,
        description="Target enterprise asset context",
    )
    risk_assessment: Optional[Union[RiskAssessment, RiskCombinationResult]] = Field(
        default=None,
        description="Claimed risk assessment record undergoing independent verification",
    )
    patch_plan: Optional[Union[PatchPlan, PatchPlanResult]] = Field(
        default=None,
        description="Proposed remediation plan undergoing constraint verification",
    )
    claims: List[SecurityClaim] = Field(
        default_factory=list,
        description="Specific factual claims to audit against ground-truth evidence",
    )
    evidence_records: Dict[str, Any] = Field(
        default_factory=dict,
        description="Ground-truth evidence dictionary supporting claim verification",
    )
    tolerance: float = Field(
        default=0.01,
        ge=0.0,
        description="Allowable numerical tolerance for mathematical score comparisons",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-evaluative contextual metadata",
    )


class VerificationResult(BaseModel):
    """Authoritative audit verdict delivered by the Verification Specialist Agent."""

    model_config = ConfigDict(extra="forbid")

    status: VerificationAgentStatus = Field(
        ...,
        description="Overall verification verdict (VERIFIED, REJECTED, NEEDS_REVIEW, INVALID_INPUT, ERROR)",
    )
    candidate_id: str = Field(
        ...,
        description="Identifier of the evaluated security candidate",
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Associated finding identifier if evaluated",
    )
    cve_id: Optional[str] = Field(
        default=None,
        description="Associated CVE identifier if evaluated",
    )
    asset_id: Optional[str] = Field(
        default=None,
        description="Associated asset identifier if evaluated",
    )
    overall_passed: bool = Field(
        ...,
        description="True if all applicable checks passed with zero critical or major failures",
    )
    checks: Dict[str, VerificationCheckResult] = Field(
        default_factory=dict,
        description="Breakdown of discrete verification check outcomes",
    )
    summary: str = Field(
        ...,
        description="Audit-ready executive summary of verification findings",
    )
    reasons: List[str] = Field(
        default_factory=list,
        description="Detailed factual justifications for the verdict",
    )
    provenance: VerificationProvenance = Field(
        ...,
        description="Audit provenance metadata",
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list,
        description="Actionable diagnostic warnings identified during audit",
    )
    errors: List[AgentNotice] = Field(
        default_factory=list,
        description="Errors or validation failures encountered during audit",
    )
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list,
        description="Chronological audit traces of verification steps",
    )
    verified_at: datetime = Field(
        ...,
        description="Timestamp when verification was completed",
    )


class VerificationAgent:
    """Specialist agent responsible for independent security auditing and verification.

    Applies strict three-state logic across mathematical integrity, evidence grounding,
    and plan constraints to challenge and validate downstream security assertions.
    """

    def __init__(self, registry: Optional[ToolRegistry] = None) -> None:
        self._registry = registry or default_tool_registry

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def run(
        self,
        candidate_id: Optional[Union[str, VerificationInput, Dict[str, Any]]] = None,
        finding: Optional[VulnerabilityFinding] = None,
        asset: Optional[Asset] = None,
        risk_assessment: Optional[Union[RiskAssessment, RiskCombinationResult]] = None,
        patch_plan: Optional[Union[PatchPlan, PatchPlanResult]] = None,
        claims: Optional[List[SecurityClaim]] = None,
        evidence_records: Optional[Dict[str, Any]] = None,
        tolerance: float = 0.01,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """Convenience invocation accepting individual parameters or input object."""
        if isinstance(candidate_id, (VerificationInput, dict)):
            return self.verify(candidate_id)
        try:
            v_input = VerificationInput(
                candidate_id=candidate_id,
                finding=finding,
                asset=asset,
                risk_assessment=risk_assessment,
                patch_plan=patch_plan,
                claims=claims or [],
                evidence_records=evidence_records or {},
                tolerance=tolerance,
                metadata=metadata or {},
            )
        except Exception as val_err:
            return self._create_invalid_input_result(
                candidate_id="CANDIDATE-INVALID",
                error_message=f"Agent input validation failed: {val_err}",
                now_utc=datetime.now(timezone.utc),
            )
        return self.verify(v_input)

    def verify(
        self,
        input_data: Union[VerificationInput, Dict[str, Any]],
    ) -> VerificationResult:
        """Execute the multi-dimensional independent verification pipeline with isolated local state.

        Dimensions:
        1. Input validation & Cross-evidence consistency (finding_id, cve_id, asset_id).
        2. Mathematical Score Derivation via `verify_score_derivation`.
        3. Factual Claim Grounding & Hallucination Audit via `detect_hallucinated_claims`.
        4. Plan Constraint Validation via `validate_plan_constraints`.
        5. Synthesis into final fail-closed verdict.
        """
        step_traces: List[AgentStepTrace] = []
        errors: List[AgentNotice] = []
        warnings: List[AgentNotice] = []
        checks: Dict[str, VerificationCheckResult] = {}
        reasons: List[str] = []
        step_counter = 1
        now_utc = datetime.now(timezone.utc)

        # ----------------------------------------------------------------------
        # 1. Validate Input Structure
        # ----------------------------------------------------------------------
        if isinstance(input_data, dict):
            try:
                typed_input = VerificationInput.model_validate(input_data)
            except Exception as val_err:
                return self._create_invalid_input_result(
                    candidate_id=str(input_data.get("candidate_id", "CANDIDATE-INVALID")),
                    error_message=f"Input structure validation failed: {val_err}",
                    now_utc=now_utc,
                )
        elif isinstance(input_data, VerificationInput):
            typed_input = input_data
        else:
            return self._create_invalid_input_result(
                candidate_id="CANDIDATE-INVALID",
                error_message=f"Expected VerificationInput or dict, got {type(input_data).__name__}",
                now_utc=now_utc,
            )

        finding = typed_input.finding
        asset = typed_input.asset
        risk = typed_input.risk_assessment
        plan = typed_input.patch_plan
        claims = typed_input.claims
        evidence = typed_input.evidence_records
        tol = typed_input.tolerance

        # Determine primary candidate identity
        candidate_id = typed_input.candidate_id or "CANDIDATE-UNKNOWN"
        finding_id: Optional[str] = None
        cve_id: Optional[str] = None
        asset_id: Optional[str] = None

        if finding:
            if not typed_input.candidate_id:
                candidate_id = f"CAND-{finding.finding_id}"
            finding_id = finding.finding_id
            cve_id = finding.cve_id
            asset_id = finding.asset_id
        elif risk:
            if not typed_input.candidate_id:
                candidate_id = f"CAND-{getattr(risk, 'finding_id', 'RISK')}"
            finding_id = getattr(risk, "finding_id", None)
            cve_id = getattr(risk, "cve_id", None)
            asset_id = getattr(risk, "asset_id", None)
        elif plan:
            if not typed_input.candidate_id:
                candidate_id = getattr(plan, "plan_id", "PLAN")
        elif claims:
            if not typed_input.candidate_id:
                candidate_id = f"CLAIMS-{len(claims)}"

        # Must supply at least one testable dimension
        if not (finding or risk or plan or claims):
            return self._create_invalid_input_result(
                candidate_id=candidate_id,
                error_message="Verification input is empty: must supply finding, risk assessment, patch plan, or claims.",
                now_utc=now_utc,
            )

        # ----------------------------------------------------------------------
        # 2. Check Cross-Evidence Consistency
        # ----------------------------------------------------------------------
        consistency_mismatches: List[str] = []

        if finding and risk:
            if finding.finding_id != getattr(risk, "finding_id", ""):
                consistency_mismatches.append(
                    f"Finding ID mismatch: finding has '{finding.finding_id}', but risk assessment has '{getattr(risk, 'finding_id', '')}'."
                )
            if finding.cve_id != getattr(risk, "cve_id", ""):
                consistency_mismatches.append(
                    f"CVE ID mismatch: finding has '{finding.cve_id}', but risk assessment has '{getattr(risk, 'cve_id', '')}'."
                )
            if finding.asset_id != getattr(risk, "asset_id", ""):
                consistency_mismatches.append(
                    f"Asset ID mismatch: finding references '{finding.asset_id}', but risk assessment has '{getattr(risk, 'asset_id', '')}'."
                )

        if finding and asset:
            if finding.asset_id != asset.asset_id:
                consistency_mismatches.append(
                    f"Asset ID mismatch: finding references asset '{finding.asset_id}', but asset context is '{asset.asset_id}'."
                )

        if risk and asset:
            if getattr(risk, "asset_id", "") != asset.asset_id:
                consistency_mismatches.append(
                    f"Asset ID mismatch: risk assessment references asset '{getattr(risk, 'asset_id', '')}', but asset context is '{asset.asset_id}'."
                )

        if consistency_mismatches:
            err_msg = f"Cross-evidence consistency failed: {'; '.join(consistency_mismatches)}"
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
                        rationale=err_msg,
                        error_code="EVIDENCE_INCONSISTENCY",
                    ),
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=err_msg,
                )
            )
            checks["cross_evidence_consistency"] = VerificationCheckResult(
                check_name="cross_evidence_consistency",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                details=err_msg,
                violations=consistency_mismatches,
            )
            reasons.append(err_msg)
            return VerificationResult(
                status=VerificationAgentStatus.REJECTED,
                candidate_id=candidate_id,
                finding_id=finding_id,
                cve_id=cve_id,
                asset_id=asset_id,
                overall_passed=False,
                checks=checks,
                summary=f"Candidate rejected due to cross-evidence inconsistency: {err_msg}",
                reasons=reasons,
                provenance=VerificationProvenance(candidate_id=candidate_id, verified_at=now_utc),
                warnings=warnings,
                errors=errors,
                step_traces=step_traces,
                verified_at=now_utc,
            )
        else:
            checks["cross_evidence_consistency"] = VerificationCheckResult(
                check_name="cross_evidence_consistency",
                status=CheckStatus.PASS,
                severity=CheckSeverity.CRITICAL,
                details="Cross-evidence entity IDs match across all provided structures.",
            )

        # ----------------------------------------------------------------------
        # 3. Dimension 1: Mathematical Score Derivation Verification
        # ----------------------------------------------------------------------
        if risk and finding and asset:
            score_action = AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="verify_score_derivation",
                tool_arguments={"finding_id": finding.finding_id, "asset_id": asset.asset_id},
                rationale=f"Independently recompute and audit risk score derivation for finding '{finding.finding_id}'",
                target_finding_id=finding.finding_id,
                target_asset_id=asset.asset_id,
            )

            # Extract claimed values without duplicating calculation formulas
            if isinstance(risk, RiskAssessment):
                meta = risk.calculation_metadata
                claimed_base = float(meta["base_score"]) if "base_score" in meta else None
                claimed_threat = float(meta["threat_score"]) if "threat_score" in meta else None
                claimed_env = float(meta["environmental_score"]) if "environmental_score" in meta else None
                claimed_mult = float(meta["control_multiplier"]) if "control_multiplier" in meta else None
                claimed_ers = float(risk.environmental_risk_score)
                claimed_dec = meta.get("aegis_decision", meta.get("remediation_decision", risk.decision.value))
                is_kev = meta.get("is_cisa_kev", "false").lower() == "true"
                epss_val = float(meta["epss_score"]) if meta.get("epss_score") not in (None, "none", "None") else None
                poc = meta.get("public_poc_available", "false").lower() == "true"
            else:
                # RiskCombinationResult
                claimed_base = float(risk.base_score) if risk.base_score is not None else None
                claimed_threat = float(risk.threat_score) if risk.threat_score is not None else None
                claimed_env = float(risk.environmental_score) if risk.environmental_score is not None else None
                claimed_mult = float(risk.control_multiplier) if risk.control_multiplier is not None else None
                claimed_ers = float(risk.environmental_risk_score) if risk.environmental_risk_score is not None else None
                claimed_dec = risk.decision.value if risk.decision else "TRACK"
                # Infer threat signals from supporting evidence or threat score
                is_kev = claimed_threat == 100.0
                epss_val = None
                poc = False

            try:
                v_tool_input = VerifyScoreDerivationInput(
                    finding=finding,
                    asset=asset,
                    claimed_base_score=claimed_base,
                    claimed_threat_score=claimed_threat,
                    claimed_environmental_score=claimed_env,
                    claimed_control_multiplier=claimed_mult,
                    claimed_ers=claimed_ers,
                    claimed_decision=claimed_dec,
                    is_cisa_kev=is_kev,
                    epss_score=epss_val,
                    public_poc_available=poc,
                    tolerance=tol,
                )
                raw_score_output = self._registry.invoke("verify_score_derivation", v_tool_input)
                if not isinstance(raw_score_output, VerifyScoreDerivationOutput):
                    raise ValueError(f"Malformed output from verify_score_derivation: {raw_score_output}")

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=score_action,
                        tool_result=raw_score_output,
                        status=raw_score_output.status,
                        notes=f"Mathematical verification status: {raw_score_output.status.value}, is_verified={raw_score_output.is_verified}",
                    )
                )

                if raw_score_output.is_verified:
                    checks["mathematical_score_derivation"] = VerificationCheckResult(
                        check_name="mathematical_score_derivation",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.CRITICAL,
                        details="Independently recomputed ERS matches claimed assessment within tolerance.",
                    )
                else:
                    mismatch_dicts = [m.model_dump() for m in raw_score_output.mismatches]
                    mismatch_descs = [f"{m.field} (claimed: {m.claimed}, actual: {m.calculated})" for m in raw_score_output.mismatches]
                    err_text = f"Score derivation mismatch: {', '.join(mismatch_descs)}"
                    checks["mathematical_score_derivation"] = VerificationCheckResult(
                        check_name="mathematical_score_derivation",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        details=err_text,
                        mismatches=mismatch_dicts,
                    )
                    errors.append(
                        AgentNotice(
                            code="SCORE_DERIVATION_MISMATCH",
                            message=err_text,
                            severity=NoticeSeverity.ERROR,
                            step_number=step_counter,
                        )
                    )
                    reasons.append(err_text)
            except Exception as score_err:
                err_text = f"Tool 'verify_score_derivation' failed: {score_err}"
                errors.append(
                    AgentNotice(
                        code="SCORE_VERIFIER_ERROR",
                        message=err_text,
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=score_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=err_text,
                    )
                )
                checks["mathematical_score_derivation"] = VerificationCheckResult(
                    check_name="mathematical_score_derivation",
                    status=CheckStatus.ERROR,
                    severity=CheckSeverity.CRITICAL,
                    details=err_text,
                )
                reasons.append(err_text)
            step_counter += 1
        elif risk:
            # Risk assessment provided without finding/asset context needed to recompute
            checks["mathematical_score_derivation"] = VerificationCheckResult(
                check_name="mathematical_score_derivation",
                status=CheckStatus.NOT_AVAILABLE,
                severity=CheckSeverity.MAJOR,
                details="Cannot verify mathematical derivation: candidate finding or asset context missing.",
            )
            warnings.append(
                AgentNotice(
                    code="CANNOT_RECOMPUTE_RISK",
                    message="Mathematical derivation could not be recomputed due to missing finding or asset object.",
                    severity=NoticeSeverity.WARNING,
                    step_number=step_counter,
                )
            )
        else:
            checks["mathematical_score_derivation"] = VerificationCheckResult(
                check_name="mathematical_score_derivation",
                status=CheckStatus.NOT_APPLICABLE,
                severity=CheckSeverity.INFO,
                details="No risk assessment candidate supplied.",
            )

        # ----------------------------------------------------------------------
        # 4. Dimension 2: Claim Grounding & Hallucination Audit
        # ----------------------------------------------------------------------
        if claims:
            claim_action = AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="detect_hallucinated_claims",
                tool_arguments={"claim_count": len(claims)},
                rationale=f"Audit {len(claims)} security claims against available factual evidence records",
            )
            try:
                claim_input = DetectHallucinatedClaimsInput(
                    claims=claims,
                    evidence_records=evidence,
                )
                raw_claim_output = self._registry.invoke("detect_hallucinated_claims", claim_input)
                if not isinstance(raw_claim_output, DetectHallucinatedClaimsOutput):
                    raise ValueError(f"Malformed output from detect_hallucinated_claims: {raw_claim_output}")

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=claim_action,
                        tool_result=raw_claim_output,
                        status=raw_claim_output.status,
                        notes=f"Claim verification: all_supported={raw_claim_output.all_claims_supported}, unsupported={raw_claim_output.unsupported_count}",
                    )
                )

                if raw_claim_output.all_claims_supported:
                    checks["claim_grounding"] = VerificationCheckResult(
                        check_name="claim_grounding",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.CRITICAL,
                        details=f"All {len(claims)} security claims are verified and grounded in evidence.",
                    )
                else:
                    unsupported_list = [r.model_dump() for r in raw_claim_output.results if r.status != ClaimVerificationStatus.SUPPORTED]
                    descs = [f"Claim {r.claim_id}: {r.rationale}" for r in raw_claim_output.results if r.status != ClaimVerificationStatus.SUPPORTED]
                    err_text = f"Unsupported security claims detected ({raw_claim_output.unsupported_count}/{len(claims)}): {'; '.join(descs)}"
                    checks["claim_grounding"] = VerificationCheckResult(
                        check_name="claim_grounding",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        details=err_text,
                        unsupported_claims=unsupported_list,
                    )
                    errors.append(
                        AgentNotice(
                            code="UNSUPPORTED_CLAIMS_DETECTED",
                            message=err_text,
                            severity=NoticeSeverity.ERROR,
                            step_number=step_counter,
                        )
                    )
                    reasons.append(err_text)
            except Exception as claim_err:
                err_text = f"Tool 'detect_hallucinated_claims' failed: {claim_err}"
                errors.append(
                    AgentNotice(
                        code="CLAIM_CHECKER_ERROR",
                        message=err_text,
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=claim_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=err_text,
                    )
                )
                checks["claim_grounding"] = VerificationCheckResult(
                    check_name="claim_grounding",
                    status=CheckStatus.ERROR,
                    severity=CheckSeverity.CRITICAL,
                    details=err_text,
                )
                reasons.append(err_text)
            step_counter += 1
        else:
            checks["claim_grounding"] = VerificationCheckResult(
                check_name="claim_grounding",
                status=CheckStatus.NOT_APPLICABLE,
                severity=CheckSeverity.INFO,
                details="No specific factual security claims submitted for grounding.",
            )

        # ----------------------------------------------------------------------
        # 5. Dimension 3: Patch Plan Constraint Validation
        # ----------------------------------------------------------------------
        if plan:
            plan_action = AgentAction(
                action_type=AgentStepActionType.CALL_TOOL,
                tool_name="validate_plan_constraints",
                tool_arguments={"plan_id": getattr(plan, "plan_id", "PLAN")},
                rationale="Audit proposed patch plan against operational capacity, uniqueness, and safety constraints",
            )
            try:
                # Convert plan candidate actions into PlanConstraintItem models
                p_id = getattr(plan, "plan_id", "PLAN")
                p_cap = float(getattr(plan, "capacity_limit_hours", 16.0))
                p_items: List[PlanConstraintItem] = []
                known_fids: List[str] = []

                if isinstance(plan, PatchPlanResult):
                    for a in plan.scheduled_actions:
                        p_items.append(
                            PlanConstraintItem(
                                finding_id=a.finding_id,
                                sequence_order=a.sequence_order,
                                estimated_hours=a.estimated_hours,
                                has_rollback_plan=bool(a.rollback_procedure),
                            )
                        )
                    known_fids = list(set(plan.scheduled_finding_ids + plan.deferred_finding_ids))
                elif isinstance(plan, PatchPlan):
                    for a in plan.actions:
                        p_items.append(
                            PlanConstraintItem(
                                finding_id=a.finding_id,
                                sequence_order=a.sequence_order,
                                estimated_hours=1.0,
                                has_rollback_plan=bool(a.rollback_plan),
                            )
                        )

                if "known_finding_ids" in typed_input.metadata:
                    known_fids = list(typed_input.metadata["known_finding_ids"])
                elif finding:
                    known_fids = [finding.finding_id]
                elif isinstance(plan, PatchPlanResult):
                    known_fids = list(set(plan.scheduled_finding_ids + plan.deferred_finding_ids))
                elif isinstance(plan, PatchPlan):
                    known_fids = [c.finding_id for c in plan.candidates] or [a.finding_id for a in plan.actions]

                plan_val_input = ValidatePlanConstraintsInput(
                    plan_id=p_id,
                    capacity_limit_hours=p_cap,
                    items=p_items,
                    known_finding_ids=known_fids,
                )
                raw_plan_output = self._registry.invoke("validate_plan_constraints", plan_val_input)
                if not isinstance(raw_plan_output, ValidatePlanConstraintsOutput):
                    raise ValueError(f"Malformed output from validate_plan_constraints: {raw_plan_output}")

                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=plan_action,
                        tool_result=raw_plan_output,
                        status=raw_plan_output.status,
                        notes=f"Plan constraint validation: is_valid={raw_plan_output.is_valid}, violations={len(raw_plan_output.violations)}",
                    )
                )

                if raw_plan_output.is_valid:
                    checks["patch_plan_constraints"] = VerificationCheckResult(
                        check_name="patch_plan_constraints",
                        status=CheckStatus.PASS,
                        severity=CheckSeverity.CRITICAL,
                        details="Patch plan satisfies capacity, uniqueness, and rollback constraints.",
                    )
                else:
                    v_msgs = [v.violation_message for v in raw_plan_output.violations]
                    err_text = f"Patch plan constraint violation(s): {'; '.join(v_msgs)}"
                    checks["patch_plan_constraints"] = VerificationCheckResult(
                        check_name="patch_plan_constraints",
                        status=CheckStatus.FAIL,
                        severity=CheckSeverity.CRITICAL,
                        details=err_text,
                        violations=v_msgs,
                    )
                    errors.append(
                        AgentNotice(
                            code="PLAN_CONSTRAINT_VIOLATION",
                            message=err_text,
                            severity=NoticeSeverity.ERROR,
                            step_number=step_counter,
                        )
                    )
                    reasons.append(err_text)
            except Exception as plan_err:
                err_text = f"Tool 'validate_plan_constraints' failed: {plan_err}"
                errors.append(
                    AgentNotice(
                        code="PLAN_VALIDATOR_ERROR",
                        message=err_text,
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )
                step_traces.append(
                    AgentStepTrace(
                        step_number=step_counter,
                        action=plan_action,
                        tool_result=None,
                        status=ToolStatus.ERROR,
                        notes=err_text,
                    )
                )
                checks["patch_plan_constraints"] = VerificationCheckResult(
                    check_name="patch_plan_constraints",
                    status=CheckStatus.ERROR,
                    severity=CheckSeverity.CRITICAL,
                    details=err_text,
                )
                reasons.append(err_text)
            step_counter += 1
        else:
            checks["patch_plan_constraints"] = VerificationCheckResult(
                check_name="patch_plan_constraints",
                status=CheckStatus.NOT_APPLICABLE,
                severity=CheckSeverity.INFO,
                details="No patch plan candidate supplied for validation.",
            )

        # ----------------------------------------------------------------------
        # 6. Synthesize Multi-Dimensional Audit Verdict (Fail-Closed)
        # ----------------------------------------------------------------------
        has_critical_failure = any(
            c.status in (CheckStatus.FAIL, CheckStatus.ERROR) and c.severity == CheckSeverity.CRITICAL
            for c in checks.values()
        )
        has_major_failure = any(
            c.status in (CheckStatus.FAIL, CheckStatus.ERROR) and c.severity == CheckSeverity.MAJOR
            for c in checks.values()
        )
        has_unavailability = any(
            c.status == CheckStatus.NOT_AVAILABLE
            for c in checks.values()
        )

        if has_critical_failure:
            final_status = VerificationAgentStatus.REJECTED
            overall_passed = False
            summary = f"Verification audit REJECTED candidate '{candidate_id}' due to critical verification failure: {'; '.join(reasons)}."
        elif has_major_failure or has_unavailability:
            final_status = VerificationAgentStatus.NEEDS_REVIEW
            overall_passed = False
            summary = f"Verification audit flagged candidate '{candidate_id}' as NEEDS_REVIEW due to unverified or unavailable evidence: {'; '.join(reasons or ['Incomplete audit sources'])}."
        else:
            final_status = VerificationAgentStatus.VERIFIED
            overall_passed = True
            passed_names = [k for k, v in checks.items() if v.status == CheckStatus.PASS]
            summary = f"Candidate '{candidate_id}' successfully VERIFIED across {len(passed_names)} audit dimension(s)."
            reasons.append("All applicable verification checks passed within mathematical tolerance and evidence boundaries.")

        return VerificationResult(
            status=final_status,
            candidate_id=candidate_id,
            finding_id=finding_id,
            cve_id=cve_id,
            asset_id=asset_id,
            overall_passed=overall_passed,
            checks=checks,
            summary=summary,
            reasons=reasons,
            provenance=VerificationProvenance(candidate_id=candidate_id, verified_at=now_utc),
            warnings=warnings,
            errors=errors,
            step_traces=step_traces,
            verified_at=now_utc,
        )

    def _create_invalid_input_result(
        self,
        candidate_id: str,
        error_message: str,
        now_utc: datetime,
    ) -> VerificationResult:
        """Standardized INVALID_INPUT result envelope."""
        notice = AgentNotice(
            code="INVALID_VERIFICATION_INPUT",
            message=error_message,
            severity=NoticeSeverity.ERROR,
            step_number=1,
        )
        trace = AgentStepTrace(
            step_number=1,
            action=AgentAction(
                action_type=AgentStepActionType.FAIL,
                rationale=error_message,
                error_code="INVALID_VERIFICATION_INPUT",
            ),
            tool_result=None,
            status=ToolStatus.ERROR,
            notes=error_message,
        )
        checks = {
            "input_schema": VerificationCheckResult(
                check_name="input_schema",
                status=CheckStatus.FAIL,
                severity=CheckSeverity.CRITICAL,
                details=error_message,
            )
        }
        return VerificationResult(
            status=VerificationAgentStatus.INVALID_INPUT,
            candidate_id=candidate_id,
            overall_passed=False,
            checks=checks,
            summary=f"Verification rejected due to invalid input: {error_message}",
            reasons=[error_message],
            provenance=VerificationProvenance(candidate_id=candidate_id, verified_at=now_utc),
            warnings=[],
            errors=[notice],
            step_traces=[trace],
            verified_at=now_utc,
        )
