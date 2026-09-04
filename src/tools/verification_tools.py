"""Deterministic verification tools for Aegis Patch.

All tools in this module perform strict verification and integrity auditing.
None of these tools employ non-deterministic LLM prompting or heuristic guesses.
Tools verify mathematical score derivations, ground factual claims against evidence records,
and validate proposed patch plans against operational capacity and integrity constraints.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set

from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import (
    ClaimVerificationResult,
    ClaimVerificationStatus,
    DetectHallucinatedClaimsInput,
    DetectHallucinatedClaimsOutput,
    PlanConstraintViolation,
    ProvenanceSourceType,
    ScoreMismatch,
    SecurityClaim,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
    VerifyScoreDerivationInput,
    VerifyScoreDerivationOutput,
)


def verify_score_derivation(
    input_data: VerifyScoreDerivationInput,
) -> VerifyScoreDerivationOutput:
    """Independently recompute and verify a claimed risk assessment.

    Recomputes B, T, E, M_control, ERS, and decision using the authoritative
    Phase 3 risk engine and flags any discrepancies exceeding numerical tolerance.
    """
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    threat = ThreatEvidence(
        evidence_id=f"EV-VERIFY-{input_data.finding.cve_id}",
        cve_id=input_data.finding.cve_id,
        is_cisa_kev=input_data.is_cisa_kev,
        epss_score=input_data.epss_score,
        public_poc_available=input_data.public_poc_available,
        threat_source="independent_verification",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )

    recomputed = evaluate_risk(
        finding=input_data.finding,
        asset=input_data.asset,
        threat=threat,
    )

    tol = input_data.tolerance
    mismatches: List[ScoreMismatch] = []

    meta = recomputed.calculation_metadata
    actual_base = float(meta.get("base_score", recomputed.cvss_score * 10.0))
    actual_threat = float(meta.get("threat_score", 0.0))
    actual_env = float(meta.get("environmental_score", 50.0))
    actual_mult = float(meta.get("control_multiplier", 1.0))
    actual_decision = meta.get("aegis_decision", meta.get("remediation_decision", recomputed.decision.value))

    def _check_float(field: str, claimed: float, actual: float) -> None:
        diff = abs(claimed - actual)
        if diff > tol:
            mismatches.append(
                ScoreMismatch(
                    field=field,
                    claimed=claimed,
                    calculated=actual,
                    difference=round(diff, 4),
                )
            )

    _check_float("base_score", input_data.claimed_base_score, actual_base)
    _check_float("threat_score", input_data.claimed_threat_score, actual_threat)
    _check_float("environmental_score", input_data.claimed_environmental_score, actual_env)
    _check_float("control_multiplier", input_data.claimed_control_multiplier, actual_mult)
    _check_float("environmental_risk_score", input_data.claimed_ers, recomputed.environmental_risk_score)

    if input_data.claimed_decision.strip().upper() != actual_decision.strip().upper():
        mismatches.append(
            ScoreMismatch(
                field="decision",
                claimed=input_data.claimed_decision,
                calculated=actual_decision,
                difference=None,
            )
        )

    is_verified = len(mismatches) == 0
    status = ToolStatus.SUCCESS if is_verified else ToolStatus.VERIFICATION_FAILED
    msg = (
        "Risk score derivation verified successfully against authoritative engine."
        if is_verified
        else f"Score derivation verification failed with {len(mismatches)} mismatches."
    )

    return VerifyScoreDerivationOutput(
        tool_name="verify_score_derivation",
        status=status,
        message=msg,
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="independent_score_verifier",
            source_type=ProvenanceSourceType.CALCULATED,
            reference="src/tools/risk_engine.py",
        ),
        is_verified=is_verified,
        mismatches=mismatches,
        recomputed_ers=recomputed.environmental_risk_score,
        recomputed_decision=actual_decision,
    )


def detect_hallucinated_claims(
    input_data: DetectHallucinatedClaimsInput,
) -> DetectHallucinatedClaimsOutput:
    """Detect whether security assertions are supported by provided evidence records.

    Deterministic evidence-support checker.
    Examines each claim against the evidence record dictionary.
    Does NOT use an LLM or guess unsupported claims.
    """
    claims = input_data.claims
    evidence = input_data.evidence_records
    results: List[ClaimVerificationResult] = []
    unsupported_count = 0

    for c in claims:
        # Check if entity exists in evidence records
        entity_evidence = evidence.get(c.entity_id)
        if entity_evidence is None:
            results.append(
                ClaimVerificationResult(
                    claim_id=c.claim_id,
                    status=ClaimVerificationStatus.UNSUPPORTED,
                    evidence_reference=None,
                    rationale=f"No evidence record exists for entity '{c.entity_id}'.",
                )
            )
            unsupported_count += 1
            continue

        # Extract value from dictionary evidence
        actual_val = None
        if isinstance(entity_evidence, dict):
            # Try matching field by claim_type or exact key
            key_candidates = [
                c.claim_type.lower(),
                c.claim_type,
                "is_cisa_kev" if "KEV" in c.claim_type.upper() else "",
                "cvss_score" if "CVSS" in c.claim_type.upper() else "",
                "epss_score" if "EPSS" in c.claim_type.upper() else "",
                "network_exposure" if "EXPOSURE" in c.claim_type.upper() else "",
                "criticality" if "CRITICALITY" in c.claim_type.upper() else "",
            ]
            for k in key_candidates:
                if k and k in entity_evidence:
                    actual_val = entity_evidence[k]
                    break
        else:
            actual_val = getattr(entity_evidence, c.claim_type.lower(), None)

        if actual_val is None:
            results.append(
                ClaimVerificationResult(
                    claim_id=c.claim_id,
                    status=ClaimVerificationStatus.UNSUPPORTED,
                    evidence_reference=f"entity:{c.entity_id}",
                    rationale=f"Property for claim type '{c.claim_type}' is missing from evidence for '{c.entity_id}'.",
                )
            )
            unsupported_count += 1
        else:
            # Compare claimed value against actual value
            claimed = c.claimed_value
            matches = False
            if isinstance(actual_val, float) and isinstance(claimed, (float, int)):
                matches = math.isclose(float(actual_val), float(claimed), abs_tol=0.01)
            elif isinstance(actual_val, bool) and isinstance(claimed, bool):
                matches = (actual_val == claimed)
            elif str(actual_val).strip().upper() == str(claimed).strip().upper():
                matches = True

            if matches:
                results.append(
                    ClaimVerificationResult(
                        claim_id=c.claim_id,
                        status=ClaimVerificationStatus.SUPPORTED,
                        evidence_reference=f"entity:{c.entity_id}",
                        rationale=f"Claimed value '{claimed}' matches verified evidence '{actual_val}'.",
                    )
                )
            else:
                results.append(
                    ClaimVerificationResult(
                        claim_id=c.claim_id,
                        status=ClaimVerificationStatus.UNSUPPORTED,
                        evidence_reference=f"entity:{c.entity_id}",
                        rationale=f"Claimed value '{claimed}' conflicts with observed evidence '{actual_val}'.",
                    )
                )
                unsupported_count += 1

    all_supported = (unsupported_count == 0)
    status = ToolStatus.SUCCESS if all_supported else ToolStatus.VERIFICATION_FAILED
    msg = (
        f"All {len(claims)} security claims are verified by evidence."
        if all_supported
        else f"{unsupported_count} of {len(claims)} security claims are UNSUPPORTED by evidence."
    )

    return DetectHallucinatedClaimsOutput(
        tool_name="detect_hallucinated_claims",
        status=status,
        message=msg,
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="evidence_grounding_auditor",
            source_type=ProvenanceSourceType.CALCULATED,
        ),
        all_claims_supported=all_supported,
        results=results,
        unsupported_count=unsupported_count,
    )


def validate_plan_constraints(
    input_data: ValidatePlanConstraintsInput,
) -> ValidatePlanConstraintsOutput:
    """Validate a proposed remediation plan against hard operational constraints.

    Checks:
    - Non-negative effort hours
    - Capacity limit (sum of hours <= limit)
    - Valid finding references (all findings exist in known_finding_ids)
    - Duplicate findings inside the same plan
    - Non-empty plan
    - Rollback plan presence
    """
    violations: List[PlanConstraintViolation] = []
    warnings: List[str] = []
    total_hours = 0.0
    seen_findings: Set[str] = set()
    known_set = set(input_data.known_finding_ids)

    if not input_data.items:
        violations.append(
            PlanConstraintViolation(
                rule_name="NON_EMPTY_PLAN",
                violation_message="Proposed remediation plan contains no action items.",
            )
        )

    for item in input_data.items:
        # Check non-negative effort
        if item.estimated_hours < 0:
            violations.append(
                PlanConstraintViolation(
                    rule_name="NON_NEGATIVE_EFFORT",
                    violation_message=f"Item for {item.finding_id} has negative estimated hours ({item.estimated_hours}h).",
                )
            )
        else:
            total_hours += item.estimated_hours

        # Check valid finding reference
        if item.finding_id not in known_set:
            violations.append(
                PlanConstraintViolation(
                    rule_name="VALID_FINDING_REFERENCE",
                    violation_message=f"Finding ID '{item.finding_id}' does not exist in known finding registry.",
                )
            )

        # Check duplicates
        if item.finding_id in seen_findings:
            violations.append(
                PlanConstraintViolation(
                    rule_name="UNIQUE_FINDINGS",
                    violation_message=f"Duplicate finding ID '{item.finding_id}' scheduled multiple times in same plan.",
                )
            )
        seen_findings.add(item.finding_id)

        # Check rollback plan
        if not item.has_rollback_plan:
            violations.append(
                PlanConstraintViolation(
                    rule_name="ROLLBACK_PLAN_REQUIRED",
                    violation_message=f"Finding '{item.finding_id}' lacks mandatory rollback procedure.",
                )
            )

    # Check capacity limit
    if total_hours > input_data.capacity_limit_hours:
        violations.append(
            PlanConstraintViolation(
                rule_name="CAPACITY_LIMIT_EXCEEDED",
                violation_message=(
                    f"Total scheduled effort ({total_hours:.1f}h) exceeds maintenance window "
                    f"capacity limit ({input_data.capacity_limit_hours:.1f}h)."
                ),
            )
        )

    is_valid = (len(violations) == 0)
    status = ToolStatus.SUCCESS if is_valid else ToolStatus.CONSTRAINT_VIOLATION
    msg = (
        f"Plan '{input_data.plan_id}' passed all constraint checks."
        if is_valid
        else f"Plan '{input_data.plan_id}' violated {len(violations)} operational constraints."
    )

    return ValidatePlanConstraintsOutput(
        tool_name="validate_plan_constraints",
        status=status,
        message=msg,
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="plan_constraint_validator",
            source_type=ProvenanceSourceType.CALCULATED,
        ),
        is_valid=is_valid,
        violations=violations,
        warnings=warnings,
        total_estimated_hours=round(total_hours, 2),
        capacity_limit_hours=input_data.capacity_limit_hours,
    )
