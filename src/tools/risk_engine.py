"""Deterministic calculation core for AegisPatch Environmental Risk Scoring (ERS).

Mathematical Model:
    B = CVSS * 10
    T = Threat Score (100 if CISA KEV; else EPSS * 80 + PoC * 20)
    E = (Criticality * 0.50) + (Exposure * 0.30) + (DataSensitivity * 0.20)
    R = (0.25 * B) + (0.40 * T) + (0.35 * E)
    ERS = min(100.0, R * M_control)
    where 0.60 <= M_control <= 1.00
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    CompensatingControl,
    ControlStatus,
    DataSensitivity,
    NetworkExposure,
)
from src.schemas.context import AssetContext, PolicyCitation
from src.schemas.risk import (
    ControlAdjustment,
    RemediationDecision,
    RiskAssessment,
    RiskTier,
)
from src.schemas.threat import ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.decision_mapping import (
    DECISION_MEANINGS,
    AegisDecision,
    get_decision_details,
    map_ers_to_decision,
)
from src.tools.risk_config import (
    CONTROL_DISCOUNTS,
    CONTROL_MULTIPLIER_MAX,
    CONTROL_MULTIPLIER_MIN,
    CRITICALITY_SCORES,
    CVSS_BASE_SCALE,
    DEFAULT_ACTIVE_CONTROL_DISCOUNT,
    ELIGIBLE_CONTROL_STATUS,
    EXPOSURE_SCORES,
    SENSITIVITY_SCORES,
    THREAT_SCORE_KEV,
    THREAT_WEIGHT_EPSS,
    THREAT_WEIGHT_POC,
    WEIGHT_BASE_CVSS,
    WEIGHT_ENV_CRITICALITY,
    WEIGHT_ENV_EXPOSURE,
    WEIGHT_ENV_SENSITIVITY,
    WEIGHT_ENVIRONMENTAL,
    WEIGHT_THREAT,
    determine_remediation_decision,
    determine_risk_tier,
)


def calculate_base_score(cvss_score: float) -> float:
    """Scale CVSS base score (0.0 - 10.0) to standard 0.0 - 100.0 base contribution B."""
    if not (0.0 <= cvss_score <= 10.0):
        raise ValueError(f"CVSS score must be between 0.0 and 10.0, got: {cvss_score}")
    return round(cvss_score * CVSS_BASE_SCALE, 4)


def calculate_threat_score(threat: Optional[ThreatEvidence]) -> Tuple[float, Dict[str, Any]]:
    """Calculate threat score T (0.0 - 100.0) from threat intelligence signals.

    Rules:
    - If listed on CISA KEV: T = 100.0
    - Otherwise: T = (EPSS * 80.0) + (public_poc * 20.0)
    - If threat intelligence is missing / None: T = 0.0 (explicitly flagged in breakdown)
    """
    if threat is None:
        return 0.0, {
            "threat_status": "MISSING_OR_UNINDEXED",
            "is_cisa_kev": False,
            "epss_score": None,
            "epss_contribution": 0.0,
            "public_poc_available": False,
            "poc_contribution": 0.0,
            "threat_score": 0.0,
        }

    if threat.is_cisa_kev:
        return THREAT_SCORE_KEV, {
            "threat_status": "CISA_KEV_CONFIRMED",
            "is_cisa_kev": True,
            "epss_score": threat.epss_score,
            "epss_contribution": (threat.epss_score * THREAT_WEIGHT_EPSS) if threat.epss_score is not None else None,
            "public_poc_available": threat.public_poc_available,
            "poc_contribution": THREAT_WEIGHT_POC if threat.public_poc_available else 0.0,
            "threat_score": THREAT_SCORE_KEV,
        }

    # When not on KEV: evaluate EPSS and public PoC
    epss_contrib = 0.0
    epss_available = threat.epss_score is not None
    if epss_available:
        epss_contrib = threat.epss_score * THREAT_WEIGHT_EPSS

    poc_contrib = THREAT_WEIGHT_POC if threat.public_poc_available else 0.0
    total_threat = min(100.0, max(0.0, epss_contrib + poc_contrib))

    return round(total_threat, 4), {
        "threat_status": "EPSS_AND_POC_EVALUATED",
        "is_cisa_kev": False,
        "epss_score": threat.epss_score,
        "epss_available": epss_available,
        "epss_contribution": round(epss_contrib, 4),
        "public_poc_available": threat.public_poc_available,
        "poc_contribution": poc_contrib,
        "threat_score": round(total_threat, 4),
    }


def calculate_environmental_score(
    asset_or_context: Union[Asset, AssetContext],
) -> Tuple[float, Dict[str, Any]]:
    """Calculate environmental factor E (0.0 - 100.0) based on asset context.

    Formula:
        E = (criticality * 0.50) + (network_exposure * 0.30) + (data_sensitivity * 0.20)
    """
    crit = asset_or_context.criticality
    exp = asset_or_context.network_exposure
    sens = asset_or_context.data_sensitivity

    crit_score = CRITICALITY_SCORES.get(crit, 50.0)
    exp_score = EXPOSURE_SCORES.get(exp, 40.0)
    sens_score = SENSITIVITY_SCORES.get(sens, 40.0)

    weighted_crit = crit_score * WEIGHT_ENV_CRITICALITY
    weighted_exp = exp_score * WEIGHT_ENV_EXPOSURE
    weighted_sens = sens_score * WEIGHT_ENV_SENSITIVITY

    total_env = min(100.0, max(0.0, weighted_crit + weighted_exp + weighted_sens))

    return round(total_env, 4), {
        "criticality": crit.value,
        "criticality_score": crit_score,
        "criticality_contribution": round(weighted_crit, 4),
        "network_exposure": exp.value,
        "exposure_score": exp_score,
        "exposure_contribution": round(weighted_exp, 4),
        "data_sensitivity": sens.value,
        "sensitivity_score": sens_score,
        "sensitivity_contribution": round(weighted_sens, 4),
        "environmental_score": round(total_env, 4),
    }


def _match_control_discount(control_name: str, description: str) -> float:
    """Identify the applicable discount for a compensating control based on category.

    Unknown or unrelated controls return 0.0 (no invented discounts).
    """
    combined = f"{control_name} {description}".upper().replace("_", " ")
    for keyword, discount in CONTROL_DISCOUNTS.items():
        if keyword in combined:
            return discount
    return DEFAULT_ACTIVE_CONTROL_DISCOUNT


def calculate_control_multiplier(
    controls: Sequence[CompensatingControl],
) -> Tuple[float, List[ControlAdjustment]]:
    """Calculate the compensating control multiplier M_control and adjustments.

    Multiplier is strictly bounded: 0.60 <= M_control <= 1.00.
    Only recognized controls with status == ACTIVE reduce risk.
    Unrelated/unknown controls receive 0.0 discount and do not reduce risk.
    """
    if not controls:
        return 1.0, []

    total_discount = 0.0
    adjustments: List[ControlAdjustment] = []

    for ctrl in controls:
        if ctrl.status == ELIGIBLE_CONTROL_STATUS:
            discount = _match_control_discount(ctrl.name, ctrl.description)
            if discount > 0.0:
                total_discount += discount
                adjustments.append(
                    ControlAdjustment(
                        control_id=ctrl.control_id,
                        name=ctrl.name,
                        adjustment_factor=-round(discount, 4),
                        description=f"Active compensating control applied: {ctrl.description}",
                    )
                )

    raw_multiplier = 1.0 - total_discount
    # Enforce strict bounds: 0.60 <= M_control <= 1.00
    bounded_multiplier = max(CONTROL_MULTIPLIER_MIN, min(CONTROL_MULTIPLIER_MAX, raw_multiplier))

    return round(bounded_multiplier, 4), adjustments


def calculate_weighted_risk(
    base_score: float,
    threat_score: float,
    environmental_score: float,
) -> float:
    """Calculate unmitigated composite risk score R (0.0 - 100.0).

    Formula:
        R = (0.25 * B) + (0.40 * T) + (0.35 * E)
    """
    r = (
        (WEIGHT_BASE_CVSS * base_score)
        + (WEIGHT_THREAT * threat_score)
        + (WEIGHT_ENVIRONMENTAL * environmental_score)
    )
    return round(min(100.0, max(0.0, r)), 4)


def calculate_ers(weighted_risk: float, control_multiplier: float) -> float:
    """Apply the compensating-control multiplier to compute final ERS.

    Formula:
        ERS = min(100.0, R * M_control)
    Guaranteed bounds: 0.0 <= ERS <= 100.0
    """
    if not (CONTROL_MULTIPLIER_MIN <= control_multiplier <= CONTROL_MULTIPLIER_MAX):
        # Defensively clamp rather than allow out-of-bounds multiplier
        control_multiplier = max(CONTROL_MULTIPLIER_MIN, min(CONTROL_MULTIPLIER_MAX, control_multiplier))

    ers = weighted_risk * control_multiplier
    return round(min(100.0, max(0.0, ers)), 2)


def generate_risk_explanation(
    finding: VulnerabilityFinding,
    asset: Asset,
    ers: float,
    aegis_decision: AegisDecision,
    risk_tier: RiskTier,
    decision: RemediationDecision,
    base_score: float,
    threat_score: float,
    env_score: float,
    weighted_risk: float,
    control_multiplier: float,
    control_adjustments: Sequence[ControlAdjustment],
    threat: Optional[ThreatEvidence],
) -> str:
    """Generate a deterministic, factual explanation of the assigned risk rating.

    Explains why AegisPatch assigned this specific decision and risk tier by connecting
    base severity, threat signals, environmental context, and compensating controls.
    """
    parts = []

    # 1. Decision & Score Lead
    parts.append(
        f"Vulnerability {finding.cve_id} on {asset.hostname} evaluated with ERS {ers:.2f} "
        f"({aegis_decision.value} / {risk_tier.value})."
    )

    # 2. Base Severity
    parts.append(
        f"Base CVSS score {finding.cvss_score:.1f} ({finding.severity.value}) contributes {base_score * WEIGHT_BASE_CVSS:.1f} "
        f"points (scaled base score: {base_score:.1f})."
    )

    # 3. Threat Intelligence
    if threat is None:
        parts.append("External threat intelligence was absent; threat score defaults to 0.0.")
    elif threat.is_cisa_kev:
        parts.append("Confirmed active exploitation is listed in CISA KEV (threat score: 100.0).")
    else:
        epss_str = f"EPSS probability of {threat.epss_score:.1%}" if threat.epss_score is not None else "EPSS score unavailable"
        poc_str = "public exploit PoC verified" if threat.public_poc_available else "no public exploit PoC"
        parts.append(f"Threat intelligence indicates {epss_str} with {poc_str} (threat score: {threat_score:.1f}).")

    # 4. Environmental Asset Context
    parts.append(
        f"Target asset '{asset.hostname}' operates with {asset.criticality.value} criticality, {asset.network_exposure.value} exposure, "
        f"and {asset.data_sensitivity.value} data sensitivity (environmental score: {env_score:.1f})."
    )

    # 5. Compensating Controls
    if control_adjustments:
        control_names = ", ".join(adj.name for adj in control_adjustments)
        parts.append(
            f"Active compensating controls ({control_names}) apply multiplier {control_multiplier:.2f}, "
            f"reducing unmitigated risk {weighted_risk:.1f} to final ERS {ers:.1f}."
        )
    else:
        parts.append(
            f"No active compensating controls were applied; unmitigated risk {weighted_risk:.1f} remained at multiplier 1.00."
        )

    # 6. Recommended Action
    parts.append(f"Recommended triage decision: {decision.value}. {DECISION_MEANINGS[aegis_decision]}")

    return " ".join(parts)


def build_supporting_evidence(
    finding: VulnerabilityFinding,
    asset: Asset,
    threat: Optional[ThreatEvidence],
    threat_details: Dict[str, Any],
    base_score: float,
    threat_score: float,
    env_score: float,
    weighted_risk: float,
    control_multiplier: float,
    control_adjustments: Sequence[ControlAdjustment],
    final_ers: float,
    aegis_decision: AegisDecision,
) -> List[str]:
    """Construct a verifiable factual evidence list backing the risk assessment."""
    evidence = [
        f"Base CVSS score {finding.cvss_score:.1f} ({finding.severity.value}) scaled to base score {base_score:.1f} (weight: {WEIGHT_BASE_CVSS * 100:.0f}%)",
    ]

    # Threat evidence
    if threat is None:
        evidence.append("Threat intelligence: Absent (defaults to 0.0 threat score)")
    elif threat.is_cisa_kev:
        evidence.append("Confirmed active exploitation listing in CISA KEV catalog (threat score: 100.0)")
    else:
        if threat.epss_score is not None:
            evidence.append(f"Threat intelligence: EPSS exploit probability {threat.epss_score:.4f} (contribution: {threat_details['epss_contribution']:.1f})")
        else:
            evidence.append("Threat intelligence: EPSS exploit probability unavailable / unindexed")

        if threat.public_poc_available:
            evidence.append(f"Threat intelligence: Verified public exploit proof-of-concept available (contribution: {threat_details['poc_contribution']:.1f})")
        else:
            evidence.append("Threat intelligence: No public exploit proof-of-concept identified")

    # Environmental evidence
    evidence.extend([
        f"Asset criticality: {asset.criticality.value} ({CRITICALITY_SCORES.get(asset.criticality, 50.0):.1f}/100, weight: {WEIGHT_ENV_CRITICALITY * 100:.0f}%)",
        f"Network exposure: {asset.network_exposure.value} ({EXPOSURE_SCORES.get(asset.network_exposure, 40.0):.1f}/100, weight: {WEIGHT_ENV_EXPOSURE * 100:.0f}%)",
        f"Data sensitivity: {asset.data_sensitivity.value} ({SENSITIVITY_SCORES.get(asset.data_sensitivity, 40.0):.1f}/100, weight: {WEIGHT_ENV_SENSITIVITY * 100:.0f}%)",
    ])

    # Compensating control evidence
    if control_adjustments:
        for adj in control_adjustments:
            evidence.append(f"Compensating control applied: {adj.name} (adjustment: {adj.adjustment_factor:+.2f})")
        evidence.append(f"Compensating control multiplier applied: {control_multiplier:.2f} (effective range: [{CONTROL_MULTIPLIER_MIN:.2f}, {CONTROL_MULTIPLIER_MAX:.2f}])")
    else:
        evidence.append("Compensating control multiplier: 1.00 (no active compensating controls)")

    # Composite scores and decision
    evidence.extend([
        f"Unmitigated composite risk score: {weighted_risk:.2f}/100",
        f"Final Environmental Risk Score (ERS): {final_ers:.2f}/100",
        f"AegisPatch decision band: {aegis_decision.value} ({DECISION_MEANINGS[aegis_decision]})",
    ])

    return evidence


def evaluate_risk(
    finding: VulnerabilityFinding,
    asset: Asset,
    threat: Optional[ThreatEvidence] = None,
    policy_citations: Optional[List[PolicyCitation]] = None,
    assessment_id: Optional[str] = None,
    assessed_at: Optional[datetime] = None,
) -> RiskAssessment:
    """End-to-end evaluation computing a validated Phase 1 RiskAssessment record.

    Pure deterministic processing linking VulnerabilityFinding, Asset, and ThreatEvidence.
    """
    if finding is None:
        raise ValueError("Vulnerability finding cannot be None.")
    if asset is None:
        raise ValueError("Asset cannot be None.")

    # Cross-entity integrity check
    if finding.asset_id and asset.asset_id and finding.asset_id != asset.asset_id:
        raise ValueError(
            f"Asset ID mismatch: finding '{finding.finding_id}' specifies asset '{finding.asset_id}', "
            f"which does not match target asset '{asset.asset_id}'."
        )

    evaluation_time = assessed_at or datetime.now(timezone.utc)

    # 1. Base Score B
    base_score = calculate_base_score(finding.cvss_score)
    cvss_contrib = round(WEIGHT_BASE_CVSS * base_score, 4)

    # 2. Threat Score T
    threat_score, threat_details = calculate_threat_score(threat)

    # 3. Environmental Score E
    env_score, env_details = calculate_environmental_score(asset)

    # 4. Composite Unmitigated Risk R
    weighted_risk = calculate_weighted_risk(base_score, threat_score, env_score)

    # 5. Compensating Control Multiplier M_control
    control_multiplier, control_adjustments = calculate_control_multiplier(asset.compensating_controls)

    # 6. Final Environmental Risk Score ERS
    final_ers = calculate_ers(weighted_risk, control_multiplier)

    # 7. Classification and Decision via Centralized Decision Mapping
    has_controls = len(control_adjustments) > 0
    decision_details = get_decision_details(final_ers, has_compensating_controls=has_controls)
    risk_tier = decision_details.risk_tier
    decision = decision_details.remediation_decision
    aegis_decision = decision_details.decision

    # 8. Build Supporting Evidence
    evidence_items = build_supporting_evidence(
        finding=finding,
        asset=asset,
        threat=threat,
        threat_details=threat_details,
        base_score=base_score,
        threat_score=threat_score,
        env_score=env_score,
        weighted_risk=weighted_risk,
        control_multiplier=control_multiplier,
        control_adjustments=control_adjustments,
        final_ers=final_ers,
        aegis_decision=aegis_decision,
    )

    # 9. Build Deterministic Explanation
    explanation = generate_risk_explanation(
        finding=finding,
        asset=asset,
        ers=final_ers,
        aegis_decision=aegis_decision,
        risk_tier=risk_tier,
        decision=decision,
        base_score=base_score,
        threat_score=threat_score,
        env_score=env_score,
        weighted_risk=weighted_risk,
        control_multiplier=control_multiplier,
        control_adjustments=control_adjustments,
        threat=threat,
    )

    # 10. Build AssetContext
    asset_ctx = AssetContext(
        context_id=f"CTX-{finding.finding_id}",
        asset_id=asset.asset_id,
        finding_id=finding.finding_id,
        criticality=asset.criticality,
        network_exposure=asset.network_exposure,
        data_sensitivity=asset.data_sensitivity,
        business_tier=asset.business_tier,
        environment=asset.environment,
        applicable_controls=asset.compensating_controls,
        policy_citations=policy_citations or [],
        context_summary=f"Asset {asset.hostname} in {asset.environment.value} with {asset.network_exposure.value} exposure.",
    )

    # Effective ThreatEvidence object
    effective_threat = threat or ThreatEvidence(
        evidence_id=f"THREAT-DEFAULT-{finding.cve_id}",
        cve_id=finding.cve_id,
        is_cisa_kev=False,
        epss_score=None,
        public_poc_available=False,
        threat_source="UNINDEXED_DEFAULT",
        retrieved_at=evaluation_time,
    )

    return RiskAssessment(
        assessment_id=assessment_id or f"RSK-{finding.finding_id}",
        finding_id=finding.finding_id,
        cve_id=finding.cve_id,
        asset_id=asset.asset_id,
        cvss_score=finding.cvss_score,
        cvss_contribution=cvss_contrib,
        threat_evidence=effective_threat,
        environmental_context=asset_ctx,
        control_adjustments=control_adjustments,
        environmental_risk_score=final_ers,
        risk_tier=risk_tier,
        decision=decision,
        explanation=explanation,
        supporting_evidence=evidence_items,
        calculation_metadata={
            "engine": "aegis_ers_deterministic_v1",
            "base_score": str(base_score),
            "cvss_score": str(finding.cvss_score),
            "threat_score": str(threat_score),
            "environmental_score": str(env_score),
            "unmitigated_risk": str(weighted_risk),
            "weighted_risk": str(weighted_risk),
            "control_multiplier": str(control_multiplier),
            "final_ers": str(final_ers),
            "aegis_decision": aegis_decision.value,
            "risk_tier": risk_tier.value,
            "remediation_decision": decision.value,
            "epss_available": "true" if (threat and threat.epss_score is not None) else "false",
            "epss_score": str(threat.epss_score) if (threat and threat.epss_score is not None) else "none",
            "is_cisa_kev": "true" if (threat and threat.is_cisa_kev) else "false",
            "public_poc_available": "true" if (threat and threat.public_poc_available) else "false",
            "active_controls_count": str(len(control_adjustments)),
        },
        assessed_at=evaluation_time,
    )
