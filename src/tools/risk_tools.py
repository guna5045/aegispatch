"""Deterministic contextual risk tools for Aegis Patch.

All tools in this module wrap and delegate directly to the authoritative
Phase 3 risk engine (`src.tools.risk_engine:evaluate_risk`) and decision mapping
(`src.tools.decision_mapping:get_decision_details`).
Zero formulas or thresholds are duplicated.
"""

from __future__ import annotations

from typing import Optional

from src.tools.decision_mapping import AegisDecision, get_decision_details, map_ers_to_decision
from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import (
    CalculateEnvironmentalRiskInput,
    CalculateEnvironmentalRiskOutput,
    MapSsvcDecisionInput,
    MapSsvcDecisionOutput,
    ProvenanceSourceType,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
)


def calculate_environmental_risk(
    input_data: CalculateEnvironmentalRiskInput,
) -> CalculateEnvironmentalRiskOutput:
    """Calculate contextual Environmental Risk Score (ERS) and triage decision.

    Delegates authoritatively to the existing Phase 3 risk engine.
    Does not duplicate the B/T/E/R/M/ERS mathematical formulas.
    """
    # Construct ThreatEvidence contract for Phase 3 engine
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    threat = ThreatEvidence(
        evidence_id=f"EV-{input_data.finding.cve_id}",
        cve_id=input_data.finding.cve_id,
        is_cisa_kev=input_data.is_cisa_kev,
        epss_score=input_data.epss_score,
        public_poc_available=input_data.public_poc_available,
        threat_source="threat_tools_intake",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )

    # Authoritative evaluation
    assessment = evaluate_risk(
        finding=input_data.finding,
        asset=input_data.asset,
        threat=threat,
    )

    meta = assessment.calculation_metadata
    b_score = float(meta.get("base_score", assessment.cvss_score * 10.0))
    t_score = float(meta.get("threat_score", 0.0))
    e_score = float(meta.get("environmental_score", 50.0))
    r_score = float(meta.get("weighted_risk", meta.get("unmitigated_risk", 50.0)))
    m_mult = float(meta.get("control_multiplier", 1.0))
    aegis_dec = AegisDecision(meta.get("aegis_decision", AegisDecision.TRACK.value))

    return CalculateEnvironmentalRiskOutput(
        tool_name="calculate_environmental_risk",
        status=ToolStatus.SUCCESS,
        message=f"Evaluated environmental risk: ERS {assessment.environmental_risk_score:.2f} ({aegis_dec.value})",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="aegis_contextual_risk_engine_v1",
            source_type=ProvenanceSourceType.CALCULATED,
            dataset_version="Phase 3 Authoritative",
            reference="src/tools/risk_engine.py",
        ),
        assessment_id=assessment.assessment_id,
        finding_id=assessment.finding_id,
        cve_id=assessment.cve_id,
        asset_id=assessment.asset_id,
        base_score=b_score,
        threat_score=t_score,
        environmental_score=e_score,
        raw_risk_score=r_score,
        control_multiplier=m_mult,
        environmental_risk_score=assessment.environmental_risk_score,
        risk_tier=assessment.risk_tier,
        decision=aegis_dec,
        remediation_decision=assessment.decision,
        explanation=assessment.explanation,
        supporting_evidence=assessment.supporting_evidence,
        engine_version="aegis_ers_deterministic_v1",
    )


def map_ssvc_decision(
    input_data: MapSsvcDecisionInput,
) -> MapSsvcDecisionOutput:
    """Map an Environmental Risk Score (0-100) to an Aegis triage decision band.

    Delegates directly to the authoritative Phase 3 decision mapping.
    Decision bands:
      85 - 100 -> ACT
      65 - 84  -> ATTEND
      40 - 64  -> PLAN
      0  - 39  -> TRACK
    Note: Transparent Aegis Patch decision bands inspired by SSVC concepts.
    """
    details = get_decision_details(
        ers=input_data.ers_score,
        has_compensating_controls=input_data.has_compensating_controls,
    )

    return MapSsvcDecisionOutput(
        tool_name="map_ssvc_decision",
        status=ToolStatus.SUCCESS,
        message=f"Mapped ERS {input_data.ers_score:.2f} to decision {details.decision.value}.",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="aegis_decision_mapping_v1",
            source_type=ProvenanceSourceType.CALCULATED,
            reference="src/tools/decision_mapping.py",
        ),
        ers_score=input_data.ers_score,
        decision=details.decision,
        risk_tier=details.risk_tier,
        remediation_decision=details.remediation_decision,
        meaning=details.meaning,
    )
