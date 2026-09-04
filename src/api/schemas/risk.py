"""Contextual risk assessment API schemas."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RiskAssessmentRead(BaseModel):
    """Auditable contextual risk evaluation result and mathematical components."""

    model_config = ConfigDict(from_attributes=True)

    assessment_id: str = Field(..., description="Unique assessment record identifier")
    finding_id: str = Field(..., description="Evaluated vulnerability finding identifier")
    cve_id: str = Field(..., description="Associated CVE identifier")
    asset_id: str = Field(..., description="Target asset identifier")

    # Mathematical components: B, T, E, R, M_control, ERS
    base_score: float = Field(..., description="Base vulnerability score B (CVSS scaled to 0-10)")
    threat_score: float = Field(..., description="Threat telemetry score T (0-10)")
    environmental_score: float = Field(..., description="Asset environmental score E (0-10)")
    raw_risk_score: float = Field(..., description="Composite unmitigated risk score R (0-100)")
    control_multiplier: float = Field(..., description="Compensating control mitigation multiplier M_control (0.0 - 1.0)")
    environmental_risk_score: float = Field(..., description="Final Environmental Risk Score ERS (0-100)")

    # Decisions and classifications
    risk_tier: str = Field(..., description="Environmental risk tier (CRITICAL, HIGH, MEDIUM, LOW)")
    decision: str = Field(..., description="Aegis triage decision (ACT, ATTEND, PLAN, TRACK)")
    remediation_decision: Optional[str] = Field(None, description="Operational triage recommendation")

    # Explanations and audit metadata
    explanation: str = Field(..., description="Deterministic human-readable risk explanation")
    supporting_evidence: Optional[List[str]] = Field(default_factory=list, description="Audit trace evidence list")
    calculation_metadata: Optional[Dict[str, Any]] = Field(None, description="Diagnostic engine evaluation variables")
    engine_version: str = Field(..., description="Deterministic risk engine version identifier")
    assessed_at: datetime = Field(..., description="Evaluation timestamp")
