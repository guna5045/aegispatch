"""Dashboard aggregation and transformation service for Aegis Patch.

Implements immutable data processing for executive KPIs, decision distributions,
severity distributions, ERS score bands, asset risk aggregation, and multi-criteria filtering.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding


def filter_findings(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
    severity: Optional[str] = None,
    decision: Optional[str] = None,
    environment: Optional[str] = None,
    criticality: Optional[str] = None,
) -> List[str]:
    """Filter finding IDs by severity, Aegis decision, asset environment, and criticality.

    Operates immutably, returning a new list of finding IDs matching all criteria.
    Treats 'ALL' or None as no filter for that respective dimension.

    Args:
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.
        severity: Optional vulnerability severity (e.g., 'CRITICAL', 'HIGH').
        decision: Optional Aegis decision (e.g., 'ACT', 'ATTEND').
        environment: Optional asset environment (e.g., 'PRODUCTION', 'STAGING').
        criticality: Optional asset criticality (e.g., 'CRITICAL', 'HIGH').

    Returns:
        List of matching finding IDs.
    """
    sev_filter = severity.upper() if severity and severity.upper() != "ALL" else None
    dec_filter = decision.upper() if decision and decision.upper() != "ALL" else None
    env_filter = environment.upper() if environment and environment.upper() != "ALL" else None
    crit_filter = criticality.upper() if criticality and criticality.upper() != "ALL" else None

    matched_ids: List[str] = []

    for fid, finding in findings.items():
        assessment = assessments.get(fid)
        asset = assets.get(finding.asset_id)

        # 1. Severity filter
        if sev_filter and finding.severity.value.upper() != sev_filter:
            continue

        # 2. Decision filter
        if dec_filter:
            if not assessment:
                continue
            aegis_decision = assessment.calculation_metadata.get(
                "aegis_decision",
                assessment.decision.value,
            ).upper()
            if aegis_decision != dec_filter:
                continue

        # 3. Environment filter
        if env_filter:
            if not asset or asset.environment.value.upper() != env_filter:
                continue

        # 4. Criticality filter
        if crit_filter:
            if not asset or asset.criticality.value.upper() != crit_filter:
                continue

        matched_ids.append(fid)

    return matched_ids


def compute_dashboard_kpis(
    finding_ids: Sequence[str],
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Compute executive-level security KPIs for the current set of findings.

    Args:
        finding_ids: Sequence of finding IDs in scope.
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        Dictionary of computed KPI values:
        - findings_analyzed: int
        - assets_affected: int
        - critical_severity_count: int
        - priority_findings_count: int (ACT + ATTEND)
        - average_ers: float
    """
    total_findings = len(finding_ids)
    if total_findings == 0:
        return {
            "findings_analyzed": 0,
            "assets_affected": 0,
            "critical_severity_count": 0,
            "priority_findings_count": 0,
            "average_ers": 0.0,
        }

    affected_assets = set()
    critical_count = 0
    priority_count = 0
    ers_sum = 0.0

    for fid in finding_ids:
        finding = findings[fid]
        assessment = assessments.get(fid)

        affected_assets.add(finding.asset_id)

        if finding.severity.value.upper() == "CRITICAL":
            critical_count += 1

        if assessment:
            ers = assessment.environmental_risk_score
            ers_sum += ers
            aegis_decision = assessment.calculation_metadata.get(
                "aegis_decision",
                assessment.decision.value,
            ).upper()
            if aegis_decision in ("ACT", "ATTEND"):
                priority_count += 1

    avg_ers = round(ers_sum / total_findings, 1)

    return {
        "findings_analyzed": total_findings,
        "assets_affected": len(affected_assets),
        "critical_severity_count": critical_count,
        "priority_findings_count": priority_count,
        "average_ers": avg_ers,
    }


def compute_decision_distribution(
    finding_ids: Sequence[str],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, int]:
    """Calculate the distribution of findings across Aegis Patch decision bands.

    Categories: ACT, ATTEND, PLAN, TRACK.

    Args:
        finding_ids: Sequence of finding IDs in scope.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        Dictionary mapping decision band name -> count of findings.
    """
    distribution: Dict[str, int] = {
        "ACT": 0,
        "ATTEND": 0,
        "PLAN": 0,
        "TRACK": 0,
    }

    for fid in finding_ids:
        assessment = assessments.get(fid)
        if assessment:
            decision = assessment.calculation_metadata.get(
                "aegis_decision",
                assessment.decision.value,
            ).upper()
            if decision in distribution:
                distribution[decision] += 1
            else:
                distribution[decision] = distribution.get(decision, 0) + 1

    return distribution


def compute_severity_distribution(
    finding_ids: Sequence[str],
    findings: Dict[str, VulnerabilityFinding],
) -> Dict[str, int]:
    """Calculate the distribution of findings by intrinsic vulnerability severity.

    Categories: CRITICAL, HIGH, MEDIUM, LOW.

    Args:
        finding_ids: Sequence of finding IDs in scope.
        findings: Map of finding_id -> VulnerabilityFinding.

    Returns:
        Dictionary mapping severity level -> count of findings.
    """
    distribution: Dict[str, int] = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for fid in finding_ids:
        finding = findings.get(fid)
        if finding:
            sev = finding.severity.value.upper()
            if sev in distribution:
                distribution[sev] += 1
            else:
                distribution[sev] = distribution.get(sev, 0) + 1

    return distribution


def compute_ers_distribution(
    finding_ids: Sequence[str],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, int]:
    """Calculate the distribution of findings across Aegis Patch benchmark ERS score bands.

    Bands:
    - ACT (85.0–100.0)
    - ATTEND (65.0–84.9)
    - PLAN (40.0–64.9)
    - TRACK (0.0–39.9)

    Args:
        finding_ids: Sequence of finding IDs in scope.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        Dictionary mapping score band name -> count of findings.
    """
    distribution: Dict[str, int] = {
        "ACT (85–100)": 0,
        "ATTEND (65–<85)": 0,
        "PLAN (40–<65)": 0,
        "TRACK (0–<40)": 0,
    }

    for fid in finding_ids:
        assessment = assessments.get(fid)
        if assessment:
            ers = assessment.environmental_risk_score
            if ers >= 85.0:
                distribution["ACT (85–100)"] += 1
            elif ers >= 65.0:
                distribution["ATTEND (65–<85)"] += 1
            elif ers >= 40.0:
                distribution["PLAN (40–<65)"] += 1
            else:
                distribution["TRACK (0–<40)"] += 1

    return distribution


def aggregate_assets_by_risk(
    finding_ids: Sequence[str],
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> List[Dict[str, Any]]:
    """Aggregate findings by asset and rank assets by maximum Environmental Risk Score (ERS).

    Secondary sort keys: number of ACT findings descending, then asset_id ascending.

    Args:
        finding_ids: Sequence of finding IDs in scope.
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        List of aggregated asset records sorted descending by risk.
    """
    asset_groups: Dict[str, List[str]] = {}
    for fid in finding_ids:
        finding = findings[fid]
        aid = finding.asset_id
        if aid not in asset_groups:
            asset_groups[aid] = []
        asset_groups[aid].append(fid)

    aggregated: List[Dict[str, Any]] = []

    for aid, fids in asset_groups.items():
        asset = assets.get(aid)
        hostname = asset.hostname if asset else "Unknown"
        env = asset.environment.value if asset else "Unknown"
        crit = asset.criticality.value if asset else "Unknown"

        highest_ers = 0.0
        act_count = 0
        attend_count = 0
        plan_count = 0
        track_count = 0

        for fid in fids:
            assessment = assessments.get(fid)
            if assessment:
                ers = assessment.environmental_risk_score
                if ers > highest_ers:
                    highest_ers = ers

                dec = assessment.calculation_metadata.get(
                    "aegis_decision",
                    assessment.decision.value,
                ).upper()
                if dec == "ACT":
                    act_count += 1
                elif dec == "ATTEND":
                    attend_count += 1
                elif dec == "PLAN":
                    plan_count += 1
                elif dec == "TRACK":
                    track_count += 1

        aggregated.append(
            {
                "asset_id": aid,
                "hostname": hostname,
                "environment": env,
                "criticality": crit,
                "findings_count": len(fids),
                "highest_ers": round(highest_ers, 2),
                "act_count": act_count,
                "attend_count": attend_count,
                "plan_count": plan_count,
                "track_count": track_count,
            }
        )

    # Deterministic sort: highest_ers desc, act_count desc, asset_id asc
    aggregated.sort(
        key=lambda item: (-item["highest_ers"], -item["act_count"], item["asset_id"])
    )

    return aggregated


def get_priority_preview(
    finding_ids: Sequence[str],
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Retrieve top N findings in scope ranked by Environmental Risk Score (ERS) descending.

    Secondary sort keys: CVSS score descending, then finding_id ascending.

    Args:
        finding_ids: Sequence of finding IDs in scope.
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.
        limit: Maximum number of preview findings (default 5).

    Returns:
        List of priority finding records with formatting ready for display.
    """
    sorted_ids = sorted(
        finding_ids,
        key=lambda fid: (
            -assessments[fid].environmental_risk_score if fid in assessments else 0.0,
            -findings[fid].cvss_score if fid in findings else 0.0,
            fid,
        ),
    )

    preview_items: List[Dict[str, Any]] = []
    for fid in sorted_ids[:limit]:
        finding = findings[fid]
        assessment = assessments.get(fid)
        asset = assets.get(finding.asset_id)

        hostname = asset.hostname if asset else "Unknown"
        ers = round(assessment.environmental_risk_score, 2) if assessment else 0.0
        dec = (
            assessment.calculation_metadata.get(
                "aegis_decision",
                assessment.decision.value,
            )
            if assessment
            else "UNKNOWN"
        )
        tier = assessment.risk_tier.value if assessment else "UNKNOWN"

        preview_items.append(
            {
                "finding_id": finding.finding_id,
                "cve_id": finding.cve_id,
                "title": finding.title,
                "asset_id": finding.asset_id,
                "hostname": hostname,
                "severity": finding.severity.value,
                "cvss_score": round(finding.cvss_score, 1),
                "environmental_risk_score": ers,
                "aegis_decision": dec,
                "risk_tier": tier,
            }
        )

    return preview_items
