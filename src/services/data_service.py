"""Data loading and risk evaluation service for Aegis Patch.

Integrates the Phase 2 benchmark datasets with the Phase 3 deterministic risk engine.
Provides validated schemas, risk assessments, top-ranked findings, and asset context.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.risk_engine import evaluate_risk

# Default dataset locations relative to repository root
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "synthetic"
DEFAULT_CMDB_PATH = DEFAULT_DATA_DIR / "enterprise_cmdb.json"
DEFAULT_SCANS_PATH = DEFAULT_DATA_DIR / "benchmark_60_scans.json"


def load_cmdb_assets(
    cmdb_path: Optional[Union[str, Path]] = None,
) -> Dict[str, Asset]:
    """Load and validate enterprise CMDB assets from JSON.

    Args:
        cmdb_path: Path to CMDB JSON file. Defaults to data/synthetic/enterprise_cmdb.json.

    Returns:
        Dict mapping asset_id -> Asset Pydantic model.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If file content is invalid JSON or violates Asset schema.
    """
    path = Path(cmdb_path) if cmdb_path else DEFAULT_CMDB_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Enterprise CMDB file not found at: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(f"Malformed JSON in CMDB file '{path}': {err}") from err

    if not isinstance(raw_data, list):
        raise ValueError(f"CMDB data must be a list of asset records, got {type(raw_data).__name__}")

    assets: Dict[str, Asset] = {}
    for idx, item in enumerate(raw_data):
        try:
            asset = Asset(**item)
            assets[asset.asset_id] = asset
        except Exception as err:
            raise ValueError(f"Asset validation error at index {idx} in '{path}': {err}") from err

    return assets


def load_benchmark_findings(
    scans_path: Optional[Union[str, Path]] = None,
) -> Dict[str, VulnerabilityFinding]:
    """Load and validate benchmark vulnerability findings from JSON.

    Args:
        scans_path: Path to scans JSON file. Defaults to data/synthetic/benchmark_60_scans.json.

    Returns:
        Dict mapping finding_id -> VulnerabilityFinding Pydantic model.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If file content is invalid JSON or violates VulnerabilityFinding schema.
    """
    path = Path(scans_path) if scans_path else DEFAULT_SCANS_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark scans file not found at: {path}")

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw_data = json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(f"Malformed JSON in benchmark scans file '{path}': {err}") from err

    if not isinstance(raw_data, list):
        raise ValueError(f"Benchmark scans data must be a list of finding records, got {type(raw_data).__name__}")

    findings: Dict[str, VulnerabilityFinding] = {}
    for idx, item in enumerate(raw_data):
        try:
            finding = VulnerabilityFinding(**item)
            findings[finding.finding_id] = finding
        except Exception as err:
            raise ValueError(f"Vulnerability finding validation error at index {idx} in '{path}': {err}") from err

    return findings


def evaluate_benchmark_risks(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
) -> Dict[str, RiskAssessment]:
    """Evaluate deterministic risk for all findings against their associated assets.

    Calls the Phase 3 evaluate_risk engine without fabricating threat intelligence.

    Args:
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.

    Returns:
        Dict mapping finding_id -> RiskAssessment.

    Raises:
        ValueError: If an asset associated with a finding is not found.
    """
    assessments: Dict[str, RiskAssessment] = {}

    for finding_id, finding in findings.items():
        asset = assets.get(finding.asset_id)
        if asset is None:
            raise ValueError(
                f"Finding '{finding_id}' references unknown asset '{finding.asset_id}' not present in CMDB."
            )

        # Evaluate risk deterministically using Phase 3 engine
        assessment = evaluate_risk(finding, asset, threat=None)
        assessments[finding_id] = assessment

    return assessments


def get_top_findings(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
    limit: int = 5,
) -> List[Dict[str, Any]]:
    """Retrieve the top N findings sorted descending by Environmental Risk Score (ERS).

    Args:
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.
        limit: Number of top findings to return (default 5).

    Returns:
        List of dictionaries with summary attributes formatted for display.
    """
    # Sort finding IDs by assessment ERS descending
    sorted_ids = sorted(
        assessments.keys(),
        key=lambda fid: assessments[fid].environmental_risk_score,
        reverse=True,
    )

    top_records: List[Dict[str, Any]] = []
    for fid in sorted_ids[:limit]:
        finding = findings[fid]
        assessment = assessments[fid]
        asset = assets.get(finding.asset_id)
        hostname = asset.hostname if asset else "Unknown"

        aegis_decision = assessment.calculation_metadata.get(
            "aegis_decision",
            assessment.decision.value,
        )

        top_records.append(
            {
                "finding_id": finding.finding_id,
                "cve_id": finding.cve_id,
                "title": finding.title,
                "asset_id": finding.asset_id,
                "hostname": hostname,
                "cvss_score": round(finding.cvss_score, 1),
                "environmental_risk_score": round(assessment.environmental_risk_score, 2),
                "aegis_decision": aegis_decision,
                "risk_tier": assessment.risk_tier.value,
            }
        )

    return top_records


def get_finding_context(
    finding_id: str,
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Optional[Dict[str, Any]]:
    """Resolve full contextual information for a given finding, asset, and assessment.

    Args:
        finding_id: Identifier of the finding (e.g., 'FINDING-001').
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        Structured dictionary with finding, asset, and risk details, or None if finding_id not found.
    """
    finding = findings.get(finding_id)
    if not finding:
        return None

    assessment = assessments.get(finding_id)
    asset = assets.get(finding.asset_id)

    controls_summary = []
    if asset and asset.compensating_controls:
        for ctrl in asset.compensating_controls:
            controls_summary.append(
                {
                    "control_id": ctrl.control_id,
                    "name": ctrl.name,
                    "status": ctrl.status.value,
                    "description": ctrl.description,
                }
            )

    meta = assessment.calculation_metadata if assessment else {}
    aegis_decision = meta.get(
        "aegis_decision",
        assessment.decision.value if assessment else "UNKNOWN",
    )

    return {
        "finding": {
            "finding_id": finding.finding_id,
            "cve_id": finding.cve_id,
            "title": finding.title,
            "description": finding.description,
            "cvss_score": round(finding.cvss_score, 1),
            "severity": finding.severity.value,
            "affected_package": finding.affected_package,
            "installed_version": finding.installed_version,
            "fixed_version": finding.fixed_version,
            "asset_id": finding.asset_id,
        },
        "asset": {
            "asset_id": asset.asset_id if asset else finding.asset_id,
            "hostname": asset.hostname if asset else "Unknown",
            "asset_type": asset.asset_type.value if asset else "Unknown",
            "business_tier": asset.business_tier.value if asset else "Unknown",
            "criticality": asset.criticality.value if asset else "Unknown",
            "network_exposure": asset.network_exposure.value if asset else "Unknown",
            "data_sensitivity": asset.data_sensitivity.value if asset else "Unknown",
            "environment": asset.environment.value if asset else "Unknown",
            "compensating_controls": controls_summary,
        }
        if asset
        else None,
        "assessment": {
            "environmental_risk_score": round(assessment.environmental_risk_score, 2)
            if assessment
            else 0.0,
            "risk_tier": assessment.risk_tier.value if assessment else "UNKNOWN",
            "aegis_decision": aegis_decision,
            "remediation_decision": assessment.decision.value
            if assessment
            else "UNKNOWN",
            "base_score": meta.get("base_score", 0.0),
            "threat_score": meta.get("threat_score", 0.0),
            "environmental_score": meta.get("environmental_score", 0.0),
            "control_multiplier": meta.get("control_multiplier", 1.0),
        }
        if assessment
        else None,
    }
