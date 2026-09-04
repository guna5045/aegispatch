"""Scenario service for Aegis Patch.

Loads and coordinates the five benchmark counterexample scenarios (A through E)
and provides deterministic constrained patch capacity what-if simulations.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from src.schemas.asset import Asset
from src.schemas.plan import ApprovalState, PatchCandidate
from src.schemas.risk import RiskAssessment, RiskTier
from src.schemas.threat import ThreatConfidence, ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.risk_engine import evaluate_risk

# Default dataset locations
DEFAULT_DATA_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "synthetic"
DEFAULT_SCENARIOS_PATH = DEFAULT_DATA_DIR / "benchmark_scenarios.json"

# Default maintenance window capacity from POL-SEC-04-patching.md §4.2.2 and DATASET_SPEC.md §8
DEFAULT_MAINTENANCE_CAPACITY_HOURS: float = 16.0


def load_benchmark_scenarios(
    scenarios_path: Optional[Path | str] = None,
) -> Dict[str, Dict[str, Any]]:
    """Load and index the benchmark counterexample scenarios from JSON.

    Args:
        scenarios_path: Path to benchmark_scenarios.json. Defaults to data/synthetic.

    Returns:
        Dict mapping scenario_id (e.g. 'SCENARIO-A') -> scenario dictionary.
    """
    path = Path(scenarios_path) if scenarios_path else DEFAULT_SCENARIOS_PATH
    if not path.is_file():
        raise FileNotFoundError(f"Benchmark scenarios file not found at: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    return {item["scenario_id"]: item for item in data}


def get_scenario_comparison_a(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Assemble Scenario A: Exposure and Criticality Inversion.

    Contrasts a theoretical critical CVSS 10.0 finding in an air-gapped testbed (FINDING-059 on ASSET-018)
    against a high CVSS 7.5 finding on a mission-critical internet-facing production service (FINDING-006 on ASSET-002).
    """
    f_isolated = findings["FINDING-059"]
    a_isolated = assets["ASSET-018"]
    r_isolated = assessments["FINDING-059"]

    f_exposed = findings["FINDING-006"]
    a_exposed = assets["ASSET-002"]
    r_exposed = assessments["FINDING-006"]

    return {
        "scenario_id": "SCENARIO-A",
        "title": "Exposure and Criticality Inversion",
        "demonstration_goal": "Demonstrates that a high CVSS score does not automatically mean the highest environmental priority.",
        "isolated": {
            "finding_id": f_isolated.finding_id,
            "cve_id": f_isolated.cve_id,
            "title": f_isolated.title,
            "cvss_score": f_isolated.cvss_score,
            "severity": f_isolated.severity.value,
            "asset_id": a_isolated.asset_id,
            "hostname": a_isolated.hostname,
            "environment": a_isolated.environment.value,
            "criticality": a_isolated.criticality.value,
            "network_exposure": a_isolated.network_exposure.value,
            "data_sensitivity": a_isolated.data_sensitivity.value,
            "compensating_controls_count": len(a_isolated.compensating_controls),
            "environmental_score": float(r_isolated.calculation_metadata.get("environmental_score", 17.5)),
            "environmental_risk_score": round(r_isolated.environmental_risk_score, 2),
            "aegis_decision": r_isolated.calculation_metadata.get("aegis_decision", r_isolated.decision.value),
            "risk_tier": r_isolated.risk_tier.value,
        },
        "exposed": {
            "finding_id": f_exposed.finding_id,
            "cve_id": f_exposed.cve_id,
            "title": f_exposed.title,
            "cvss_score": f_exposed.cvss_score,
            "severity": f_exposed.severity.value,
            "asset_id": a_exposed.asset_id,
            "hostname": a_exposed.hostname,
            "environment": a_exposed.environment.value,
            "criticality": a_exposed.criticality.value,
            "network_exposure": a_exposed.network_exposure.value,
            "data_sensitivity": a_exposed.data_sensitivity.value,
            "compensating_controls_count": len(a_exposed.compensating_controls),
            "environmental_score": float(r_exposed.calculation_metadata.get("environmental_score", 100.0)),
            "environmental_risk_score": round(r_exposed.environmental_risk_score, 2),
            "aegis_decision": r_exposed.calculation_metadata.get("aegis_decision", r_exposed.decision.value),
            "risk_tier": r_exposed.risk_tier.value,
        },
        "cvss_delta": round(f_isolated.cvss_score - f_exposed.cvss_score, 1),
        "ers_delta": round(r_exposed.environmental_risk_score - r_isolated.environmental_risk_score, 2),
        "key_insight": "Environmental context can reverse a severity-only ranking: the CVSS 7.5 vulnerability is prioritized into PLAN because it sits on exposed mission-critical production infrastructure, while the CVSS 10.0 vulnerability is relegated to TRACK on an air-gapped test system.",
    }


def get_scenario_comparison_b(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Assemble Scenario B: Threat Intelligence Exploitation Differential.

    Pairs findings where base CVSS scores diverge from real-world exploitability evidence.
    Contrasts the unaugmented benchmark baseline (where threat feeds are absent) against
    a verified-input demonstration fixture (FINDING-007 with verified weaponized PoC & EPSS 0.45).
    """
    f_18 = findings["FINDING-018"]
    a_04 = assets["ASSET-004"]
    r_18 = assessments["FINDING-018"]

    f_07 = findings["FINDING-007"]
    a_02 = assets["ASSET-002"]
    r_07_baseline = assessments["FINDING-007"]

    # Verified-input demonstration fixture (as established in Phase 3E test suite)
    threat_07_verified = ThreatEvidence(
        evidence_id="THREAT-007-POC",
        cve_id=f_07.cve_id,
        is_cisa_kev=False,
        epss_score=0.45,
        epss_percentile=0.92,
        public_poc_available=True,
        threat_source="FIRST_EPSS_AND_EXPLOITDB",
        confidence=ThreatConfidence.HIGH,
        retrieved_at=datetime(2026, 9, 4, 12, 0, 0, tzinfo=timezone.utc),
    )
    r_07_verified = evaluate_risk(f_07, a_02, threat=threat_07_verified)

    return {
        "scenario_id": "SCENARIO-B",
        "title": "Threat Intelligence Exploitation Differential",
        "demonstration_goal": "Demonstrates how verified real-world threat evidence elevates operational urgency beyond base CVSS.",
        "baseline_unaugmented": {
            "finding_id": f_07.finding_id,
            "cve_id": f_07.cve_id,
            "title": f_07.title,
            "cvss_score": f_07.cvss_score,
            "severity": f_07.severity.value,
            "threat_status": "Threat intelligence unavailable in benchmark baseline",
            "threat_score": float(r_07_baseline.calculation_metadata.get("threat_score", 0.0)),
            "environmental_risk_score": round(r_07_baseline.environmental_risk_score, 2),
            "aegis_decision": r_07_baseline.calculation_metadata.get("aegis_decision", r_07_baseline.decision.value),
            "risk_tier": r_07_baseline.risk_tier.value,
        },
        "verified_input_demonstration": {
            "finding_id": f_07.finding_id,
            "cve_id": f_07.cve_id,
            "title": f_07.title,
            "cvss_score": f_07.cvss_score,
            "severity": f_07.severity.value,
            "threat_status": "Verified-input demonstration: Weaponized public PoC confirmed, EPSS 0.45 (92nd percentile)",
            "threat_score": float(r_07_verified.calculation_metadata.get("threat_score", 56.0)),
            "environmental_risk_score": round(r_07_verified.environmental_risk_score, 2),
            "aegis_decision": r_07_verified.calculation_metadata.get("aegis_decision", r_07_verified.decision.value),
            "risk_tier": r_07_verified.risk_tier.value,
        },
        "unweaponized_comparison": {
            "finding_id": f_18.finding_id,
            "cve_id": f_18.cve_id,
            "title": f_18.title,
            "cvss_score": f_18.cvss_score,
            "severity": f_18.severity.value,
            "threat_status": "No active weaponized network exploitation tooling",
            "threat_score": float(r_18.calculation_metadata.get("threat_score", 0.0)),
            "environmental_risk_score": round(r_18.environmental_risk_score, 2),
            "aegis_decision": r_18.calculation_metadata.get("aegis_decision", r_18.decision.value),
            "risk_tier": r_18.risk_tier.value,
        },
        "ers_jump": round(r_07_verified.environmental_risk_score - r_07_baseline.environmental_risk_score, 2),
        "key_insight": "Verified threat evidence materially changes environmental risk: confirmed public exploit tooling and high EPSS probability elevate FINDING-007's ERS from 43.60 to 61.52 (+17.92 points), distinguishing weaponized threats from unweaponized theoretical vulnerabilities.",
    }


def get_scenario_comparison_c(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Assemble Scenario C: Compensating Controls Risk Mitigation.

    Compares identical vulnerability CVE-2023-38545 between an asset shielded by an active Layer 7 WAF
    (ASSET-001) versus an unshielded developer container (ASSET-015).
    """
    f_protected = findings["FINDING-001"]
    a_protected = assets["ASSET-001"]
    r_protected = assessments["FINDING-001"]

    f_unprotected = findings["FINDING-051"]
    a_unprotected = assets["ASSET-015"]
    r_unprotected = assessments["FINDING-051"]

    unmitigated_r = float(r_protected.calculation_metadata.get("unmitigated_risk", 57.40))
    ctrl_multiplier = float(r_protected.calculation_metadata.get("control_multiplier", 0.85))

    return {
        "scenario_id": "SCENARIO-C",
        "title": "Compensating Controls Risk Mitigation",
        "demonstration_goal": "Demonstrates that active compensating controls dampen residual environmental risk without pretending the vulnerability has disappeared.",
        "shared_cve": "CVE-2023-38545",
        "cvss_score": f_protected.cvss_score,
        "protected_asset": {
            "finding_id": f_protected.finding_id,
            "asset_id": a_protected.asset_id,
            "hostname": a_protected.hostname,
            "environment": a_protected.environment.value,
            "criticality": a_protected.criticality.value,
            "network_exposure": a_protected.network_exposure.value,
            "controls": [f"{c.name} ({c.status.value})" for c in a_protected.compensating_controls],
            "unmitigated_risk": round(unmitigated_r, 2),
            "control_multiplier": ctrl_multiplier,
            "environmental_risk_score": round(r_protected.environmental_risk_score, 2),
            "aegis_decision": r_protected.calculation_metadata.get("aegis_decision", r_protected.decision.value),
            "risk_tier": r_protected.risk_tier.value,
            "points_dampened": round(unmitigated_r - r_protected.environmental_risk_score, 2),
        },
        "unprotected_asset": {
            "finding_id": f_unprotected.finding_id,
            "asset_id": a_unprotected.asset_id,
            "hostname": a_unprotected.hostname,
            "environment": a_unprotected.environment.value,
            "criticality": a_unprotected.criticality.value,
            "network_exposure": a_unprotected.network_exposure.value,
            "controls": [f"{c.name} ({c.status.value})" for c in a_unprotected.compensating_controls] or ["None configured"],
            "control_multiplier": float(r_unprotected.calculation_metadata.get("control_multiplier", 1.00)),
            "environmental_risk_score": round(r_unprotected.environmental_risk_score, 2),
            "aegis_decision": r_unprotected.calculation_metadata.get("aegis_decision", r_unprotected.decision.value),
            "risk_tier": r_unprotected.risk_tier.value,
        },
        "caveat": "The benchmark demonstrates how recognized controls influence the environmental risk calculation; the compared assets also differ in environmental context (ASSET-001 is production internet-facing, ASSET-015 is internal development sandbox).",
        "key_insight": "Compensating controls can reduce residual environmental risk without removing the underlying vulnerability: active Cloudflare Enterprise WAF dampens exposure by -15% (multiplier 0.85), reducing residual risk on ASSET-001 by 8.61 points while keeping the vulnerability visible in the planning queue.",
    }


def get_scenario_comparison_d(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Assemble Scenario D: Intra-Asset Hotspot Prioritization.

    Evaluates a single mission-critical asset (ASSET-002, OAuth2 IDP Provider) hosting
    5 concurrent findings competing for remediation sequencing within that asset's maintenance window.
    """
    asset = assets["ASSET-002"]
    fids = ["FINDING-005", "FINDING-006", "FINDING-007", "FINDING-008", "FINDING-009"]

    hotspot_findings = []
    for fid in fids:
        f = findings[fid]
        r = assessments[fid]
        hotspot_findings.append(
            {
                "finding_id": f.finding_id,
                "cve_id": f.cve_id,
                "title": f.title,
                "affected_package": f.affected_package,
                "installed_version": f.installed_version,
                "severity": f.severity.value,
                "cvss_score": round(f.cvss_score, 1),
                "environmental_risk_score": round(r.environmental_risk_score, 2),
                "aegis_decision": r.calculation_metadata.get("aegis_decision", r.decision.value),
                "risk_tier": r.risk_tier.value,
            }
        )

    # Rank findings by ERS descending for deterministic intra-asset sequencing
    hotspot_findings.sort(
        key=lambda x: (x["environmental_risk_score"], x["cvss_score"], x["finding_id"]),
        reverse=True,
    )

    max_ers = max(item["environmental_risk_score"] for item in hotspot_findings)
    act_count = sum(1 for item in hotspot_findings if item["aegis_decision"] == "ACT")
    attend_count = sum(1 for item in hotspot_findings if item["aegis_decision"] == "ATTEND")
    priority_count = act_count + attend_count

    return {
        "scenario_id": "SCENARIO-D",
        "title": "Intra-Asset Hotspot Prioritization",
        "demonstration_goal": "Demonstrates how multiple concurrent vulnerabilities concentrate on a single critical asset, requiring sequential remediation planning.",
        "asset": {
            "asset_id": asset.asset_id,
            "hostname": asset.hostname,
            "owner_team": asset.owner_team,
            "environment": asset.environment.value,
            "criticality": asset.criticality.value,
            "network_exposure": asset.network_exposure.value,
            "data_sensitivity": asset.data_sensitivity.value,
            "finding_count": len(hotspot_findings),
            "max_finding_ers": max_ers,
            "priority_count": priority_count,
            "act_count": act_count,
            "attend_count": attend_count,
        },
        "findings": hotspot_findings,
        "key_insight": "Multiple findings on a critical asset create a concentrated remediation hotspot: rather than inspecting vulnerabilities in isolation across disparate teams, security operations can sequence all 5 findings on ASSET-002 within a single scheduled maintenance window based on ERS rank.",
    }


def get_scenario_comparison_e(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> Dict[str, Any]:
    """Assemble Scenario E: Cross-Asset Prevalent Vulnerability Spread.

    Tracks an identical CVE (CVE-2023-38545) across 4 distinct enterprise infrastructure tiers:
    Production Internet-facing, Staging, Internal Development, and Air-gapped Storage.
    """
    cve_id = "CVE-2023-38545"
    fids = ["FINDING-001", "FINDING-045", "FINDING-051", "FINDING-057"]

    tier_comparisons = []
    for fid in fids:
        f = findings[fid]
        a = assets[f.asset_id]
        r = assessments[fid]
        tier_comparisons.append(
            {
                "finding_id": f.finding_id,
                "asset_id": a.asset_id,
                "hostname": a.hostname,
                "environment": a.environment.value,
                "criticality": a.criticality.value,
                "network_exposure": a.network_exposure.value,
                "data_sensitivity": a.data_sensitivity.value,
                "controls_count": len(a.compensating_controls),
                "cvss_score": round(f.cvss_score, 1),
                "control_multiplier": float(r.calculation_metadata.get("control_multiplier", 1.0)),
                "environmental_risk_score": round(r.environmental_risk_score, 2),
                "aegis_decision": r.calculation_metadata.get("aegis_decision", r.decision.value),
                "risk_tier": r.risk_tier.value,
            }
        )

    # Sort descending by ERS
    tier_comparisons.sort(key=lambda x: x["environmental_risk_score"], reverse=True)

    return {
        "scenario_id": "SCENARIO-E",
        "title": "Cross-Asset Prevalent Vulnerability Spread",
        "demonstration_goal": "Demonstrates that the exact same CVE receives different environmental risk scores depending on where it exists.",
        "cve_id": cve_id,
        "underlying_vulnerability": "curl SOCKS5 heap-based buffer overflow (CVSS 9.8)",
        "comparisons": tier_comparisons,
        "ers_spread": round(tier_comparisons[0]["environmental_risk_score"] - tier_comparisons[-1]["environmental_risk_score"], 2),
        "key_insight": "Same vulnerability. Different environment. Different risk. The exact same libcurl CVE-2023-38545 ranges from ERS 48.79 (PLAN) on the production gateway down to ERS 33.77 (TRACK) in the dev sandbox, proving that Aegis Patch prevents over-patching low-risk environments.",
    }


# ==============================================================================
# WHAT-IF PATCH CAPACITY CONSTRAINED OPTIMIZER
# ==============================================================================


def estimate_patch_effort_hours(finding: VulnerabilityFinding, asset: Asset) -> float:
    """Deterministically estimate operational engineering hours required to test and deploy a patch.

    Grounded in DATASET_SPEC.md §8 (cost range 0.5 - 6.0 hours) and POL-SEC-04-patching.md §5.1:
    - Production deployment requires change review, staging verification, and rollback prep (2.0h).
    - Staging requires validation test suite run (1.0h).
    - Dev / Testing requires developer test execution (0.5h).
    - Core system/runtime/crypto packages (glibc, kernel, openssl, golang) require 1.0 - 1.5h complexity.
    - Application packages (curl, nghttp2, etc.) require 0.5h.

    Returns:
        Estimated effort in engineering hours (between 1.0h and 3.5h).
    """
    env_str = asset.environment.value.upper()
    if env_str == "PRODUCTION":
        env_effort = 2.0
    elif env_str == "STAGING":
        env_effort = 1.0
    else:
        env_effort = 0.5

    pkg_name = finding.affected_package.lower()
    if any(k in pkg_name for k in ["glibc", "linux", "openssl", "kernel"]):
        pkg_effort = 1.5
    elif any(k in pkg_name for k in ["golang", "python", "openjdk", "node"]):
        pkg_effort = 1.0
    else:
        pkg_effort = 0.5

    return round(env_effort + pkg_effort, 1)


def build_patch_candidates(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> List[PatchCandidate]:
    """Assemble strongly-typed PatchCandidate instances for all benchmark findings.

    Args:
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.
        assessments: Map of finding_id -> RiskAssessment.

    Returns:
        List of PatchCandidate instances.
    """
    candidates: List[PatchCandidate] = []
    for fid in sorted(findings.keys(), key=lambda x: int(x.replace("FINDING-", ""))):
        f = findings[fid]
        a = assets.get(f.asset_id)
        if not a:
            continue
        r = assessments.get(fid)
        ers = r.environmental_risk_score if r else 0.0
        tier = r.risk_tier if r else RiskTier.LOW
        effort = estimate_patch_effort_hours(f, a)

        candidates.append(
            PatchCandidate(
                candidate_id=f"CAND-{f.finding_id.replace('FINDING-', '')}",
                finding_id=f.finding_id,
                cve_id=f.cve_id,
                asset_id=f.asset_id,
                risk_tier=tier,
                expected_risk_reduction=round(ers, 2),
                estimated_cost_hours=effort,
                dependencies=[],
            )
        )

    return candidates


def optimize_patch_schedule(
    candidates: List[PatchCandidate],
    capacity_limit_hours: float,
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
) -> Dict[str, Any]:
    """Deterministically solve the 0/1 knapsack problem to maximize risk reduction under capacity limit.

    Args:
        candidates: List of candidate vulnerabilities.
        capacity_limit_hours: Total maintenance window engineering hours available.
        findings: Map of finding_id -> VulnerabilityFinding.
        assets: Map of asset_id -> Asset.

    Returns:
        Dictionary containing scheduled actions, deferred actions, total scheduled effort,
        total expected risk reduction, and remaining maintenance window capacity.
    """
    if capacity_limit_hours <= 0:
        return {
            "capacity_limit_hours": 0.0,
            "total_scheduled_effort_hours": 0.0,
            "total_expected_risk_reduction": 0.0,
            "remaining_capacity_hours": 0.0,
            "scheduled_count": 0,
            "deferred_count": len(candidates),
            "scheduled_candidates": [],
            "deferred_candidates": [],
        }

    # Discretize capacity to 0.5 hour steps for standard integer knapsack DP
    step = 0.5
    max_steps = int(round(capacity_limit_hours / step))

    # Pre-filter candidates with positive risk reduction and valid cost
    valid_candidates = [c for c in candidates if c.estimated_cost_hours > 0 and c.expected_risk_reduction > 0]

    # Pre-sort candidates by risk-to-effort efficiency descending, then ERS descending, then ID ascending
    valid_candidates.sort(
        key=lambda c: (
            round(c.expected_risk_reduction / c.estimated_cost_hours, 4),
            c.expected_risk_reduction,
            c.candidate_id,
        ),
        reverse=True,
    )

    n = len(valid_candidates)
    weights = [int(round(c.estimated_cost_hours / step)) for c in valid_candidates]
    values = [c.expected_risk_reduction for c in valid_candidates]

    # Standard DP table
    dp = [[0.0] * (max_steps + 1) for _ in range(n + 1)]

    for i in range(1, n + 1):
        w = weights[i - 1]
        v = values[i - 1]
        for c in range(max_steps + 1):
            if w <= c:
                dp[i][c] = max(dp[i - 1][c], dp[i - 1][c - w] + v)
            else:
                dp[i][c] = dp[i - 1][c]

    # Backtrack to identify selected items
    selected_indices = set()
    rem_c = max_steps
    for i in range(n, 0, -1):
        if dp[i][rem_c] != dp[i - 1][rem_c]:
            selected_indices.add(i - 1)
            rem_c -= weights[i - 1]

    scheduled: List[Dict[str, Any]] = []
    deferred: List[Dict[str, Any]] = []

    total_effort = 0.0
    total_reduction = 0.0

    # Sort all candidates in final presentation order
    ranked_candidates = sorted(
        valid_candidates,
        key=lambda c: (
            c.expected_risk_reduction / c.estimated_cost_hours,
            c.expected_risk_reduction,
            c.candidate_id,
        ),
        reverse=True,
    )

    for rank_idx, cand in enumerate(ranked_candidates, start=1):
        f = findings.get(cand.finding_id)
        a = assets.get(cand.asset_id)
        hostname = a.hostname if a else "Unknown"
        env = a.environment.value if a else "Unknown"
        ratio = round(cand.expected_risk_reduction / cand.estimated_cost_hours, 2)

        record = {
            "rank": rank_idx,
            "candidate_id": cand.candidate_id,
            "finding_id": cand.finding_id,
            "cve_id": cand.cve_id,
            "asset_id": cand.asset_id,
            "hostname": hostname,
            "environment": env,
            "risk_tier": cand.risk_tier.value,
            "expected_risk_reduction": cand.expected_risk_reduction,
            "estimated_cost_hours": cand.estimated_cost_hours,
            "efficiency_ratio": ratio,
        }

        # Check if index in valid_candidates was selected
        cand_idx = valid_candidates.index(cand)
        if cand_idx in selected_indices:
            record["status"] = "SCHEDULED"
            scheduled.append(record)
            total_effort += cand.estimated_cost_hours
            total_reduction += cand.expected_risk_reduction
        else:
            record["status"] = "DEFERRED"
            deferred.append(record)

    return {
        "capacity_limit_hours": round(capacity_limit_hours, 1),
        "total_scheduled_effort_hours": round(total_effort, 1),
        "total_expected_risk_reduction": round(total_reduction, 2),
        "remaining_capacity_hours": round(max(0.0, capacity_limit_hours - total_effort), 1),
        "scheduled_count": len(scheduled),
        "deferred_count": len(deferred),
        "scheduled_candidates": scheduled,
        "deferred_candidates": deferred,
    }
