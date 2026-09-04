"""Deterministic remediation planning and simulation tools for Aegis Patch.

All tools in this module operate deterministically with explicit typing and side-effect guarantees.
None of these tools execute real patches, modify servers, connect via SSH, or run package managers.
The optimizer wraps the authoritative Phase 4 knapsack implementation from scenario_service.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List, Optional

from src.schemas.asset import Asset
from src.schemas.plan import PatchCandidate
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.scenario_service import optimize_patch_schedule
from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import (
    DependencyItem,
    OptimizePatchCapacityInput,
    OptimizePatchCapacityOutput,
    ProvenanceSourceType,
    ResolvePackageDependenciesInput,
    ResolvePackageDependenciesOutput,
    SideEffectClass,
    SimulateRiskReductionInput,
    SimulateRiskReductionOutput,
    ToolProvenance,
    ToolStatus,
)


def optimize_patch_capacity(
    input_data: OptimizePatchCapacityInput,
) -> OptimizePatchCapacityOutput:
    """Select a subset of candidate remediation actions maximizing cumulative expected risk reduction.

    Delegates directly to the authoritative Phase 4 0/1 knapsack dynamic programming optimizer.
    Respects maintenance window capacity limit in engineering hours.
    Analytical simulation only: no actual patches are applied.
    """
    candidates = input_data.candidates
    limit = input_data.capacity_limit_hours

    # Dummy maps required by scenario_service presentation formatting
    findings_map: Dict[str, VulnerabilityFinding] = {}
    assets_map: Dict[str, Asset] = {}

    opt_result = optimize_patch_schedule(
        candidates=candidates,
        capacity_limit_hours=limit,
        findings=findings_map,
        assets=assets_map,
    )

    # Convert returned scheduled/deferred items back to PatchCandidate references
    scheduled_ids = {item["candidate_id"] for item in opt_result.get("scheduled_candidates", [])}
    scheduled_cands = [c for c in candidates if c.candidate_id in scheduled_ids]
    deferred_cands = [c for c in candidates if c.candidate_id not in scheduled_ids]

    total_effort = float(opt_result.get("total_scheduled_effort_hours", 0.0))
    total_reduction = float(opt_result.get("total_expected_risk_reduction", 0.0))
    rem_capacity = float(opt_result.get("remaining_capacity_hours", max(0.0, limit - total_effort)))
    utilization = round((total_effort / limit * 100.0), 1) if limit > 0 else 0.0

    return OptimizePatchCapacityOutput(
        tool_name="optimize_patch_capacity",
        status=ToolStatus.SUCCESS,
        message=f"Scheduled {len(scheduled_cands)} actions utilizing {total_effort:.1f}h / {limit:.1f}h ({utilization}%).",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="knapsack_patch_optimizer_dp",
            source_type=ProvenanceSourceType.CALCULATED,
            reference="src/services/scenario_service.py",
        ),
        capacity_limit_hours=limit,
        total_scheduled_effort_hours=total_effort,
        total_expected_risk_reduction=total_reduction,
        remaining_capacity_hours=rem_capacity,
        capacity_utilization_percent=utilization,
        scheduled_candidates=scheduled_cands,
        deferred_candidates=deferred_cands,
        algorithm="deterministic_0_1_knapsack_dp",
    )


def resolve_package_dependencies(
    input_data: ResolvePackageDependenciesInput,
) -> ResolvePackageDependenciesOutput:
    """Analyze package and prerequisite dependency relationships for remediation planning.

    Safe analytical tool only. Does NOT invoke package managers (apt, dpkg, pip, etc.),
    does NOT run shell commands, and does NOT modify target machines.
    Returns structured NOT_AVAILABLE when live ecosystem dependency trees are absent.
    """
    # Deterministic knowledge fixture for known benchmark dependencies
    pkg = input_data.package_name.lower()
    target_ver = input_data.target_version

    known_deps: Dict[str, List[DependencyItem]] = {
        "libcurl4": [
            DependencyItem(package_name="libssl3", required_version=">=3.0.0", dependency_type="DIRECT"),
            DependencyItem(package_name="zlib1g", required_version=">=1:1.2.11", dependency_type="DIRECT"),
        ],
        "nghttp2": [
            DependencyItem(package_name="libc6", required_version=">=2.34", dependency_type="DIRECT"),
        ],
    }

    if pkg in known_deps:
        return ResolvePackageDependenciesOutput(
            tool_name="resolve_package_dependencies",
            status=ToolStatus.SUCCESS,
            message=f"Resolved {len(known_deps[pkg])} direct dependencies for {input_data.package_name}.",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="package_dependency_benchmark_catalog",
                source_type=ProvenanceSourceType.LOCAL_DATASET,
            ),
            package_name=input_data.package_name,
            target_version=target_ver,
            prerequisites=known_deps[pkg],
            conflicts=[],
            has_conflicts=False,
        )

    return ResolvePackageDependenciesOutput(
        tool_name="resolve_package_dependencies",
        status=ToolStatus.NOT_AVAILABLE,
        message=f"No local dependency graph available for package '{input_data.package_name}'.",
        side_effect=SideEffectClass.READ_ONLY,
        provenance=ToolProvenance(
            source="package_dependency_benchmark_catalog",
            source_type=ProvenanceSourceType.LOCAL_DATASET,
        ),
        package_name=input_data.package_name,
        target_version=target_ver,
        prerequisites=[],
        conflicts=[],
        has_conflicts=False,
    )


def simulate_risk_reduction(
    input_data: SimulateRiskReductionInput,
) -> SimulateRiskReductionOutput:
    """Simulate expected risk score and decision changes after applying hypothetical controls.

    What-if calculation only: does NOT apply patches or mutate infrastructure.
    Uses authoritative Phase 3 risk engine.
    """
    from datetime import datetime, timezone
    from src.schemas.threat import ThreatConfidence, ThreatEvidence

    threat = ThreatEvidence(
        evidence_id=f"EV-SIM-{input_data.finding.cve_id}",
        cve_id=input_data.finding.cve_id,
        is_cisa_kev=input_data.is_cisa_kev,
        epss_score=input_data.epss_score,
        public_poc_available=input_data.public_poc_available,
        threat_source="what_if_simulation",
        retrieved_at=datetime.now(timezone.utc),
        confidence=ThreatConfidence.HIGH,
    )

    # Baseline assessment
    baseline = evaluate_risk(
        finding=input_data.finding,
        asset=input_data.asset,
        threat=threat,
    )

    # Construct hypothetical asset with added compensating controls
    from src.schemas.asset import CompensatingControl, ControlStatus
    hypo_asset_dict = input_data.asset.model_dump()
    existing_controls = list(input_data.asset.compensating_controls)
    for c_name in input_data.hypothetical_controls_added:
        if not any(c.name == c_name for c in existing_controls):
            existing_controls.append(
                CompensatingControl(
                    control_id=f"CTRL-SIM-{len(existing_controls)+1}",
                    name=c_name,
                    description=f"Simulated control: {c_name}",
                    status=ControlStatus.ACTIVE,
                )
            )
    hypo_asset_dict["compensating_controls"] = [c.model_dump() for c in existing_controls]
    hypo_asset = Asset.model_validate(hypo_asset_dict)

    # Simulated assessment
    simulated = evaluate_risk(
        finding=input_data.finding,
        asset=hypo_asset,
        threat=threat,
    )

    delta = round(baseline.environmental_risk_score - simulated.environmental_risk_score, 2)

    from src.tools.decision_mapping import AegisDecision
    base_dec = AegisDecision(baseline.calculation_metadata.get("aegis_decision", AegisDecision.TRACK.value))
    sim_dec = AegisDecision(simulated.calculation_metadata.get("aegis_decision", AegisDecision.TRACK.value))

    return SimulateRiskReductionOutput(
        tool_name="simulate_risk_reduction",
        status=ToolStatus.SUCCESS,
        message=f"Simulated risk reduction: baseline ERS {baseline.environmental_risk_score:.2f} -> projected ERS {simulated.environmental_risk_score:.2f} (delta {delta:+.2f}).",
        side_effect=SideEffectClass.SIMULATION,
        provenance=ToolProvenance(
            source="aegis_what_if_simulator",
            source_type=ProvenanceSourceType.CALCULATED,
            reference="src/tools/risk_engine.py",
        ),
        current_ers=baseline.environmental_risk_score,
        simulated_ers=simulated.environmental_risk_score,
        projected_risk_reduction=delta,
        current_decision=base_dec,
        simulated_decision=sim_dec,
        simulation_label="SIMULATED",
    )
