"""Tests for Phase 7 planning tools: optimize_patch_capacity, resolve_package_dependencies, and simulate_risk_reduction."""

import pytest
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    BusinessTier,
    EnvironmentType,
    NetworkExposure,
)
from src.schemas.plan import PatchCandidate
from src.schemas.risk import RiskTier
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.planning_tools import (
    optimize_patch_capacity,
    resolve_package_dependencies,
    simulate_risk_reduction,
)
from src.tools.schemas import (
    OptimizePatchCapacityInput,
    ResolvePackageDependenciesInput,
    SideEffectClass,
    SimulateRiskReductionInput,
    ToolStatus,
)


@pytest.fixture
def sample_candidates():
    return [
        PatchCandidate(
            candidate_id="CAND-01",
            finding_id="FINDING-001",
            cve_id="CVE-2023-38545",
            asset_id="ASSET-001",
            risk_tier=RiskTier.CRITICAL,
            expected_risk_reduction=90.0,
            estimated_cost_hours=2.5,
            dependencies=[],
        ),
        PatchCandidate(
            candidate_id="CAND-02",
            finding_id="FINDING-002",
            cve_id="CVE-2023-44487",
            asset_id="ASSET-001",
            risk_tier=RiskTier.HIGH,
            expected_risk_reduction=65.0,
            estimated_cost_hours=2.5,
            dependencies=[],
        ),
        PatchCandidate(
            candidate_id="CAND-03",
            finding_id="FINDING-003",
            cve_id="CVE-2023-45288",
            asset_id="ASSET-001",
            risk_tier=RiskTier.HIGH,
            expected_risk_reduction=60.0,
            estimated_cost_hours=3.0,
            dependencies=[],
        ),
    ]


@pytest.fixture
def sample_finding_and_asset():
    from src.schemas.asset import AssetType, DataSensitivity
    f = VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow",
        description="Heap overflow in SOCKS5 proxy handshake.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-001",
        source="synthetic_benchmark",
    )
    a = Asset(
        asset_id="ASSET-001",
        hostname="gw-prod-01",
        asset_type=AssetType.SERVER,
        environment=EnvironmentType.PRODUCTION,
        criticality=AssetCriticality.CRITICAL,
        business_tier=BusinessTier.MISSION_CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        owner_team="SecOps",
        compensating_controls=[],
    )
    return f, a


def test_optimize_patch_capacity(sample_candidates):
    # Capacity allows CAND-01 (2.5h) and CAND-02 (2.5h) = 5.0h <= 6.0h
    inp = OptimizePatchCapacityInput(candidates=sample_candidates, capacity_limit_hours=6.0)
    out = optimize_patch_capacity(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.COMPUTE_ONLY
    assert out.total_scheduled_effort_hours <= 6.0
    assert len(out.scheduled_candidates) >= 1
    assert out.capacity_utilization_percent > 0.0
    assert out.algorithm == "deterministic_0_1_knapsack_dp"


def test_optimize_patch_capacity_zero_limit(sample_candidates):
    inp = OptimizePatchCapacityInput(candidates=sample_candidates, capacity_limit_hours=0.0)
    out = optimize_patch_capacity(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.total_scheduled_effort_hours == 0.0
    assert len(out.scheduled_candidates) == 0
    assert len(out.deferred_candidates) == len(sample_candidates)


def test_resolve_package_dependencies_known():
    inp = ResolvePackageDependenciesInput(package_name="libcurl4", target_version="8.4.0-1")
    out = resolve_package_dependencies(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.package_name == "libcurl4"
    assert len(out.prerequisites) == 2
    assert any(p.package_name == "libssl3" for p in out.prerequisites)


def test_resolve_package_dependencies_unknown():
    inp = ResolvePackageDependenciesInput(package_name="unknown-internal-pkg", target_version="1.0.0")
    out = resolve_package_dependencies(inp)

    assert out.status == ToolStatus.NOT_AVAILABLE
    assert len(out.prerequisites) == 0


def test_simulate_risk_reduction(sample_finding_and_asset):
    f, a = sample_finding_and_asset
    inp = SimulateRiskReductionInput(
        finding=f,
        asset=a,
        hypothetical_controls_added=["WAF", "NETWORK_SEGMENTATION"],
        is_cisa_kev=True,
    )
    out = simulate_risk_reduction(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.SIMULATION
    assert out.simulation_label == "SIMULATED"
    assert out.current_ers > out.simulated_ers
    assert out.projected_risk_reduction > 0.0
