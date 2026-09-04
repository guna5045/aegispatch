"""Comprehensive unit and Streamlit AppTest integration tests for Phase 4D Scenario Explorer & What-If Demonstration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Dict

import pytest

from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.data_service import evaluate_benchmark_risks
from src.services.scenario_service import (
    DEFAULT_MAINTENANCE_CAPACITY_HOURS,
    build_patch_candidates,
    estimate_patch_effort_hours,
    get_scenario_comparison_a,
    get_scenario_comparison_b,
    get_scenario_comparison_c,
    get_scenario_comparison_d,
    get_scenario_comparison_e,
    load_benchmark_scenarios,
    optimize_patch_schedule,
)

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
SCANS_PATH = DATA_DIR / "benchmark_60_scans.json"
CMDB_PATH = DATA_DIR / "enterprise_cmdb.json"
SCENARIOS_PATH = DATA_DIR / "benchmark_scenarios.json"


@pytest.fixture(scope="module")
def benchmark_findings() -> Dict[str, VulnerabilityFinding]:
    with open(SCANS_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {item["finding_id"]: VulnerabilityFinding(**item) for item in data}


@pytest.fixture(scope="module")
def cmdb_assets() -> Dict[str, Asset]:
    with open(CMDB_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return {item["asset_id"]: Asset(**item) for item in data}


@pytest.fixture(scope="module")
def benchmark_assessments(benchmark_findings, cmdb_assets) -> Dict[str, RiskAssessment]:
    return evaluate_benchmark_risks(benchmark_findings, cmdb_assets)


# ==============================================================================
# 1. Scenario Metadata & Integrity Tests
# ==============================================================================


def test_load_benchmark_scenarios_integrity():
    """Verify all 5 benchmark scenarios load and contain expected structure."""
    scenarios = load_benchmark_scenarios()
    expected_ids = {"SCENARIO-A", "SCENARIO-B", "SCENARIO-C", "SCENARIO-D", "SCENARIO-E"}
    assert set(scenarios.keys()) == expected_ids

    for sc_id, sc in scenarios.items():
        assert "title" in sc
        assert "description" in sc
        assert "finding_ids" in sc
        assert "asset_ids" in sc
        assert len(sc["finding_ids"]) > 0
        assert len(sc["asset_ids"]) > 0


# ==============================================================================
# 2. Scenario A Tests: Exposure / Criticality Inversion
# ==============================================================================


def test_scenario_a_exposure_and_criticality_inversion(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Scenario A: Verify CVSS 10.0 on isolated test system is prioritized lower than CVSS 7.5 on exposed prod."""
    comp = get_scenario_comparison_a(benchmark_findings, cmdb_assets, benchmark_assessments)

    assert comp["scenario_id"] == "SCENARIO-A"
    iso = comp["isolated"]
    exp = comp["exposed"]

    # Base CVSS: 10.0 > 7.5
    assert iso["cvss_score"] == 10.0
    assert exp["cvss_score"] == 7.5
    assert iso["cvss_score"] > exp["cvss_score"]
    assert comp["cvss_delta"] == 2.5

    # Environmental risk inversion: Exposed (43.00) > Isolated (28.01)
    assert exp["environmental_risk_score"] > iso["environmental_risk_score"]
    assert comp["ers_delta"] > 0
    assert exp["environmental_risk_score"] == 43.00
    assert iso["environmental_risk_score"] == 28.01

    # Decision divergence
    assert exp["aegis_decision"] == "PLAN"
    assert iso["aegis_decision"] == "TRACK"
    assert exp["risk_tier"] == "MEDIUM"
    assert iso["risk_tier"] == "LOW"


# ==============================================================================
# 3. Scenario B Tests: Threat Intelligence Differential
# ==============================================================================


def test_scenario_b_threat_differential(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Scenario B: Baseline threat absence is preserved; verified threat input elevates ERS."""
    comp = get_scenario_comparison_b(benchmark_findings, cmdb_assets, benchmark_assessments)

    assert comp["scenario_id"] == "SCENARIO-B"
    base = comp["baseline_unaugmented"]
    dem = comp["verified_input_demonstration"]

    # Baseline: threat feed is absent
    assert "Threat intelligence unavailable" in base["threat_status"]
    assert base["threat_score"] == 0.0
    assert base["environmental_risk_score"] == 43.60
    assert base["aegis_decision"] == "PLAN"

    # Verified demonstration: weaponized PoC + EPSS 0.45 elevates score
    assert dem["threat_score"] == 56.0
    assert dem["environmental_risk_score"] == 61.52
    assert comp["ers_jump"] == 17.92
    assert dem["environmental_risk_score"] > base["environmental_risk_score"]


# ==============================================================================
# 4. Scenario C Tests: Compensating Controls Risk Mitigation
# ==============================================================================


def test_scenario_c_compensating_controls_dampening(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Scenario C: Active WAF on ASSET-001 dampens unmitigated risk without removing vulnerability."""
    comp = get_scenario_comparison_c(benchmark_findings, cmdb_assets, benchmark_assessments)

    assert comp["scenario_id"] == "SCENARIO-C"
    assert comp["shared_cve"] == "CVE-2023-38545"
    assert comp["cvss_score"] == 9.8

    prot = comp["protected_asset"]
    unprot = comp["unprotected_asset"]

    # Control multipliers
    assert prot["control_multiplier"] == 0.85
    assert unprot["control_multiplier"] == 1.00

    # Dampening points
    assert prot["points_dampened"] == 8.61
    assert prot["environmental_risk_score"] == 48.79
    assert prot["unmitigated_risk"] == 57.40
    assert prot["environmental_risk_score"] < prot["unmitigated_risk"]

    # Valid multiplier bounds
    assert 0.60 <= prot["control_multiplier"] <= 1.00


# ==============================================================================
# 5. Scenario D Tests: Intra-Asset Hotspot Prioritization
# ==============================================================================


def test_scenario_d_intra_asset_hotspot(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Scenario D: 5 concurrent findings on ASSET-002 sequenced by ERS descending."""
    comp = get_scenario_comparison_d(benchmark_findings, cmdb_assets, benchmark_assessments)

    assert comp["scenario_id"] == "SCENARIO-D"
    asset = comp["asset"]
    assert asset["asset_id"] == "ASSET-002"
    assert asset["finding_count"] == 5
    assert asset["max_finding_ers"] == 47.60

    findings = comp["findings"]
    assert len(findings) == 5

    # Check descending order of ERS
    ers_scores = [f["environmental_risk_score"] for f in findings]
    assert ers_scores == sorted(ers_scores, reverse=True)
    assert findings[0]["finding_id"] == "FINDING-008"
    assert findings[-1]["finding_id"] == "FINDING-009"


# ==============================================================================
# 6. Scenario E Tests: Cross-Asset Prevalent Vulnerability Spread
# ==============================================================================


def test_scenario_e_cross_asset_spread(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Scenario E: Same CVE-2023-38545 across 4 distinct environments yields 4 distinct ERS values."""
    comp = get_scenario_comparison_e(benchmark_findings, cmdb_assets, benchmark_assessments)

    assert comp["scenario_id"] == "SCENARIO-E"
    assert comp["cve_id"] == "CVE-2023-38545"

    comparisons = comp["comparisons"]
    assert len(comparisons) == 4

    # 4 distinct ERS scores
    ers_values = [c["environmental_risk_score"] for c in comparisons]
    assert len(set(ers_values)) == 4

    # Descending check: Prod Gateway highest (48.79), Dev sandbox lowest (33.77)
    assert comparisons[0]["asset_id"] == "ASSET-001"
    assert comparisons[0]["environmental_risk_score"] == 48.79
    assert comparisons[-1]["asset_id"] == "ASSET-015"
    assert comparisons[-1]["environmental_risk_score"] == 33.77
    assert comp["ers_spread"] == 15.02


# ==============================================================================
# 7. What-If Patch Capacity Optimizer Tests
# ==============================================================================


def test_estimate_patch_effort_hours(benchmark_findings, cmdb_assets):
    """Verify deterministic patch effort estimates adhere to DATASET_SPEC range (0.5 to 6.0 hours)."""
    for fid, f in benchmark_findings.items():
        asset = cmdb_assets[f.asset_id]
        effort = estimate_patch_effort_hours(f, asset)
        assert 0.5 <= effort <= 6.0, f"Effort {effort} out of range for {fid}"


def test_build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify strongly-typed PatchCandidate generation for all 60 benchmark findings."""
    candidates = build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments)
    assert len(candidates) == 60

    for c in candidates:
        assert c.candidate_id.startswith("CAND-")
        assert c.finding_id in benchmark_findings
        assert c.estimated_cost_hours > 0
        assert c.expected_risk_reduction > 0


def test_optimize_patch_schedule_default_capacity(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify optimization respects the default 16.0 hour maintenance capacity constraint."""
    candidates = build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments)
    res = optimize_patch_schedule(candidates, DEFAULT_MAINTENANCE_CAPACITY_HOURS, benchmark_findings, cmdb_assets)

    assert res["capacity_limit_hours"] == 16.0
    assert res["total_scheduled_effort_hours"] <= 16.0
    assert res["remaining_capacity_hours"] == round(16.0 - res["total_scheduled_effort_hours"], 1)
    assert res["scheduled_count"] > 0
    assert res["deferred_count"] > 0
    assert res["scheduled_count"] + res["deferred_count"] == 60
    assert res["total_expected_risk_reduction"] > 0


def test_optimize_patch_schedule_monotonicity(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify increasing capacity increases or maintains scheduled candidates and risk reduction."""
    candidates = build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments)

    res_8 = optimize_patch_schedule(candidates, 8.0, benchmark_findings, cmdb_assets)
    res_16 = optimize_patch_schedule(candidates, 16.0, benchmark_findings, cmdb_assets)
    res_24 = optimize_patch_schedule(candidates, 24.0, benchmark_findings, cmdb_assets)

    assert res_8["total_scheduled_effort_hours"] <= 8.0
    assert res_16["total_scheduled_effort_hours"] <= 16.0
    assert res_24["total_scheduled_effort_hours"] <= 24.0

    assert res_16["scheduled_count"] >= res_8["scheduled_count"]
    assert res_24["scheduled_count"] >= res_16["scheduled_count"]

    assert res_16["total_expected_risk_reduction"] >= res_8["total_expected_risk_reduction"]
    assert res_24["total_expected_risk_reduction"] >= res_16["total_expected_risk_reduction"]


def test_optimize_patch_schedule_zero_capacity(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify zero capacity yields zero scheduled actions without errors."""
    candidates = build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments)
    res = optimize_patch_schedule(candidates, 0.0, benchmark_findings, cmdb_assets)

    assert res["scheduled_count"] == 0
    assert res["deferred_count"] == 60
    assert res["total_scheduled_effort_hours"] == 0.0
    assert res["total_expected_risk_reduction"] == 0.0


def test_scenario_service_data_immutability(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify scenario calculations do not mutate source data."""
    findings_snapshot = {fid: f.model_dump() for fid, f in benchmark_findings.items()}
    assets_snapshot = {aid: a.model_dump() for aid, a in cmdb_assets.items()}

    _ = get_scenario_comparison_a(benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = get_scenario_comparison_b(benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = get_scenario_comparison_c(benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = get_scenario_comparison_d(benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = get_scenario_comparison_e(benchmark_findings, cmdb_assets, benchmark_assessments)
    candidates = build_patch_candidates(benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = optimize_patch_schedule(candidates, 16.0, benchmark_findings, cmdb_assets)

    for fid, f in benchmark_findings.items():
        assert f.model_dump() == findings_snapshot[fid]

    for aid, a in cmdb_assets.items():
        assert a.model_dump() == assets_snapshot[aid]


# ==============================================================================
# 8. Streamlit AppTest Integration Tests
# ==============================================================================


def test_streamlit_scenarios_page_default_navigation():
    """Verify that app.py loads with Scenarios as the active view and renders header and selector."""
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    # Navigate to Scenarios view via sidebar radio
    at.sidebar.radio[0].set_value("Scenarios").run()
    assert not at.exception

    # Header and subtitle
    assert at.title[0].value == "Aegis Patch — Scenarios Explorer"
    assert "See how environmental context changes vulnerability priority" in at.subheader[0].value

    # Scenario selectbox exists
    scenario_sel = next((s for s in at.selectbox if s.key == "scenario_select_box"), None)
    assert scenario_sel is not None
    assert len(scenario_sel.options) == 6


def test_streamlit_scenarios_switching():
    """Verify switching across Scenarios A through E and What-If simulation in AppTest."""
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    at.sidebar.radio[0].set_value("Scenarios").run()

    scenario_sel = next(s for s in at.selectbox if s.key == "scenario_select_box")

    # Select Scenario B
    scenario_sel.select("Scenario B: Threat Intelligence Differential").run()
    assert not at.exception

    # Select Scenario C
    scenario_sel.select("Scenario C: Compensating Control Dampening").run()
    assert not at.exception

    # Select Scenario D
    scenario_sel.select("Scenario D: Intra-Asset Hotspot Prioritization").run()
    assert not at.exception
    assert len(at.dataframe) >= 1

    # Select Scenario E
    scenario_sel.select("Scenario E: Cross-Asset Prevalent Vulnerability Spread").run()
    assert not at.exception
    assert len(at.dataframe) >= 1

    # Select What-If Simulation
    scenario_sel.select("What-If: Patch Capacity Simulation").run()
    assert not at.exception
    # Verify slider exists
    slider = next((s for s in at.slider if s.key == "slider_capacity_hours"), None)
    assert slider is not None
    assert slider.value == 16.0


def test_streamlit_what_if_capacity_slider_interaction():
    """Verify adjusting the capacity slider updates the simulation plan and table."""
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    at.sidebar.radio[0].set_value("Scenarios").run()

    # Switch to What-If simulation
    scenario_sel = next(s for s in at.selectbox if s.key == "scenario_select_box")
    scenario_sel.select("What-If: Patch Capacity Simulation").run()

    slider = next(s for s in at.slider if s.key == "slider_capacity_hours")

    # Change capacity to 8.0h
    slider.set_value(8.0).run()
    assert not at.exception

    # Check dataframe is rendered with 60 candidates
    df = at.dataframe[0].value
    assert len(df) == 60

    # Scheduled candidates should have effort <= 8.0
    scheduled_rows = df[df["Status"] == "SCHEDULED"]
    total_effort = scheduled_rows["Effort (Hours)"].sum()
    assert total_effort <= 8.0
