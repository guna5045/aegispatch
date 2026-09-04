"""Unit tests for Phase 4B dashboard service and metrics calculations."""

import copy
import pytest
from src.services.dashboard_service import (
    aggregate_assets_by_risk,
    compute_dashboard_kpis,
    compute_decision_distribution,
    compute_ers_distribution,
    compute_severity_distribution,
    filter_findings,
    get_priority_preview,
)
from src.services.data_service import (
    evaluate_benchmark_risks,
    load_benchmark_findings,
    load_cmdb_assets,
)


@pytest.fixture(scope="module")
def cmdb_assets():
    return load_cmdb_assets()


@pytest.fixture(scope="module")
def benchmark_findings():
    return load_benchmark_findings()


@pytest.fixture(scope="module")
def benchmark_assessments(benchmark_findings, cmdb_assets):
    return evaluate_benchmark_risks(benchmark_findings, cmdb_assets)


@pytest.fixture(scope="module")
def all_finding_ids(benchmark_findings):
    return list(benchmark_findings.keys())


# ==============================================================================
# 1. KPI Calculations (Items 1 - 6)
# ==============================================================================


def test_compute_dashboard_kpis_baseline(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify KPI calculation accuracy across the complete benchmark dataset."""
    kpis = compute_dashboard_kpis(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments)

    # 1. Total findings analyzed
    assert kpis["findings_analyzed"] == 60

    # 2. Distinct affected assets
    expected_assets = len({f.asset_id for f in benchmark_findings.values()})
    assert kpis["assets_affected"] == expected_assets
    assert kpis["assets_affected"] == 18

    # 3. Critical vulnerability severity count
    expected_critical = sum(1 for f in benchmark_findings.values() if f.severity.value == "CRITICAL")
    assert kpis["critical_severity_count"] == expected_critical

    # 4. Priority findings count (ACT + ATTEND)
    expected_priority = sum(
        1 for a in benchmark_assessments.values()
        if a.calculation_metadata.get("aegis_decision", a.decision.value) in ("ACT", "ATTEND")
    )
    assert kpis["priority_findings_count"] == expected_priority

    # 5. Average ERS calculation
    expected_avg = round(sum(a.environmental_risk_score for a in benchmark_assessments.values()) / 60, 1)
    assert kpis["average_ers"] == expected_avg
    assert 0.0 < kpis["average_ers"] < 100.0


def test_compute_dashboard_kpis_with_priority_findings(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify priority_findings_count correctly counts ACT and ATTEND decisions when present."""
    # Temporarily copy assessments and modify one to ACT and one to ATTEND
    mock_assessments = copy.deepcopy(benchmark_assessments)
    fids = list(mock_assessments.keys())[:5]
    mock_assessments[fids[0]].calculation_metadata["aegis_decision"] = "ACT"
    mock_assessments[fids[1]].calculation_metadata["aegis_decision"] = "ATTEND"

    kpis = compute_dashboard_kpis(fids, benchmark_findings, cmdb_assets, mock_assessments)
    assert kpis["priority_findings_count"] == 2
    assert kpis["findings_analyzed"] == 5


def test_compute_dashboard_kpis_empty():
    """Verify that KPI calculations on empty finding list return safe zeros."""
    empty_kpis = compute_dashboard_kpis([], {}, {}, {})
    assert empty_kpis["findings_analyzed"] == 0
    assert empty_kpis["assets_affected"] == 0
    assert empty_kpis["critical_severity_count"] == 0
    assert empty_kpis["priority_findings_count"] == 0
    assert empty_kpis["average_ers"] == 0.0


# ==============================================================================
# 2. Distributions (Items 7 - 9)
# ==============================================================================


def test_compute_severity_distribution(all_finding_ids, benchmark_findings):
    """Verify vulnerability severity distribution counts sum to total findings."""
    dist = compute_severity_distribution(all_finding_ids, benchmark_findings)

    expected_keys = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert set(dist.keys()) == expected_keys
    assert sum(dist.values()) == 60

    for sev, count in dist.items():
        expected_count = sum(1 for f in benchmark_findings.values() if f.severity.value == sev)
        assert count == expected_count


def test_compute_decision_distribution(all_finding_ids, benchmark_assessments):
    """Verify Aegis Patch decision distribution counts sum to total findings."""
    dist = compute_decision_distribution(all_finding_ids, benchmark_assessments)

    expected_keys = {"ACT", "ATTEND", "PLAN", "TRACK"}
    assert set(dist.keys()) == expected_keys
    assert sum(dist.values()) == 60

    for dec, count in dist.items():
        expected_count = sum(
            1 for a in benchmark_assessments.values()
            if a.calculation_metadata.get("aegis_decision", a.decision.value) == dec
        )
        assert count == expected_count


def test_compute_ers_distribution(all_finding_ids, benchmark_assessments):
    """Verify ERS score band distribution matches Phase 3 threshold logic."""
    dist = compute_ers_distribution(all_finding_ids, benchmark_assessments)

    expected_keys = {"ACT (85–100)", "ATTEND (65–<85)", "PLAN (40–<65)", "TRACK (0–<40)"}
    assert set(dist.keys()) == expected_keys
    assert sum(dist.values()) == 60

    # Test threshold classification consistency
    act_count = sum(1 for a in benchmark_assessments.values() if a.environmental_risk_score >= 85.0)
    attend_count = sum(1 for a in benchmark_assessments.values() if 65.0 <= a.environmental_risk_score < 85.0)
    plan_count = sum(1 for a in benchmark_assessments.values() if 40.0 <= a.environmental_risk_score < 65.0)
    track_count = sum(1 for a in benchmark_assessments.values() if a.environmental_risk_score < 40.0)

    assert dist["ACT (85–100)"] == act_count
    assert dist["ATTEND (65–<85)"] == attend_count
    assert dist["PLAN (40–<65)"] == plan_count
    assert dist["TRACK (0–<40)"] == track_count


# ==============================================================================
# 3. Asset Risk Aggregation & Ranking (Items 10 - 11)
# ==============================================================================


def test_aggregate_assets_by_risk_and_ranking(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify asset aggregation and deterministic descending sorting by highest ERS."""
    assets_ranked = aggregate_assets_by_risk(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments)

    assert len(assets_ranked) == 18

    # Verify each entry has required fields
    required_keys = {
        "asset_id",
        "hostname",
        "environment",
        "criticality",
        "findings_count",
        "highest_ers",
        "act_count",
        "attend_count",
        "plan_count",
        "track_count",
    }
    for entry in assets_ranked:
        assert required_keys.issubset(entry.keys())
        assert entry["findings_count"] > 0
        assert 0.0 <= entry["highest_ers"] <= 100.0

    # Verify descending ordering by highest_ers and secondary act_count
    for i in range(len(assets_ranked) - 1):
        curr_item = assets_ranked[i]
        next_item = assets_ranked[i + 1]
        assert curr_item["highest_ers"] >= next_item["highest_ers"]
        if curr_item["highest_ers"] == next_item["highest_ers"]:
            assert curr_item["act_count"] >= next_item["act_count"]


# ==============================================================================
# 4. Priority Preview (Item 12)
# ==============================================================================


def test_get_priority_preview(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify top 5 priority preview records are sorted descending by ERS."""
    limit = 5
    preview = get_priority_preview(all_finding_ids, benchmark_findings, cmdb_assets, benchmark_assessments, limit=limit)

    assert len(preview) == limit

    expected_keys = {
        "finding_id",
        "cve_id",
        "title",
        "asset_id",
        "hostname",
        "severity",
        "cvss_score",
        "environmental_risk_score",
        "aegis_decision",
        "risk_tier",
    }
    for item in preview:
        assert expected_keys.issubset(item.keys())

    for i in range(len(preview) - 1):
        assert preview[i]["environmental_risk_score"] >= preview[i + 1]["environmental_risk_score"]


# ==============================================================================
# 5. Multi-criteria Filtering & Empty State (Items 13 - 14)
# ==============================================================================


def test_filter_findings_by_severity(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify filtering by vulnerability severity."""
    crit_ids = filter_findings(benchmark_findings, cmdb_assets, benchmark_assessments, severity="CRITICAL")
    assert len(crit_ids) > 0
    assert len(crit_ids) < 60
    for fid in crit_ids:
        assert benchmark_findings[fid].severity.value == "CRITICAL"


def test_filter_findings_by_decision(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify filtering by Aegis decision."""
    act_ids = filter_findings(benchmark_findings, cmdb_assets, benchmark_assessments, decision="ACT")
    for fid in act_ids:
        assessment = benchmark_assessments[fid]
        dec = assessment.calculation_metadata.get("aegis_decision", assessment.decision.value)
        assert dec == "ACT"


def test_filter_findings_by_environment(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify filtering by asset environment."""
    prod_ids = filter_findings(benchmark_findings, cmdb_assets, benchmark_assessments, environment="PRODUCTION")
    assert len(prod_ids) > 0
    for fid in prod_ids:
        asset = cmdb_assets[benchmark_findings[fid].asset_id]
        assert asset.environment.value == "PRODUCTION"


def test_filter_findings_by_criticality(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify filtering by asset criticality."""
    crit_asset_ids = filter_findings(benchmark_findings, cmdb_assets, benchmark_assessments, criticality="CRITICAL")
    assert len(crit_asset_ids) > 0
    for fid in crit_asset_ids:
        asset = cmdb_assets[benchmark_findings[fid].asset_id]
        assert asset.criticality.value == "CRITICAL"


def test_filter_findings_zero_results(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify filtering with contradictory criteria safely produces an empty list."""
    # Low severity finding on Testing asset with ACT decision (nonexistent in benchmark)
    empty_ids = filter_findings(
        benchmark_findings,
        cmdb_assets,
        benchmark_assessments,
        severity="LOW",
        decision="ACT",
    )
    assert empty_ids == []


# ==============================================================================
# 6. Data Immutability (Item 15)
# ==============================================================================


def test_source_data_immutability(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify that filtering and aggregation calculations do not mutate source data."""
    # Create snapshots
    findings_snapshot = {fid: f.model_dump() for fid, f in benchmark_findings.items()}
    assets_snapshot = {aid: a.model_dump() for aid, a in cmdb_assets.items()}

    # Run filtering, KPI, aggregation, distribution
    all_fids = list(benchmark_findings.keys())
    filtered_fids = filter_findings(benchmark_findings, cmdb_assets, benchmark_assessments, severity="HIGH", decision="PLAN")
    _ = compute_dashboard_kpis(filtered_fids, benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = compute_decision_distribution(all_fids, benchmark_assessments)
    _ = compute_severity_distribution(all_fids, benchmark_findings)
    _ = compute_ers_distribution(all_fids, benchmark_assessments)
    _ = aggregate_assets_by_risk(all_fids, benchmark_findings, cmdb_assets, benchmark_assessments)
    _ = get_priority_preview(all_fids, benchmark_findings, cmdb_assets, benchmark_assessments)

    # Verify original findings and assets are unchanged
    for fid, f in benchmark_findings.items():
        assert f.model_dump() == findings_snapshot[fid]

    for aid, a in cmdb_assets.items():
        assert a.model_dump() == assets_snapshot[aid]


# ==============================================================================
# 7. Streamlit Dashboard App Tests
# ==============================================================================


def test_streamlit_dashboard_rendering():
    """Verify that app.py runs via Streamlit AppTest without errors and renders Phase 4B dashboard elements."""
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()

    assert not at.exception
    assert at.title[0].value == "Aegis Patch"
    assert "Context-Driven Vulnerability Prioritization" in at.subheader[0].value

    # Check that 5 selectboxes exist (4 filters + 1 finding selector)
    assert len(at.selectbox) == 5

    # Check filter options
    assert at.selectbox[0].options == ["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"]
    assert at.selectbox[1].options == ["All", "ACT", "ATTEND", "PLAN", "TRACK"]


def test_streamlit_dashboard_filtering_and_empty_state():
    """Verify interactive filtering and safe empty state handling in Streamlit."""
    from pathlib import Path
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()

    # Filter to CRITICAL
    at.selectbox[0].select("CRITICAL").run()
    assert not at.exception

    # Filter to contradictory combination yielding 0 matches
    at.selectbox[1].select("PLAN").run()
    at.selectbox[2].select("TESTING").run()
    assert not at.exception

    # Confirm graceful message without tracebacks
    assert len(at.info) > 0
    assert "No findings match the current filters" in at.info[0].value

