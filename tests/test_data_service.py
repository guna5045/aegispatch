"""Unit tests for Phase 4A data loading and risk evaluation service."""

import json
from pathlib import Path
import pytest
from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.data_service import (
    DEFAULT_CMDB_PATH,
    DEFAULT_SCANS_PATH,
    evaluate_benchmark_risks,
    get_finding_context,
    get_top_findings,
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


# ==============================================================================
# 1. Dataset Loading Tests
# ==============================================================================


def test_load_cmdb_assets_success(cmdb_assets):
    """Verify that all 18 enterprise CMDB assets load successfully as Pydantic models."""
    assert len(cmdb_assets) == 18
    assert "ASSET-001" in cmdb_assets
    assert "ASSET-018" in cmdb_assets

    for asset_id, asset in cmdb_assets.items():
        assert isinstance(asset, Asset)
        assert asset.asset_id == asset_id
        assert asset.hostname
        assert asset.criticality is not None
        assert asset.network_exposure is not None


def test_load_benchmark_findings_success(benchmark_findings):
    """Verify that all 60 benchmark findings load successfully as Pydantic models."""
    assert len(benchmark_findings) == 60
    assert "FINDING-001" in benchmark_findings
    assert "FINDING-060" in benchmark_findings

    for finding_id, finding in benchmark_findings.items():
        assert isinstance(finding, VulnerabilityFinding)
        assert finding.finding_id == finding_id
        assert finding.cve_id.startswith("CVE-")
        assert 0.0 <= finding.cvss_score <= 10.0


def test_app_get_cached_data():
    """Verify that app.get_cached_data loads datasets and returns zero error."""
    import app
    findings, assets, assessments, err_msg = app.get_cached_data()
    assert err_msg is None
    assert len(findings) == 60
    assert len(assets) == 18
    assert len(assessments) == 60


def test_streamlit_app_rendering():
    """Verify that app.py runs via Streamlit AppTest without errors and renders branding."""
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception
    assert at.title[0].value == "Aegis Patch"
    assert "Context-Driven Vulnerability Prioritization" in at.subheader[0].value
    assert len(at.selectbox[-1].options) == 60


def test_streamlit_app_navigation_and_selection():
    """Verify that user interaction (selection and navigation) works cleanly."""
    from streamlit.testing.v1 import AppTest

    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    # Test selecting a different finding on finding selector (last selectbox)
    at.selectbox[-1].select("FINDING-006").run()
    assert not at.exception

    # Test navigating to Vulnerabilities placeholder
    at.sidebar.radio[0].set_value("Vulnerabilities").run()
    assert not at.exception
    assert "Vulnerabilities" in at.title[0].value

    # Test navigating to Scenarios placeholder
    at.sidebar.radio[0].set_value("Scenarios").run()
    assert not at.exception
    assert "Scenarios" in at.title[0].value


# ==============================================================================
# 2. Relationship & Risk Engine Execution Tests
# ==============================================================================


def test_findings_map_to_cmdb_assets(benchmark_findings, cmdb_assets):
    """Verify that every benchmark finding's asset_id maps to an existing asset."""
    for finding_id, finding in benchmark_findings.items():
        assert finding.asset_id in cmdb_assets, (
            f"Finding {finding_id} references missing asset '{finding.asset_id}'"
        )


def test_evaluate_benchmark_risks_success(benchmark_assessments):
    """Verify that the Phase 3 risk engine evaluates all 60 findings deterministically."""
    assert len(benchmark_assessments) == 60

    valid_decisions = {"ACT", "ATTEND", "PLAN", "TRACK"}
    valid_tiers = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    for fid, assessment in benchmark_assessments.items():
        assert isinstance(assessment, RiskAssessment)
        assert 0.0 <= assessment.environmental_risk_score <= 100.0
        assert assessment.risk_tier.value in valid_tiers

        aegis_decision = assessment.calculation_metadata.get("aegis_decision")
        assert aegis_decision in valid_decisions


# ==============================================================================
# 3. Top Findings and Sorting Tests
# ==============================================================================


def test_get_top_findings_sorting(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify that get_top_findings retrieves top N findings sorted descending by ERS."""
    limit = 5
    top_5 = get_top_findings(benchmark_findings, cmdb_assets, benchmark_assessments, limit=limit)

    assert len(top_5) == limit

    for i in range(len(top_5) - 1):
        curr_ers = top_5[i]["environmental_risk_score"]
        next_ers = top_5[i + 1]["environmental_risk_score"]
        assert curr_ers >= next_ers, f"Sorting violation: {curr_ers} < {next_ers}"

    # Verify all expected keys are populated
    expected_keys = {
        "finding_id",
        "cve_id",
        "title",
        "asset_id",
        "hostname",
        "cvss_score",
        "environmental_risk_score",
        "aegis_decision",
        "risk_tier",
    }
    for item in top_5:
        assert expected_keys.issubset(item.keys())
        assert item["hostname"] != "Unknown"


# ==============================================================================
# 4. Context Resolution Tests
# ==============================================================================


def test_get_finding_context_resolution(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify that get_finding_context resolves finding, asset, and assessment data."""
    ctx = get_finding_context("FINDING-001", benchmark_findings, cmdb_assets, benchmark_assessments)

    assert ctx is not None
    assert "finding" in ctx
    assert "asset" in ctx
    assert "assessment" in ctx

    # Check finding details
    assert ctx["finding"]["finding_id"] == "FINDING-001"
    assert ctx["finding"]["cve_id"] == "CVE-2023-38545"

    # Check asset details
    assert ctx["asset"]["asset_id"] == "ASSET-001"
    assert ctx["asset"]["hostname"] == "api-gw-prod-01.aegis.internal"
    assert "compensating_controls" in ctx["asset"]

    # Check assessment details
    assert ctx["assessment"]["environmental_risk_score"] > 0.0
    assert ctx["assessment"]["aegis_decision"] in {"ACT", "ATTEND", "PLAN", "TRACK"}


def test_get_finding_context_nonexistent(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify that get_finding_context returns None for invalid finding ID."""
    ctx = get_finding_context("NONEXISTENT-999", benchmark_findings, cmdb_assets, benchmark_assessments)
    assert ctx is None


# ==============================================================================
# 5. Error Handling Tests
# ==============================================================================


def test_missing_files_error_handling(tmp_path):
    """Verify that missing files raise FileNotFoundError."""
    nonexistent = tmp_path / "does_not_exist.json"

    with pytest.raises(FileNotFoundError, match="Enterprise CMDB file not found"):
        load_cmdb_assets(nonexistent)

    with pytest.raises(FileNotFoundError, match="Benchmark scans file not found"):
        load_benchmark_findings(nonexistent)


def test_malformed_json_error_handling(tmp_path):
    """Verify that malformed JSON raises ValueError."""
    bad_json_file = tmp_path / "bad.json"
    bad_json_file.write_text("{ not valid json", encoding="utf-8")

    with pytest.raises(ValueError, match="Malformed JSON"):
        load_cmdb_assets(bad_json_file)

    with pytest.raises(ValueError, match="Malformed JSON"):
        load_benchmark_findings(bad_json_file)


def test_invalid_schema_records_error_handling(tmp_path):
    """Verify that invalid schema records raise ValueError."""
    bad_record_file = tmp_path / "bad_schema.json"
    bad_record_file.write_text(json.dumps([{"invalid_field": 123}]), encoding="utf-8")

    with pytest.raises(ValueError, match="validation error"):
        load_cmdb_assets(bad_record_file)

    with pytest.raises(ValueError, match="validation error"):
        load_benchmark_findings(bad_record_file)


def test_evaluate_risks_unknown_asset_error(benchmark_findings):
    """Verify that evaluate_benchmark_risks raises ValueError if an asset is not found."""
    empty_assets = {}
    with pytest.raises(ValueError, match="references unknown asset"):
        evaluate_benchmark_risks(benchmark_findings, empty_assets)
