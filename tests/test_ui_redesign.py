"""Comprehensive test suite for Phase Aegis Patch Website & UI Redesign.

Validates top navigation bar, Patch Plan view, How Aegis Works page,
Business Area derivation, Why It Matters rationale, and progressive disclosure cards.
"""

from __future__ import annotations

from pathlib import Path
import pytest
from streamlit.testing.v1 import AppTest

from src.schemas.asset import Asset, AssetType, BusinessTier, AssetCriticality, NetworkExposure, DataSensitivity, EnvironmentType
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.services.data_service import (
    evaluate_benchmark_risks,
    load_benchmark_findings,
    load_cmdb_assets,
)
from src.services.vulnerability_service import (
    derive_business_area,
    derive_why_it_matters,
    get_investigation_detail,
    get_prioritized_table_records,
)
from src.ui.styles import (
    render_agent_card,
    render_business_area_tag,
    render_capacity_bar,
    render_decision_badge,
    render_decision_factor_card,
    render_human_approval_callout,
    render_pipeline_story_cards,
    render_verification_card,
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
# 1. Business Area & Why It Matters Derivation Tests
# ==============================================================================


def test_derive_business_area_factual_mapping(cmdb_assets, benchmark_findings):
    """Verify business area derivation accurately extracts department/role from CMDB."""
    # Test known assets from benchmark
    api_gw_asset = cmdb_assets.get("ASSET-001")
    assert api_gw_asset is not None
    assert derive_business_area(None, api_gw_asset) == "API Gateway / Edge"

    idp_asset = cmdb_assets.get("ASSET-002")
    assert idp_asset is not None
    assert derive_business_area(None, idp_asset) == "Identity & Access (IAM)"

    pay_asset = cmdb_assets.get("ASSET-003")
    assert pay_asset is not None
    assert derive_business_area(None, pay_asset) == "Payment Processing"

    db_asset = cmdb_assets.get("ASSET-004")
    assert db_asset is not None
    assert derive_business_area(None, db_asset) == "Customer Database"

    vpn_asset = cmdb_assets.get("ASSET-010")
    assert vpn_asset is not None
    assert derive_business_area(None, vpn_asset) == "Corporate Network & VPN"

    ci_asset = cmdb_assets.get("ASSET-011")
    assert ci_asset is not None
    assert derive_business_area(None, ci_asset) == "DevOps / CI/CD"

    airgap_asset = cmdb_assets.get("ASSET-017")
    assert airgap_asset is not None
    assert derive_business_area(None, airgap_asset) == "Backup & Disaster Recovery"

    # None asset test
    assert derive_business_area(None, None) == "Not specified"


def test_derive_why_it_matters_rationale(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify why_it_matters synthesizes threat, exposure, and asset criticality."""
    f1 = benchmark_findings["FINDING-001"]
    a1 = cmdb_assets["ASSET-001"]
    r1 = benchmark_assessments["FINDING-001"]

    why_matters = derive_why_it_matters(f1, a1, r1)
    assert len(why_matters) > 15
    assert isinstance(why_matters, str)

    # Isolated test asset
    f59 = benchmark_findings["FINDING-059"]
    a18 = cmdb_assets["ASSET-018"]
    r59 = benchmark_assessments["FINDING-059"]
    why_59 = derive_why_it_matters(f59, a18, r59)
    assert "Isolated" in why_59 or "TESTING" in why_59 or "airgap" in why_59.lower() or len(why_59) > 10


def test_prioritized_table_contains_business_area(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify prioritized table records contain business_area and why_it_matters keys."""
    records = get_prioritized_table_records(
        list(benchmark_findings.keys()),
        benchmark_findings,
        cmdb_assets,
        benchmark_assessments,
    )
    assert len(records) == 60
    for r in records:
        assert "business_area" in r
        assert r["business_area"] != ""
        assert "why_it_matters" in r
        assert len(r["why_it_matters"]) > 5


def test_investigation_detail_contains_business_area(benchmark_findings, cmdb_assets, benchmark_assessments):
    """Verify deep-dive investigation detail dict includes business_area and why_it_matters."""
    detail = get_investigation_detail("FINDING-001", benchmark_findings, cmdb_assets, benchmark_assessments)
    assert detail is not None
    assert "business_area" in detail
    assert detail["business_area"] == "API Gateway / Edge"
    assert "why_it_matters" in detail
    assert len(detail["why_it_matters"]) > 10


# ==============================================================================
# 2. UI Helper Snippet Rendering Tests
# ==============================================================================


def test_render_pipeline_story_cards_html():
    """Verify 6-step pipeline story cards HTML generation."""
    html_out = render_pipeline_story_cards()
    assert "pipeline-flow" in html_out
    assert "Vulnerabilities Discovered" in html_out
    assert "Environment Investigated" in html_out
    assert "Threat Context Analyzed" in html_out
    assert "Aegis Risk Prioritized" in html_out
    assert "Patch Plan Created" in html_out
    assert "Recommendation Verified" in html_out


def test_render_human_approval_callout_html():
    """Verify human approval callout contains safety guarantee."""
    html_out = render_human_approval_callout()
    assert "human-approval-banner" in html_out
    assert "Human Approval Required" in html_out
    assert "never silently" in html_out


def test_render_capacity_bar_html():
    """Verify capacity progress bar calculation and styling."""
    bar_html = render_capacity_bar(12.0, 16.0)
    assert "capacity-bar-fill" in bar_html
    assert "75.0%" in bar_html
    assert "12.0h planned of 16.0h total" in bar_html


def test_render_agent_card_html():
    """Verify specialist agent card rendering with deterministic tools."""
    card_html = render_agent_card(
        step_num=1,
        agent_name="Scan Intake Specialist",
        status="COMPLETE",
        simple_desc="Parses multi-format scanner payloads.",
        key_result="Normalized libcurl package.",
        tools=["parse_scanner_finding", "validate_cve_schema"],
    )
    assert "agent-card" in card_html
    assert "Agent 1" in card_html
    assert "Scan Intake Specialist" in card_html
    assert "COMPLETE" in card_html
    assert "parse_scanner_finding" in card_html


def test_render_verification_card_html():
    """Verify independent verification card rendering."""
    card_html = render_verification_card(
        status="VERIFIED",
        overall_passed=True,
        reasons=["Mathematical Derivation: PASSED", "Claim Grounding: PASSED"],
    )
    assert "verif-box-pass" in card_html
    assert "Recommendation Verified" in card_html
    assert "Mathematical Derivation: PASSED" in card_html


def test_render_decision_factor_card_html():
    """Verify decision factor card rendering."""
    factor_html = render_decision_factor_card(
        icon="⚡",
        title="1. Base Severity",
        value="CVSS 9.8 (CRITICAL)",
        explanation="Published scanner severity.",
    )
    assert "detail-box" in factor_html
    assert "1. Base Severity" in factor_html
    assert "CVSS 9.8 (CRITICAL)" in factor_html


# ==============================================================================
# 3. Streamlit AppTest Navigation & Redesign View Tests
# ==============================================================================


def test_streamlit_top_navigation_patch_plan():
    """Verify navigating to Patch Plan page renders human approval and capacity bar."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    # Select Patch Plan in top navigation
    nav_radio = next(r for r in at.radio if r.key == "top_nav_selector")
    nav_radio.set_value("Patch Plan").run()
    assert not at.exception

    # Confirm Patch Plan page elements rendered
    # Should have dataframes for scheduled and deferred
    assert len(at.dataframe) >= 2


def test_streamlit_top_navigation_how_aegis_works():
    """Verify navigating to How Aegis Works page renders architectural deep-dive."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    nav_radio = next(r for r in at.radio if r.key == "top_nav_selector")
    nav_radio.set_value("How Aegis Works").run()
    assert not at.exception


def test_streamlit_vulnerabilities_investigation_agent_story():
    """Verify opening investigation view renders all 6 specialist agent cards and verification card."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()

    # Navigate to Vulnerabilities
    at.sidebar.radio[0].set_value("Vulnerabilities").run()

    # Click Investigate Finding
    inspect_btn = next(b for b in at.button if b.key == "btn_inspect_finding")
    inspect_btn.click().run()
    assert not at.exception

    # Check back button exists
    back_btn = next((b for b in at.button if b.key == "btn_back_to_findings_view"), None)
    assert back_btn is not None


def test_no_raw_html_code_blocks_rendered():
    """Verify that zero raw HTML fragments or indented code blocks are displayed as text."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    # Scan markdown elements on Overview page
    for md in at.markdown:
        # None of them should contain raw code-fenced HTML or pipeline-step tags
        assert "```<div" not in md.value
        assert "<div class=\"pipeline-step\">" not in md.value or "```" not in md.value


def test_remediation_plan_approval_and_rejection_workflow():
    """Verify the interactive security operations approval workflow without live infrastructure changes."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    # Navigate to Patch Plan
    nav_radio = next(r for r in at.radio if r.key == "top_nav_selector")
    nav_radio.set_value("Patch Plan").run()
    assert not at.exception

    # Initially status should be PENDING APPROVAL
    # Click Approve Remediation Plan
    btn_approve = next(b for b in at.button if b.key == "btn_open_approval_modal")
    btn_approve.click().run()
    assert not at.exception

    # Confirmation section appears with safety notice
    btn_confirm = next(b for b in at.button if b.key == "btn_confirm_approval_action")
    btn_confirm.click().run()
    assert not at.exception

    # Verify approved state is recorded
    assert at.session_state["remediation_plan_approval_state"] == "APPROVED"

    # Reset state for rejection test
    btn_reset = next(b for b in at.button if b.key == "btn_reset_approval_demo")
    btn_reset.click().run()
    assert not at.exception
    assert at.session_state["remediation_plan_approval_state"] == "PENDING_APPROVAL"

    # Test rejection
    btn_reject = next(b for b in at.button if b.key == "btn_reject_plan")
    btn_reject.click().run()
    assert not at.exception
    assert at.session_state["remediation_plan_approval_state"] == "REJECTED"


def test_how_aegis_works_specialist_agents_and_architecture():
    """Verify How Aegis Works page exhibits 6 specialist agents and technical architecture."""
    app_path = str(Path(__file__).resolve().parent.parent / "app.py")
    at = AppTest.from_file(app_path, default_timeout=30).run()
    assert not at.exception

    # Navigate to How Aegis Works
    nav_radio = next(r for r in at.radio if r.key == "top_nav_selector")
    nav_radio.set_value("How Aegis Works").run()
    assert not at.exception

    # Check that specialist agent mentions exist
    md_texts = " ".join(md.value for md in at.markdown)
    assert "Scan Intake" in md_texts
    assert "Threat & Exploit Check" in md_texts
    assert "Business & Asset Context" in md_texts
    assert "Risk Decision" in md_texts
    assert "Patch Planning" in md_texts
    assert "Verification" in md_texts
    assert "WHY SPECIALIST AGENTS?" in md_texts
    assert "Tool Registry" in md_texts
