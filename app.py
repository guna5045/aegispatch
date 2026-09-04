"""Aegis Patch — Streamlit Web Application Entry Point.

Phase 4B: Professional Security Dashboard & Risk Visualizations.
Connects real Phase 2 synthetic benchmark datasets to the Phase 3 deterministic risk engine.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

import pandas as pd
import streamlit as st

from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
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
    get_finding_context,
    load_benchmark_findings,
    load_cmdb_assets,
)
from src.services.scenario_service import (
    get_scenario_comparison_a,
    get_scenario_comparison_b,
    get_scenario_comparison_c,
    get_scenario_comparison_d,
    get_scenario_comparison_e,
)
from src.services.vulnerability_service import (
    filter_vulnerabilities,
    get_investigation_detail,
    get_prioritized_table_records,
    search_findings,
)
from src.ui.dashboard_views import (
    create_decision_chart,
    create_ers_bands_chart,
    create_severity_chart,
)
from src.ui.scenario_views import (
    render_scenario_a_view,
    render_scenario_b_view,
    render_scenario_c_view,
    render_scenario_d_view,
    render_scenario_e_view,
    render_scenario_header,
    render_what_if_capacity_view,
)
from src.ui.styles import (
    SOC_CSS,
    render_context_callout,
    render_decision_badge,
    render_filter_counter,
    render_metric_card,
    render_scheduled_badge,
    render_severity_badge,
    render_status_pill,
    render_threat_badge,
)
from src.ui.vulnerability_views import render_vulnerability_investigation_view

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis_patch.app")

# Streamlit page configuration
st.set_page_config(
    page_title="Aegis Patch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Inject custom enterprise light CSS styles
st.markdown(SOC_CSS, unsafe_allow_html=True)


@st.cache_data(show_spinner="Loading enterprise benchmark datasets...")
def get_cached_data() -> Tuple[
    Optional[Dict[str, VulnerabilityFinding]],
    Optional[Dict[str, Asset]],
    Optional[Dict[str, RiskAssessment]],
    Optional[str],
]:
    """Load benchmark datasets and compute Phase 3 risk assessments with caching."""
    try:
        findings = load_benchmark_findings()
        assets = load_cmdb_assets()
        assessments = evaluate_benchmark_risks(findings, assets)
        return findings, assets, assessments, None
    except Exception as exc:
        logger.error(f"Failed to load datasets or evaluate risk: {exc}", exc_info=True)
        return None, None, None, str(exc)


def render_sidebar(findings_count: int, assets_count: int, is_operational: bool) -> str:
    """Render the sidebar navigation, system status badges, and application metadata."""
    with st.sidebar:
        st.markdown("## Aegis Patch")
        st.caption("Context-Driven Vulnerability Prioritization")
        st.markdown("---")

        # System Status Indicators with accessible text + symbol
        st.markdown("### System Status")
        col_status1, col_status2 = st.columns(2)
        with col_status1:
            engine_status_html = (
                render_status_pill("Operational", "operational")
                if is_operational
                else render_status_pill("Degraded", "neutral")
            )
            st.markdown(f"**Risk Engine**<br>{engine_status_html}", unsafe_allow_html=True)
        with col_status2:
            data_status_html = (
                render_status_pill("Loaded", "loaded")
                if findings_count > 0
                else render_status_pill("Missing", "neutral")
            )
            st.markdown(f"**Benchmark Dataset**<br>{data_status_html}", unsafe_allow_html=True)

        st.markdown("---")

        # Navigation Foundation
        st.markdown("### Navigation")
        page = st.radio(
            "Select View",
            options=["Overview", "Vulnerabilities", "Scenarios"],
            index=0,
            label_visibility="collapsed",
        )

        st.markdown("---")
        st.caption("Phase 4 • Security Dashboard & Scenario Explorer")
        st.caption("Deterministic Environmental Risk Engine")

    return page


def render_overview_page(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the executive security dashboard for Aegis Patch."""
    # Header & Product Positioning
    st.title("Aegis Patch")
    st.subheader("Context-Driven Vulnerability Prioritization and Remediation Orchestration")
    st.markdown(
        """
        Aegis Patch determines which vulnerabilities are most dangerous in a specific enterprise environment
        by combining vulnerability severity, threat intelligence, asset context, and compensating controls.
        """
    )

    # --------------------------------------------------------------------------
    # 1. Dashboard Filters
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Dashboard Filters</h3>
            <div class="section-subtitle">Filter findings across vulnerability severity, Aegis decision, asset environment, and criticality</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_f1, col_f2, col_f3, col_f4 = st.columns(4)
    with col_f1:
        sel_severity = st.selectbox(
            "Vulnerability Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            help="Filter by base CVSS vulnerability severity.",
        )
    with col_f2:
        sel_decision = st.selectbox(
            "Aegis Decision",
            options=["All", "ACT", "ATTEND", "PLAN", "TRACK"],
            index=0,
            help="Filter by deterministic Aegis Patch decision band.",
        )
    with col_f3:
        sel_env = st.selectbox(
            "Asset Environment",
            options=["All", "PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING"],
            index=0,
            help="Filter by deployment lifecycle environment.",
        )
    with col_f4:
        sel_crit = st.selectbox(
            "Asset Criticality",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            help="Filter by asset business criticality.",
        )

    # Compute filtered subset
    filtered_ids = filter_findings(
        findings=findings,
        assets=assets,
        assessments=assessments,
        severity=sel_severity,
        decision=sel_decision,
        environment=sel_env,
        criticality=sel_crit,
    )

    st.markdown(render_filter_counter(len(filtered_ids), len(findings)), unsafe_allow_html=True)
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # Handle zero-findings state safely
    if len(filtered_ids) == 0:
        st.info("No findings match the current filters. Please adjust filter selections above.")
        return

    # --------------------------------------------------------------------------
    # 2. Executive KPI Section
    # --------------------------------------------------------------------------
    st.markdown(
        '<div class="section-header"><h3 class="section-title">Executive Summary</h3></div>',
        unsafe_allow_html=True,
    )

    kpis = compute_dashboard_kpis(filtered_ids, findings, assets, assessments)

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            render_metric_card(
                "Findings Analyzed",
                str(kpis["findings_analyzed"]),
                "Scoped benchmark findings",
            ),
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            render_metric_card(
                "Assets Affected",
                str(kpis["assets_affected"]),
                "Unique enterprise hosts impacted",
            ),
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            render_metric_card(
                "Critical Severity",
                str(kpis["critical_severity_count"]),
                "Base severity = CRITICAL",
            ),
            unsafe_allow_html=True,
        )
    with col4:
        st.markdown(
            render_metric_card(
                "Priority Findings",
                str(kpis["priority_findings_count"]),
                "Aegis Decision: ACT + ATTEND",
            ),
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            render_metric_card(
                "Average ERS",
                f"{kpis['average_ers']} / 100",
                "Environmental Risk Score mean",
            ),
            unsafe_allow_html=True,
        )

    # --------------------------------------------------------------------------
    # 3. Decision Distribution vs. Severity Distribution (Side-by-Side)
    # --------------------------------------------------------------------------
    col_chart_left, col_chart_right = st.columns(2)

    with col_chart_left:
        st.markdown(
            """
            <div class="section-header">
                <h3 class="section-title">Aegis Patch Decision Distribution</h3>
                <div class="section-subtitle">Decision categories derived from the Aegis Patch environmental risk model</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        decision_counts = compute_decision_distribution(filtered_ids, assessments)
        dec_chart = create_decision_chart(decision_counts)
        st.altair_chart(dec_chart, width="stretch")

    with col_chart_right:
        st.markdown(
            """
            <div class="section-header">
                <h3 class="section-title">Vulnerability Severity Distribution</h3>
                <div class="section-subtitle">Base severity of findings before environmental prioritization</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        severity_counts = compute_severity_distribution(filtered_ids, findings)
        sev_chart = create_severity_chart(severity_counts)
        st.altair_chart(sev_chart, width="stretch")

    # --------------------------------------------------------------------------
    # 4. Environmental Risk Overview (ERS Decision Bands)
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Environmental Risk Overview</h3>
            <div class="section-subtitle">Findings distribution across Aegis Patch benchmark ERS score bands</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ers_counts = compute_ers_distribution(filtered_ids, assessments)
    ers_chart = create_ers_bands_chart(ers_counts)
    st.altair_chart(ers_chart, width="stretch")

    # --------------------------------------------------------------------------
    # 5. Context Changes Priority (Core Differentiator Callout)
    # --------------------------------------------------------------------------
    st.markdown(
        render_context_callout(
            "Context Changes Priority",
            "Aegis Patch does not treat CVSS as the final priority. It evaluates vulnerability severity alongside "
            "threat evidence, asset criticality, network exposure, data sensitivity, and compensating controls to "
            "determine environmental risk. High-CVSS vulnerabilities on isolated test systems are deprioritized, "
            "while moderate vulnerabilities on exposed mission-critical infrastructure are elevated.",
        ),
        unsafe_allow_html=True,
    )

    # --------------------------------------------------------------------------
    # 6. Assets with Highest-Risk Findings
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Assets with Highest-Risk Findings</h3>
            <div class="section-subtitle">Enterprise assets ranked by maximum Environmental Risk Score (ERS) among hosted findings</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    ranked_assets = aggregate_assets_by_risk(filtered_ids, findings, assets, assessments)

    # Render compact asset risk table
    asset_headers = ["Asset ID", "Hostname", "Environment", "Criticality", "Findings", "Highest ERS", "ACT", "ATTEND"]
    asset_cols = st.columns([1.5, 2.5, 1.5, 1.5, 1.0, 1.2, 0.8, 1.0])
    for col, h in zip(asset_cols, asset_headers):
        col.markdown(f"<span style='color: #475569; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;'>{h}</span>", unsafe_allow_html=True)

    st.markdown("<hr style='border-color: #e2e8f0; margin: 4px 0 8px 0;'>", unsafe_allow_html=True)

    for a_row in ranked_assets[:8]:
        row_cols = st.columns([1.5, 2.5, 1.5, 1.5, 1.0, 1.2, 0.8, 1.0])
        row_cols[0].markdown(f"`{a_row['asset_id']}`")
        row_cols[1].markdown(f"**{a_row['hostname']}**")
        row_cols[2].markdown(f"{a_row['environment']}")
        row_cols[3].markdown(f"{a_row['criticality']}")
        row_cols[4].markdown(f"{a_row['findings_count']}")
        row_cols[5].markdown(f"<strong style='color: #1d4ed8;'>{a_row['highest_ers']}</strong>", unsafe_allow_html=True)
        row_cols[6].markdown(f"{a_row['act_count']}")
        row_cols[7].markdown(f"{a_row['attend_count']}")

    # --------------------------------------------------------------------------
    # 7. Priority Preview (Top 5 Findings)
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Priority Preview</h3>
            <div class="section-subtitle">Top 5 highest Environmental Risk Score (ERS) findings in the current scope</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    top_5 = get_priority_preview(filtered_ids, findings, assets, assessments, limit=5)

    headers = ["Finding ID", "CVE ID", "Target Asset", "Severity", "CVSS Base", "ERS Score", "Aegis Decision", "Risk Tier"]
    header_cols = st.columns([1.5, 1.8, 2.2, 1.2, 1.0, 1.2, 1.4, 1.2])
    for col, h in zip(header_cols, headers):
        col.markdown(f"<span style='color: #475569; font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em;'>{h}</span>", unsafe_allow_html=True)

    st.markdown("<hr style='border-color: #e2e8f0; margin: 4px 0 10px 0;'>", unsafe_allow_html=True)

    for item in top_5:
        row_cols = st.columns([1.5, 1.8, 2.2, 1.2, 1.0, 1.2, 1.4, 1.2])
        row_cols[0].markdown(f"`{item['finding_id']}`")
        row_cols[1].markdown(f"**{item['cve_id']}**")
        row_cols[2].markdown(f"{item['hostname']} (`{item['asset_id']}`)")
        row_cols[3].markdown(f"{item['severity']}")
        row_cols[4].markdown(f"{item['cvss_score']}")
        row_cols[5].markdown(f"<strong style='color: #1d4ed8;'>{item['environmental_risk_score']}</strong>", unsafe_allow_html=True)
        row_cols[6].markdown(render_decision_badge(item["aegis_decision"]), unsafe_allow_html=True)
        row_cols[7].markdown(f"**{item['risk_tier']}**")

    # --------------------------------------------------------------------------
    # 8. Asset Context Deep Dive
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Asset Context Deep Dive</h3>
            <div class="section-subtitle">Select any finding to inspect its environmental asset context and risk breakdown</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    finding_options = sorted(filtered_ids, key=lambda fid: int(fid.replace("FINDING-", "")))
    selected_finding_id = st.selectbox(
        "Select Vulnerability Finding",
        options=finding_options,
        format_func=lambda fid: f"{fid} — {findings[fid].cve_id} ({findings[fid].title})",
        help="Select a finding to inspect real CMDB context and risk factors.",
    )

    if selected_finding_id:
        context = get_finding_context(selected_finding_id, findings, assets, assessments)
        if context:
            f_data = context["finding"]
            a_data = context["asset"]
            r_data = context["assessment"]

            col_detail_left, col_detail_right = st.columns([1.2, 1])

            with col_detail_left:
                st.markdown("#### Finding & Asset Context")

                # Finding details
                st.markdown(
                    f"""
                    <div class="detail-box">
                        <div class="detail-label">Vulnerability Finding</div>
                        <div class="detail-val">{f_data['finding_id']} • {f_data['cve_id']}</div>
                        <p style="color: #334155; font-size: 0.85rem; margin-top: 6px;">{f_data['title']}</p>
                        <div style="font-size: 0.8rem; color: #475569; margin-top: 8px;">
                            <strong>Package:</strong> {f_data['affected_package']} &nbsp;|&nbsp;
                            <strong>Installed:</strong> {f_data['installed_version']} &nbsp;|&nbsp;
                            <strong>Fixed:</strong> {f_data['fixed_version']} &nbsp;|&nbsp;
                            <strong>CVSS:</strong> {f_data['cvss_score']} ({f_data['severity']})
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

                # Asset details
                if a_data:
                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown(
                            f"""
                            <div class="detail-box">
                                <div class="detail-label">Asset Identifier & Hostname</div>
                                <div class="detail-val">{a_data['asset_id']}</div>
                                <div style="font-size: 0.85rem; color: #475569;">{a_data['hostname']}</div>
                                <div style="margin-top: 10px;">
                                    <div class="detail-label">Asset Type & Business Tier</div>
                                    <div class="detail-val">{a_data['asset_type']} • {a_data['business_tier']}</div>
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )
                    with c2:
                        st.markdown(
                            f"""
                            <div class="detail-box">
                                <div class="detail-label">Criticality & Exposure</div>
                                <div class="detail-val">{a_data['criticality']} • {a_data['network_exposure']}</div>
                                <div style="margin-top: 10px;">
                                    <div class="detail-label">Data Sensitivity & Environment</div>
                                    <div class="detail-val">{a_data['data_sensitivity']} • {a_data['environment']}</div>
                                </div>
                            </div>
                            """,
                            unsafe_allow_html=True,
                        )

                    # Compensating controls
                    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
                    st.markdown("**Compensating Controls:**")
                    if a_data["compensating_controls"]:
                        controls_html = "".join(
                            [
                                f'<span class="control-tag">🛡️ {c["name"]} ({c["status"]})</span>'
                                for c in a_data["compensating_controls"]
                            ]
                        )
                        st.markdown(controls_html, unsafe_allow_html=True)
                    else:
                        st.markdown("<span style='color: #64748b; font-size: 0.85rem;'>None configured</span>", unsafe_allow_html=True)

            with col_detail_right:
                st.markdown("#### Risk Assessment Breakdown")
                if r_data:
                    st.markdown(
                        f"""
                        <div class="detail-box">
                            <div class="detail-label">Environmental Risk Score (ERS)</div>
                            <div class="detail-val" style="font-size: 2.2rem; color: #1d4ed8;">{r_data['environmental_risk_score']} / 100.0</div>
                            <div style="margin-top: 8px;">
                                <span class="detail-label">Aegis Decision:</span> {render_decision_badge(r_data['aegis_decision'])}
                                &nbsp;&nbsp;
                                <span class="detail-label">Risk Tier:</span> <strong>{r_data['risk_tier']}</strong>
                            </div>
                            <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                            <div style="font-size: 0.82rem; color: #334155; line-height: 1.6;">
                                <div><strong>Base Score (B = CVSS × 10):</strong> {r_data['base_score']}</div>
                                <div><strong>Threat Score (T):</strong> {r_data['threat_score']}</div>
                                <div><strong>Environmental Score (E):</strong> {r_data['environmental_score']}</div>
                                <div><strong>Control Multiplier (M_control):</strong> {r_data['control_multiplier']}</div>
                                <div><strong>Operational Triage:</strong> {r_data['remediation_decision']}</div>
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )


def render_vulnerabilities_page(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the full vulnerability prioritization table and investigation experience."""
    st.session_state.setdefault("selected_finding_id", None)

    # --------------------------------------------------------------------------
    # 1. Deep-Dive Investigation View (if a finding is selected)
    # --------------------------------------------------------------------------
    if st.session_state["selected_finding_id"]:
        detail = get_investigation_detail(
            st.session_state["selected_finding_id"],
            findings,
            assets,
            assessments,
        )
        if detail:
            render_vulnerability_investigation_view(
                detail,
                on_back_clicked=lambda: st.session_state.update({"selected_finding_id": None}),
            )
            return
        else:
            st.session_state["selected_finding_id"] = None

    # --------------------------------------------------------------------------
    # 2. Prioritization Queue Header
    # --------------------------------------------------------------------------
    st.title("Aegis Patch — Vulnerabilities")
    st.subheader("Vulnerability Prioritization & Investigation")
    st.markdown(
        """
        Prioritize enterprise vulnerability findings using the deterministic Aegis Patch Environmental
        Risk Score (ERS). Filter across security and operational dimensions, inspect ranked findings,
        and select any vulnerability to open its full contextual investigation deep-dive.
        """
    )

    # --------------------------------------------------------------------------
    # 3. Filters & Search Section
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Vulnerability Filters & Search</h3>
            <div class="section-subtitle">Multi-criteria filtering across scanner findings, environmental scope, and risk decisions</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Reset filter callback
    def _reset_vuln_filters() -> None:
        st.session_state["vuln_search_input"] = ""
        st.session_state["vuln_sev_select"] = "All"
        st.session_state["vuln_dec_select"] = "All"
        st.session_state["vuln_tier_select"] = "All"
        st.session_state["vuln_env_select"] = "All"
        st.session_state["vuln_crit_select"] = "All"

    # Search bar and Reset button
    col_search, col_reset = st.columns([4, 1])
    with col_search:
        search_query = st.text_input(
            "Search Findings",
            placeholder="Search by CVE ID, Finding ID, package name, asset ID, or target hostname...",
            key="vuln_search_input",
            help="Case-insensitive text search across finding identifiers, CVEs, package names, and hostnames.",
        )

    with col_reset:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        st.button(
            "Reset Filters",
            key="btn_reset_vuln_filters",
            on_click=_reset_vuln_filters,
            use_container_width=True,
        )

    # Dropdown filters
    f_col1, f_col2, f_col3, f_col4, f_col5 = st.columns(5)
    with f_col1:
        sel_sev = st.selectbox(
            "Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="vuln_sev_select",
            help="Filter by intrinsic CVSS severity.",
        )

    with f_col2:
        sel_dec = st.selectbox(
            "Aegis Decision",
            options=["All", "ACT", "ATTEND", "PLAN", "TRACK"],
            key="vuln_dec_select",
            help="Filter by Aegis Patch decision band.",
        )

    with f_col3:
        sel_tier = st.selectbox(
            "Risk Tier",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="vuln_tier_select",
            help="Filter by environmental risk severity tier.",
        )

    with f_col4:
        sel_env = st.selectbox(
            "Environment",
            options=["All", "PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING"],
            key="vuln_env_select",
            help="Filter by asset deployment environment.",
        )

    with f_col5:
        sel_crit = st.selectbox(
            "Asset Criticality",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="vuln_crit_select",
            help="Filter by asset business criticality.",
        )

    # Apply multi-criteria filtering
    filtered_ids = filter_vulnerabilities(
        findings=findings,
        assets=assets,
        assessments=assessments,
        query=search_query,
        severity=sel_sev,
        decision=sel_dec,
        risk_tier=sel_tier,
        environment=sel_env,
        criticality=sel_crit,
    )

    # Dynamic filter count indicator
    st.markdown(render_filter_counter(len(filtered_ids), len(findings)), unsafe_allow_html=True)
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # --------------------------------------------------------------------------
    # 4. Scoped Summary KPIs
    # --------------------------------------------------------------------------
    total_scoped = len(filtered_ids)
    priority_count = sum(
        1
        for fid in filtered_ids
        if assessments.get(fid)
        and assessments[fid].calculation_metadata.get(
            "aegis_decision", assessments[fid].decision.value
        ).upper()
        in ("ACT", "ATTEND")
    )
    crit_count = sum(
        1 for fid in filtered_ids if findings[fid].severity.value.upper() == "CRITICAL"
    )
    unique_assets = len(set(findings[fid].asset_id for fid in filtered_ids))

    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    with kpi1:
        st.markdown(
            render_metric_card("Findings Scoped", str(total_scoped), "Current matching findings"),
            unsafe_allow_html=True,
        )
    with kpi2:
        st.markdown(
            render_metric_card(
                "Priority Findings",
                str(priority_count),
                "Decision ACT or ATTEND",
            ),
            unsafe_allow_html=True,
        )
    with kpi3:
        st.markdown(
            render_metric_card(
                "Critical Severity",
                str(crit_count),
                "Base severity = CRITICAL",
            ),
            unsafe_allow_html=True,
        )
    with kpi4:
        st.markdown(
            render_metric_card(
                "Assets Impacted",
                str(unique_assets),
                "Unique affected hosts",
            ),
            unsafe_allow_html=True,
        )

    # Zero-findings state handling
    if total_scoped == 0:
        st.info("No findings match the current filter criteria. Adjust or reset your filters above.")
        return

    # --------------------------------------------------------------------------
    # 5. Prioritized Findings Queue Table & Deep-Dive Selector
    # --------------------------------------------------------------------------
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Prioritized Findings Queue</h3>
            <div class="section-subtitle">Ranked by Environmental Risk Score (ERS) with contextual tie-breaking</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    records = get_prioritized_table_records(
        finding_ids=filtered_ids,
        findings=findings,
        assets=assets,
        assessments=assessments,
        sort_by="ERS",
        sort_desc=True,
    )

    # Finding investigation action row
    col_pick, col_action = st.columns([3.5, 1.2])
    with col_pick:
        inspect_options = [r["finding_id"] for r in records]
        chosen_id = st.selectbox(
            "Select Finding to Investigate",
            options=inspect_options,
            format_func=lambda fid: (
                f"#{next(r['priority_rank'] for r in records if r['finding_id'] == fid)}: "
                f"{fid} — {findings[fid].cve_id} (ERS {assessments[fid].environmental_risk_score:.2f} • "
                f"{assessments[fid].calculation_metadata.get('aegis_decision', assessments[fid].decision.value)} • "
                f"{assets[findings[fid].asset_id].hostname if findings[fid].asset_id in assets else 'Unknown'})"
            ),
            key="investigate_finding_select",
            help="Choose a vulnerability finding to open its full investigation report.",
        )
    with col_action:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button(
            "Investigate Finding",
            key="btn_inspect_finding",
            use_container_width=True,
        ):
            st.session_state["selected_finding_id"] = chosen_id
            st.rerun()

    # Formatted DataFrame presentation
    df_data = []
    for r in records:
        df_data.append(
            {
                "Rank": f"#{r['priority_rank']}",
                "Finding ID": r["finding_id"],
                "CVE ID": r["cve_id"],
                "Target Hostname": r["hostname"],
                "Environment": r["environment"],
                "Criticality": r["criticality"],
                "Severity": r["severity"],
                "CVSS": r["cvss_score"],
                "ERS Score": r["environmental_risk_score"],
                "Aegis Decision": r["aegis_decision"],
                "Risk Tier": r["risk_tier"],
            }
        )

    df = pd.DataFrame(df_data)

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Rank": st.column_config.TextColumn("Rank", width="small"),
            "Finding ID": st.column_config.TextColumn("Finding ID", width="small"),
            "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
            "Target Hostname": st.column_config.TextColumn("Target Hostname", width="medium"),
            "Environment": st.column_config.TextColumn("Env", width="small"),
            "Criticality": st.column_config.TextColumn("Crit", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
            "ERS Score": st.column_config.NumberColumn("ERS Score", format="%.2f", width="small"),
            "Aegis Decision": st.column_config.TextColumn("Aegis Decision", width="small"),
            "Risk Tier": st.column_config.TextColumn("Risk Tier", width="small"),
        },
    )


def render_scenarios_page(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the Scenario Explorer and What-If Patch Capacity Demonstration page."""
    render_scenario_header()

    scenario_options = [
        "Scenario A: Exposure & Criticality Inversion",
        "Scenario B: Threat Intelligence Differential",
        "Scenario C: Compensating Control Dampening",
        "Scenario D: Intra-Asset Hotspot Prioritization",
        "Scenario E: Cross-Asset Prevalent Vulnerability Spread",
        "What-If: Patch Capacity Simulation",
    ]

    selected_scenario = st.selectbox(
        "Select Scenario or Simulation",
        options=scenario_options,
        index=0,
        key="scenario_select_box",
        help="Choose a benchmark counterexample scenario or the interactive patch capacity planning simulation.",
    )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    if "Scenario A" in selected_scenario:
        comp_a = get_scenario_comparison_a(findings, assets, assessments)
        render_scenario_a_view(comp_a)
    elif "Scenario B" in selected_scenario:
        comp_b = get_scenario_comparison_b(findings, assets, assessments)
        render_scenario_b_view(comp_b)
    elif "Scenario C" in selected_scenario:
        comp_c = get_scenario_comparison_c(findings, assets, assessments)
        render_scenario_c_view(comp_c)
    elif "Scenario D" in selected_scenario:
        comp_d = get_scenario_comparison_d(findings, assets, assessments)
        render_scenario_d_view(comp_d)
    elif "Scenario E" in selected_scenario:
        comp_e = get_scenario_comparison_e(findings, assets, assessments)
        render_scenario_e_view(comp_e)
    elif "What-If" in selected_scenario:
        render_what_if_capacity_view(findings, assets, assessments)


def main() -> None:
    """Main application routine for Aegis Patch."""
    findings, assets, assessments, err_msg = get_cached_data()

    if err_msg or findings is None or assets is None or assessments is None:
        st.error(
            f"**Error Loading Aegis Patch Foundation:**\n\n"
            f"{err_msg or 'Benchmark datasets could not be resolved.'}\n\n"
            "Please ensure `data/synthetic/benchmark_60_scans.json` and "
            "`data/synthetic/enterprise_cmdb.json` exist."
        )
        render_sidebar(0, 0, is_operational=False)
        return

    # Render sidebar and get selected navigation page
    selected_page = render_sidebar(
        findings_count=len(findings),
        assets_count=len(assets),
        is_operational=True,
    )

    # Route navigation
    if selected_page == "Overview":
        render_overview_page(findings, assets, assessments)
    elif selected_page == "Vulnerabilities":
        render_vulnerabilities_page(findings, assets, assessments)
    elif selected_page == "Scenarios":
        render_scenarios_page(findings, assets, assessments)


if __name__ == "__main__":
    main()

