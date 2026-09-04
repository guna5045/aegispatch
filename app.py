"""Aegis Patch — Streamlit Web Application Entry Point.

Product UX Redesign: Enterprise SOC Presentation & Multi-Agent Orchestration Interface.
Connects real Phase 2 synthetic benchmark datasets to the Phase 3 deterministic risk engine
and Phase 9 specialist multi-agent architecture.
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
    derive_business_area,
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
    render_patch_plan_view,
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
    clean_html,
    render_agent_card,
    render_business_area_tag,
    render_capacity_bar,
    render_context_callout,
    render_decision_badge,
    render_filter_counter,
    render_human_approval_callout,
    render_metric_card,
    render_pipeline_story_cards,
    render_scheduled_badge,
    render_security_approval_callout,
    render_severity_badge,
    render_status_pill,
    render_threat_badge,
    render_verification_card,
)
from src.ui.vulnerability_views import render_vulnerability_investigation_view

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("aegis_patch.app")

# Streamlit page configuration
st.set_page_config(
    page_title="Aegis Patch — Vulnerability Prioritization",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
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


def render_top_header(current_page: str) -> str:
    """Render the enterprise top header and horizontal primary navigation bar."""
    st.markdown(
        """
        <div class="aegis-header">
            <div style="display: flex; align-items: center; gap: 14px;">
                <div style="font-size: 1.8rem;">🛡️</div>
                <div>
                    <div class="aegis-brand-title">
                        AEGIS PATCH
                    </div>
                    <div class="aegis-brand-subtitle">
                        Security Vulnerability Prioritization
                    </div>
                </div>
            </div>
            <div style="display: flex; align-items: center; gap: 10px; flex-wrap: wrap;">
                <span class="status-badge status-operational">● Risk Engine Operational</span>
                <span class="status-badge status-loaded">● Benchmark Data Ready</span>
                <span style="font-size: 0.78rem; color: #64748b; margin-left: 4px;">(60 Findings • 18 Hosts)</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Primary Navigation Options
    nav_options = ["Overview", "Vulnerabilities", "Patch Plan", "What If?", "How Aegis Works"]

    # Map aliases
    mapped_current = current_page
    if mapped_current == "Scenarios":
        mapped_current = "What If?"

    initial_idx = nav_options.index(mapped_current) if mapped_current in nav_options else 0

    selected = st.radio(
        "Application Navigation",
        options=nav_options,
        index=initial_idx,
        format_func=lambda opt: "Recommended Remediation Plan" if opt == "Patch Plan" else opt,
        horizontal=True,
        label_visibility="collapsed",
        key="top_nav_selector",
    )

    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)
    return selected


def render_sidebar(findings_count: int, assets_count: int, is_operational: bool) -> str:
    """Render the sidebar navigation for backwards compatibility and test accessibility."""
    with st.sidebar:
        st.markdown("## Aegis Patch")
        st.caption("Security Vulnerability Prioritization")
        st.markdown("---")

        # System Status Indicators
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

        # Navigation radio (includes 'Scenarios' alias for AppTest backwards compatibility)
        st.markdown("### Navigation")
        options = ["Overview", "Vulnerabilities", "Scenarios", "Patch Plan", "What If?", "How Aegis Works"]
        page = st.radio(
            "Select View",
            options=options,
            index=0,
            label_visibility="collapsed",
            key="sidebar_nav_radio",
        )

    return page



def render_overview_page(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the executive security dashboard for Aegis Patch."""
    st.title("Aegis Patch")
    st.subheader("Context-Driven Vulnerability Prioritization and Remediation Orchestration")
    st.markdown(
        clean_html("""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 24px; margin-bottom: 16px; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);">
            <div style="font-size: 1.4rem; font-weight: 800; color: #0f172a; margin-bottom: 6px;">
                Find the vulnerabilities that actually matter.
            </div>
            <div style="font-size: 0.94rem; color: #334155; line-height: 1.6; max-width: 980px;">
                Aegis Patch looks beyond vulnerability severity. It evaluates available threat evidence, the affected system, business importance, network exposure, sensitive data and existing security protection to recommend what should be addressed first.
            </div>
            <div style="font-size: 0.78rem; font-weight: 700; color: #64748b; text-transform: uppercase; letter-spacing: 0.04em; margin-top: 8px;">
                Context-Aware Vulnerability Prioritization & Remediation
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # 2. Visual 6-Step Workflow
    st.markdown(render_pipeline_story_cards(), unsafe_allow_html=True)
    st.markdown("<div style='height: 10px;'></div>", unsafe_allow_html=True)

    # 3. Dashboard Scoping Filters
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Dashboard Scope & Filters</h3>
            <div class="section-subtitle">Scope findings by intrinsic severity, Recommended Action, environment, and Business Importance</div>
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
            "Recommended Action",
            options=["All", "ACT", "ATTEND", "PLAN", "TRACK"],
            index=0,
            help="Filter by Recommended Action: Fix Immediately (ACT), Review Soon (ATTEND), Plan Fix (PLAN), Monitor (TRACK).",
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
            "Business Importance",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            index=0,
            help="Filter by asset business criticality tier.",
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

    # 4. Humanized Executive KPIs with honest zero handling
    kpis = compute_dashboard_kpis(filtered_ids, findings, assets, assessments)
    priority_count = kpis["priority_findings_count"]
    plan_count = sum(
        1 for fid in filtered_ids
        if assessments.get(fid)
        and assessments[fid].calculation_metadata.get("aegis_decision", assessments[fid].decision.value).upper() == "PLAN"
    )
    track_count = sum(
        1 for fid in filtered_ids
        if assessments.get(fid)
        and assessments[fid].calculation_metadata.get("aegis_decision", assessments[fid].decision.value).upper() == "TRACK"
    )

    col1, col2, col3, col4, col5 = st.columns(5)
    with col1:
        st.markdown(
            render_metric_card(
                "Vulnerabilities Found",
                str(kpis["findings_analyzed"]),
                "Findings evaluated across systems",
            ),
            unsafe_allow_html=True,
        )
    with col2:
        st.markdown(
            render_metric_card(
                "Systems Affected",
                str(kpis["assets_affected"]),
                "Unique hosts hosting findings",
            ),
            unsafe_allow_html=True,
        )
    with col3:
        st.markdown(
            render_metric_card(
                "Critical Vulnerabilities",
                str(kpis["critical_severity_count"]),
                "Intrinsic CVSS = CRITICAL",
            ),
            unsafe_allow_html=True,
        )
    with col4:
        p_caption = "No findings currently require immediate action" if priority_count == 0 else "Immediate remediation (ACT + ATTEND)"
        st.markdown(
            render_metric_card(
                "Highest-Priority Findings",
                str(priority_count),
                p_caption,
            ),
            unsafe_allow_html=True,
        )
    with col5:
        st.markdown(
            render_metric_card(
                "Average Aegis Risk",
                f"{kpis['average_ers']} / 100",
                "Contextual ERS mean across scope",
            ),
            unsafe_allow_html=True,
        )

    # Sub-KPI row for planning and monitoring distribution
    col_sub1, col_sub2 = st.columns(2)
    with col_sub1:
        st.markdown(
            f"""
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #1d4ed8; border-radius: 6px; padding: 10px 14px; font-size: 0.86rem; color: #1e293b;">
                📅 <strong>Findings Recommended for Planning:</strong> <strong style="color: #1d4ed8;">{plan_count}</strong>
                <span style="color: #64748b; font-size: 0.8rem; margin-left: 6px;">(Queue for scheduled maintenance window)</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with col_sub2:
        st.markdown(
            f"""
            <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #64748b; border-radius: 6px; padding: 10px 14px; font-size: 0.86rem; color: #1e293b;">
                👁️ <strong>Findings to Monitor:</strong> <strong style="color: #475569;">{track_count}</strong>
                <span style="color: #64748b; font-size: 0.8rem; margin-left: 6px;">(Safe for continuous operational tracking)</span>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # 5. "WHY AEGIS PATCH DOES MORE THAN CVSS" Factor Breakdown
    st.markdown(
        """
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px 22px; margin: 16px 0; box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);">
            <div style="font-size: 1.05rem; font-weight: 800; color: #0f172a; margin-bottom: 6px;">
                WHY AEGIS PATCH DOES MORE THAN CVSS
            </div>
            <div style="font-size: 0.88rem; color: #475569; line-height: 1.5; margin-bottom: 12px;">
                CVSS measures technical flaw severity in a vacuum. Aegis Patch adds threat evidence, enterprise topology, data sensitivity, and compensating controls to recommend the right action:
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 16px; font-size: 0.84rem; font-weight: 700; color: #1e293b;">
                <span>CVSS Severity</span>
                <span style="color: #94a3b8;">+</span>
                <span>Threat Evidence</span>
                <span style="color: #94a3b8;">+</span>
                <span>Business Importance</span>
                <span style="color: #94a3b8;">+</span>
                <span>Network Exposure</span>
                <span style="color: #94a3b8;">+</span>
                <span>Data Sensitivity</span>
                <span style="color: #94a3b8;">+</span>
                <span>Existing Security Protection</span>
                <span style="color: #1d4ed8;">=</span>
                <span style="color: #1d4ed8;">Aegis Risk Score</span>
                <span style="color: #15803d;">→</span>
                <span style="color: #15803d;">Recommended Action</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.expander("ℹ️ How Each Factor Influences Prioritization [i]"):
        st.markdown(
            """
            - **CVSS Severity [i]:** Intrinsic flaw severity published in CVE databases. Weighted at 25% of unmitigated risk ($B = \\text{CVSS} \\times 10.0$).
            - **Threat Evidence [i]:** Real-world exploitation activity. If listed in CISA KEV ($T = 100.0$); otherwise calculated from EPSS score and public exploit code ($T = \\text{EPSS} \\times 80 + \\text{PoC} \\times 20$). Weighted at 40%.
            - **Business Importance [i]:** How critical the affected system is to core operations (Mission-critical = 100.0 down to Low = 25.0).
            - **Network Exposure [i]:** Whether the system is Internet-facing (100.0), in a DMZ (70.0), internal (30.0), or air-gapped (0.0).
            - **Data Sensitivity [i]:** Data classification held on the host (Confidential/PII = 100.0 down to Public = 20.0).
            - **Existing Security Protection [i]:** Multiplicative discount ($M_{\\text{control}}$) applied for active controls (e.g. WAF, EDR, Network Segmentation).
            """
        )

    # 6. Priority Preview (Top Findings)
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Priority Preview: Top Findings</h3>
            <div class="section-subtitle">Highest Aegis Risk Score (ERS) findings requiring remediation attention</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    top_5 = get_priority_preview(filtered_ids, findings, assets, assessments, limit=5)

    headers = ["Priority", "Vulnerability", "Business Area", "Affected System", "Environment", "Severity", "CVSS", "Aegis Risk", "Recommended Action"]
    header_cols = st.columns([0.8, 1.8, 2.2, 2.0, 1.2, 1.0, 0.9, 1.1, 1.4])
    for col, h in zip(header_cols, headers):
        col.markdown(f"<span style='color: #475569; font-size: 0.76rem; font-weight: 700; text-transform: uppercase;'>{h}</span>", unsafe_allow_html=True)

    st.markdown("<hr style='border-color: #e2e8f0; margin: 4px 0 10px 0;'>", unsafe_allow_html=True)

    for rank_idx, item in enumerate(top_5, start=1):
        f_obj = findings.get(item["finding_id"])
        a_obj = assets.get(item["asset_id"])
        biz_area = derive_business_area(f_obj, a_obj)
        row_cols = st.columns([0.8, 1.8, 2.2, 2.0, 1.2, 1.0, 0.9, 1.1, 1.4])
        row_cols[0].markdown(f"#{rank_idx}")
        row_cols[1].markdown(f"**{item['cve_id']}**")
        row_cols[2].markdown(f"{biz_area}")
        row_cols[3].markdown(f"<code>{item['hostname']}</code>", unsafe_allow_html=True)
        row_cols[4].markdown(f"{a_obj.environment.value if a_obj else 'Production'}")
        row_cols[5].markdown(f"{item['severity']}")
        row_cols[6].markdown(f"{item['cvss_score']:.1f}")
        row_cols[7].markdown(f"<strong style='color: #1d4ed8;'>{item['environmental_risk_score']:.2f}</strong>", unsafe_allow_html=True)
        row_cols[8].markdown(render_decision_badge(item["aegis_decision"]), unsafe_allow_html=True)

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)


    # 10. Asset Context Deep Dive
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Contextual Asset Inspection</h3>
            <div class="section-subtitle">Select any vulnerability finding to inspect its real enterprise CMDB context and risk calculation factors</div>
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
                st.markdown(
                    f"""
                    <div class="detail-box">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.86rem; margin-bottom: 12px;">
                            <div><span class="detail-label">Finding ID:</span> <code>{f_data['finding_id']}</code></div>
                            <div><span class="detail-label">CVE ID:</span> <strong>{f_data['cve_id']}</strong></div>
                            <div><span class="detail-label">Affected Package:</span> <code>{f_data['affected_package']}</code></div>
                            <div><span class="detail-label">Installed Version:</span> <code>{f_data['installed_version']}</code></div>
                            <div><span class="detail-label">Base CVSS:</span> <strong>{f_data['cvss_score']}</strong> ({f_data['severity']})</div>
                            <div><span class="detail-label">Fixed Version:</span> <code>{f_data['fixed_version'] or 'None recorded'}</code></div>
                        </div>
                        <hr style="border-color: #e2e8f0; margin: 10px 0;">
                        <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.86rem;">
                            <div><span class="detail-label">Host:</span> <strong>{a_data['hostname']}</strong> (<code>{a_data['asset_id']}</code>)</div>
                            <div><span class="detail-label">Environment:</span> <strong>{a_data['environment']}</strong></div>
                            <div><span class="detail-label">Criticality:</span> <strong>{a_data['criticality']}</strong></div>
                            <div><span class="detail-label">Exposure:</span> {a_data['network_exposure']}</div>
                            <div><span class="detail-label">Data Sensitivity:</span> {a_data['data_sensitivity']}</div>
                            <div><span class="detail-label">Business Tier:</span> {a_data.get('business_tier', 'Standard')}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

            with col_detail_right:
                st.markdown("#### Environmental Risk Breakdown")
                st.markdown(
                    f"""
                    <div class="detail-box">
                        <div style="display: flex; flex-direction: column; gap: 6px; font-size: 0.85rem;">
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px;">
                                <span style="color: #475569;">Base Score (B):</span> <strong>{r_data['base_score']} / 100</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px;">
                                <span style="color: #475569;">Threat Score (T):</span> <strong>{r_data['threat_score']} / 100</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px;">
                                <span style="color: #475569;">Environmental Score (E):</span> <strong>{r_data['environmental_score']} / 100</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px;">
                                <span style="color: #475569;">Compensating Multiplier:</span> <strong>{r_data['control_multiplier']}</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; padding-top: 6px;">
                                <span style="font-weight: 700; color: #0f172a;">Environmental Risk Score:</span>
                                <strong style="color: #1d4ed8; font-size: 1.1rem;">{r_data['environmental_risk_score']}</strong>
                            </div>
                            <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 4px;">
                                <span style="color: #475569;">Aegis Decision:</span>
                                {render_decision_badge(r_data['aegis_decision'])}
                            </div>
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
    """Render the Vulnerabilities Prioritization and Deep-Dive Investigation page."""
    # Check if a specific finding has been selected for deep-dive investigation
    selected_finding_id = st.session_state.get("selected_finding_id")

    if selected_finding_id and selected_finding_id in findings:
        detail = get_investigation_detail(selected_finding_id, findings, assets, assessments)
        if detail:
            render_vulnerability_investigation_view(
                detail=detail,
                on_back_clicked=lambda: st.session_state.update({"selected_finding_id": None}),
            )
            return

    st.title("Aegis Patch — Vulnerabilities")
    st.subheader("Prioritization & Investigation Experience")

    # Reset filter callback
    def _reset_vuln_filters() -> None:
        st.session_state["vuln_search_input"] = ""
        st.session_state["vuln_sev_select"] = "All"
        st.session_state["vuln_dec_select"] = "All"
        st.session_state["vuln_tier_select"] = "All"
        st.session_state["vuln_env_select"] = "All"
        st.session_state["vuln_crit_select"] = "All"
        st.session_state["selected_finding_id"] = None

    # 1. Header & Scoping Context
    st.markdown(
        clean_html("""
        <div class="section-header">
            <h3 class="section-title">VULNERABILITIES</h3>
            <div class="section-subtitle">See which vulnerabilities deserve attention first — and why.</div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # 2. Search Bar and Filter Reset Row
    col_search, col_reset = st.columns([4, 1.2])

    with col_search:
        search_query = st.text_input(
            "Search findings",
            placeholder="Search by CVE, vulnerability ID, package, system, or hostname...",
            key="vuln_search_input",
            label_visibility="collapsed",
        )

    with col_reset:
        st.button(
            "Reset Filters",
            key="btn_reset_vuln_filters",
            on_click=_reset_vuln_filters,
            use_container_width=True,
        )

    # 3. Dropdown Filters
    col_sev, col_dec, col_tier, col_env, col_crit = st.columns(5)

    with col_sev:
        sel_sev = st.selectbox(
            "Severity",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="vuln_sev_select",
            help="Filter by base CVSS severity.",
        )
    with col_dec:
        sel_dec = st.selectbox(
            "Recommended Action",
            options=["All", "ACT", "ATTEND", "PLAN", "TRACK"],
            format_func=lambda d: {
                "All": "All Actions",
                "ACT": "Fix Immediately (ACT)",
                "ATTEND": "Review Soon (ATTEND)",
                "PLAN": "Plan Fix (PLAN)",
                "TRACK": "Monitor (TRACK)",
            }.get(d, d),
            key="vuln_dec_select",
            help="Filter by Aegis action recommendation.",
        )
    with col_tier:
        sel_tier = st.selectbox(
            "Risk Level",
            options=["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"],
            key="vuln_tier_select",
            help="Filter by Aegis Risk Level (Risk Tier).",
        )
    with col_env:
        sel_env = st.selectbox(
            "Environment",
            options=["All", "PRODUCTION", "STAGING", "DEVELOPMENT", "TESTING"],
            key="vuln_env_select",
            help="Filter by asset environment.",
        )
    with col_crit:
        sel_crit = st.selectbox(
            "Business Importance",
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

    # 4. Scoped Summary KPIs
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
                "Critical Base Severity",
                str(crit_count),
                "CVSS = CRITICAL",
            ),
            unsafe_allow_html=True,
        )
    with kpi4:
        st.markdown(
            render_metric_card(
                "Assets Impacted",
                str(unique_assets),
                "Unique affected enterprise hosts",
            ),
            unsafe_allow_html=True,
        )

    # Zero-findings state handling
    if total_scoped == 0:
        st.info("No findings match the current filter criteria. Adjust or reset your filters above.")
        return

    # 5. Prioritized Findings Queue Table & Deep-Dive Selector
    st.markdown(
        clean_html("""
        <div class="section-header">
            <h3 class="section-title">Prioritized Findings Queue</h3>
            <div class="section-subtitle">Ranked deterministically by Aegis Risk Score (ERS)</div>
        </div>
        """),
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
            "View Investigation",
            key="btn_inspect_finding",
            use_container_width=True,
        ):
            st.session_state["selected_finding_id"] = chosen_id
            st.rerun()

    # Formatted DataFrame presentation with Business Area
    df_data = []
    for r in records:
        dec_label = {
            "ACT": "Fix Immediately (ACT)",
            "ATTEND": "Review Soon (ATTEND)",
            "PLAN": "Plan Fix (PLAN)",
            "TRACK": "Monitor (TRACK)",
        }.get(r["aegis_decision"], r["aegis_decision"])

        df_data.append(
            {
                "Priority": f"#{r['priority_rank']}",
                "Vulnerability": r["cve_id"],
                "Finding ID": r["finding_id"],
                "CVE ID": r["cve_id"],
                "Business Area": r.get("business_area", "Not specified"),
                "Affected System": r["hostname"],
                "Environment": r["environment"].capitalize(),
                "Severity": r["severity"].capitalize(),
                "CVSS": r["cvss_score"],
                "Aegis Risk": r["environmental_risk_score"],
                "ERS Score": r["environmental_risk_score"],
                "Recommended Action": dec_label,
            }
        )

    df = pd.DataFrame(df_data)

    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Priority": st.column_config.TextColumn("Priority", width="small"),
            "Vulnerability": st.column_config.TextColumn("Vulnerability", width="medium"),
            "Business Area": st.column_config.TextColumn("Business Area", width="medium"),
            "Affected System": st.column_config.TextColumn("Affected System", width="medium"),
            "Environment": st.column_config.TextColumn("Environment", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
            "Aegis Risk": st.column_config.NumberColumn("Aegis Risk", format="%.2f", width="small"),
            "Recommended Action": st.column_config.TextColumn("Recommended Action", width="medium"),
            "Finding ID": None,
            "CVE ID": None,
            "ERS Score": None,
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


def render_how_it_works_page() -> None:
    """Render the architectural deep-dive page explaining Aegis Patch and the 6 specialist agents."""
    st.markdown(
        clean_html("""
        <div class="section-header">
            <h2 class="section-title" style="font-size: 1.6rem;">HOW AEGIS PATCH WORKS</h2>
            <div class="section-subtitle">Six specialist agents investigate a vulnerability from different perspectives before a remediation recommendation is verified.</div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # Architectural Pipeline Flow Visual
    st.markdown(
        clean_html("""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px 22px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);">
            <div style="font-size: 0.8rem; font-weight: 800; color: #1e3a8a; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
                End-to-End Specialist Workflow
            </div>
            <div style="display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; font-size: 0.82rem; font-weight: 700; color: #0f172a;">
                <span style="background: #f1f5f9; padding: 6px 10px; border-radius: 4px; border: 1px solid #cbd5e1;">Vulnerability Found</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">1. Scan Intake</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">2. Threat & Exploit Check</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">3. Business & Asset Context</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">4. Risk Decision</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">5. Patch Planning</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #eff6ff; padding: 6px 10px; border-radius: 4px; border: 1px solid #bfdbfe; color: #1e40af;">6. Verification</span>
                <span style="color: #94a3b8;">→</span>
                <span style="background: #f0fdf4; padding: 6px 10px; border-radius: 4px; border: 1px solid #bbf7d0; color: #166534;">Security Operations Approval</span>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # 1. Why Specialist Agents?
    st.markdown(
        clean_html("""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px 24px; margin-bottom: 24px; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);">
            <h3 style="font-size: 1.15rem; font-weight: 800; color: #0f172a; margin-bottom: 8px;">
                WHY SPECIALIST AGENTS?
            </h3>
            <p style="font-size: 0.9rem; color: #334155; line-height: 1.6; margin-bottom: 16px;">
                Security vulnerability prioritization requires several different types of analysis. Aegis Patch separates these responsibilities into specialist agents. Each agent focuses on one bounded task, while the Verification Agent independently checks the final recommendation.
            </p>
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; font-size: 0.85rem;">
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #1e40af;">1. Scan Intake:</strong>
                    <div style="color: #475569; margin-top: 4px;">"What did the scanner find?" Normalizes schema and dedupes scanner outputs.</div>
                </div>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #1e40af;">2. Threat & Exploit Check:</strong>
                    <div style="color: #475569; margin-top: 4px;">"How strong is the real-world threat evidence?" Queries CISA KEV and EPSS feeds.</div>
                </div>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #1e40af;">3. Business & Asset Context:</strong>
                    <div style="color: #475569; margin-top: 4px;">"Where is the vulnerability and how important is the system?" Investigates CMDB & controls.</div>
                </div>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #1e40af;">4. Risk Decision:</strong>
                    <div style="color: #475569; margin-top: 4px;">"How risky is it in this environment?" Computes deterministic Aegis Risk Score.</div>
                </div>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #1e40af;">5. Patch Planning:</strong>
                    <div style="color: #475569; margin-top: 4px;">"What should be fixed within the available maintenance capacity?" Solves 0/1 knapsack.</div>
                </div>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; padding: 12px 14px; border-radius: 6px;">
                    <strong style="color: #166534;">6. Verification:</strong>
                    <div style="color: #475569; margin-top: 4px;">"Is the recommendation supported and internally consistent?" 4-dimension audit.</div>
                </div>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    # 2. The 6 Specialist Agents Cards
    st.markdown(
        clean_html("""
        <div class="section-header">
            <h3 class="section-title">Specialist Agent Responsibilities & Tools</h3>
            <div class="section-subtitle">Each specialist agent executes bounded deterministic tools through the Tool Registry</div>
        </div>
        """),
        unsafe_allow_html=True,
    )

    ag_col1, ag_col2 = st.columns(2)

    with ag_col1:
        st.markdown(
            render_agent_card(
                1,
                "Scan Intake Specialist Agent",
                "Ingestion Specialist",
                "Parses multi-format scanner payloads (Trivy, OSV, SARIF), cleans duplicate findings, and validates standard CVE identifiers.",
                "Normalizes package names, installed versions, and minimum fixed version targets.",
                ["parse_scanner_finding", "validate_cve_schema", "normalize_package_spec"],
            ),
            unsafe_allow_html=True,
        )

        st.markdown(
            render_agent_card(
                3,
                "Business & Asset Context Agent",
                "Context Specialist",
                "Queries enterprise CMDB to determine affected asset topology, lifecycle environment, data classification, and active controls.",
                "Derives network boundary exposure and applies compensating mitigation multipliers (M_control).",
                ["query_asset_cmdb", "get_network_reachability", "query_rag_policy"],
            ),
            unsafe_allow_html=True,
        )

        st.markdown(
            render_agent_card(
                5,
                "Patch Planning Specialist Agent",
                "Optimization Specialist",
                "Formulates 0/1 knapsack mathematical optimization under maintenance capacity constraints (e.g. 16h window).",
                "Ranks candidates by Risk Reduction per Engineering Hour and plans safe deployment sequences.",
                ["optimize_patch_capacity", "resolve_package_dependencies", "simulate_risk_reduction"],
            ),
            unsafe_allow_html=True,
        )

    with ag_col2:
        st.markdown(
            render_agent_card(
                2,
                "Threat & Exploit Check Agent",
                "Threat Specialist",
                "Cross-references real-world adversary threat feeds: CISA Known Exploited Vulnerabilities (KEV), First.org EPSS, and public exploit code.",
                "Computes empirical threat score (T) and identifies weaponized zero-day vectors.",
                ["lookup_cisa_kev", "query_epss", "query_osv_database"],
            ),
            unsafe_allow_html=True,
        )

        st.markdown(
            render_agent_card(
                4,
                "Risk Decision Specialist Agent",
                "Calculation Specialist",
                "Applies deterministic Environmental Risk Score (ERS) formula combining Base (B), Threat (T), and Environmental (E) factors.",
                "Assigns transparent action recommendations: Fix Immediately (ACT), Review Soon (ATTEND), Plan Fix (PLAN), Monitor (TRACK).",
                ["calculate_environmental_risk", "map_ssvc_decision"],
            ),
            unsafe_allow_html=True,
        )

        st.markdown(
            render_agent_card(
                6,
                "Verification Specialist Agent",
                "Audit Specialist",
                "Executes 4-dimension independent verification: checks score math, grounds factual claims, validates plan bounds, and confirms cross-evidence consistency.",
                "Guarantees 0% hallucination and defensible audit trails before Security Operations review.",
                ["verify_score_derivation", "detect_hallucinated_claims", "validate_plan_constraints"],
            ),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # 3. Expandable Technical Architecture
    with st.expander("TECHNICAL ARCHITECTURE — Layered System Design", expanded=False):
        st.markdown(
            clean_html("""
            <div style="font-size: 0.88rem; color: #334155; line-height: 1.7;">
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 14px 18px; margin-bottom: 14px; font-family: monospace; font-size: 0.85rem; color: #0f172a;">
                    <strong>Enterprise Architecture Hierarchy:</strong><br/>
                    User Interface (Streamlit Presentation Layer)<br/>
                    &nbsp;&nbsp;↓<br/>
                    Application / API Layer (FastAPI REST Endpoints & Orchestration Services)<br/>
                    &nbsp;&nbsp;↓<br/>
                    Workflow / Agent Layer (Specialist Contracts & State Transition)<br/>
                    &nbsp;&nbsp;↓<br/>
                    Six Specialist Agents (Bounded Task Responsibilities)<br/>
                    &nbsp;&nbsp;↓<br/>
                    Tool Registry (Deterministic Security Tools & Verification Auditors)<br/>
                    &nbsp;&nbsp;↓<br/>
                    Database / Benchmark Evidence (CMDB, CISA KEV, EPSS Feeds, Scans)
                </div>
                <p><strong>Core Architectural Principles:</strong></p>
                <ul>
                    <li><strong>Tool Registry Integration:</strong> Specialist agents invoke deterministic security tools through the central Tool Registry.</li>
                    <li><strong>Deterministic Grounding:</strong> Critical risk calculations, priority rankings, and knapsack optimizations remain 100% deterministic and reproducible.</li>
                    <li><strong>Independent Verification:</strong> The Verification Agent functions as an adversarial audit gate, validating score derivations and plan bounds before any human review.</li>
                    <li><strong>Infrastructure Safety Guarantee:</strong> No agent directly modifies production infrastructure, runs shell commands, or initiates unattended live patches.</li>
                    <li><strong>State Status Model:</strong> Agent executions follow an explicit deterministic status model (<code>WAITING</code>, <code>RUNNING</code>, <code>COMPLETED</code>, <code>FAILED</code>, <code>NOT_APPLICABLE</code>, <code>NOT_AVAILABLE</code>).</li>
                </ul>
            </div>
            """),
            unsafe_allow_html=True,
        )

    # 4. Technology Stack
    st.markdown(
        clean_html("""
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px 22px; margin-top: 18px;">
            <h4 style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 8px;">Technology Stack & Verification Foundation</h4>
            <div style="display: flex; gap: 20px; font-size: 0.84rem; color: #475569; flex-wrap: wrap;">
                <span>🐍 <strong>Core:</strong> Python 3.12 (Strict typing)</span>
                <span>🛡️ <strong>Validation:</strong> Pydantic v2 schemas</span>
                <span>⚡ <strong>Backend API:</strong> FastAPI REST endpoints</span>
                <span>🎨 <strong>UI Framework:</strong> Streamlit (Reactive light theme)</span>
                <span>📊 <strong>Visualizations:</strong> Altair (Interactive Vega-Lite)</span>
                <span>✅ <strong>Test Harness:</strong> Pytest (Automated verification suite)</span>
            </div>
        </div>
        """),
        unsafe_allow_html=True,
    )


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

    # Track navigation in session state
    if "nav_page" not in st.session_state:
        st.session_state["nav_page"] = "Overview"

    # Render top bar navigation
    top_page = render_top_header(st.session_state["nav_page"])

    # Render sidebar navigation (for testing & alternative access)
    sidebar_page = render_sidebar(
        findings_count=len(findings),
        assets_count=len(assets),
        is_operational=True,
    )

    # Harmonize navigation selection
    # If sidebar radio was explicitly used by an automated test or user:
    active_page = top_page
    if sidebar_page != "Overview" and sidebar_page != top_page:
        # If sidebar was changed (e.g. In test suite)
        active_page = sidebar_page

    # Update session state
    st.session_state["nav_page"] = active_page

    # Route navigation
    if active_page == "Overview":
        render_overview_page(findings, assets, assessments)
    elif active_page == "Vulnerabilities":
        render_vulnerabilities_page(findings, assets, assessments)
    elif active_page == "Patch Plan":
        render_patch_plan_view(findings, assets, assessments)
    elif active_page in ("What If?", "Scenarios"):
        render_scenarios_page(findings, assets, assessments)
    elif active_page == "How Aegis Works":
        render_how_it_works_page()


if __name__ == "__main__":
    main()
