"""UI rendering helpers for Aegis Patch Scenario Explorer & What-If Demonstration.

Provides interactive visualizations for benchmark counterexample scenarios A through E
and the constrained patch-capacity what-if remediation simulation.
"""

from __future__ import annotations

from typing import Any, Dict

import pandas as pd
import streamlit as st

from src.schemas.asset import Asset
from src.schemas.risk import RiskAssessment
from src.schemas.vulnerability import VulnerabilityFinding
from src.services.scenario_service import (
    DEFAULT_MAINTENANCE_CAPACITY_HOURS,
    build_patch_candidates,
    get_scenario_comparison_a,
    get_scenario_comparison_b,
    get_scenario_comparison_c,
    get_scenario_comparison_d,
    get_scenario_comparison_e,
    optimize_patch_schedule,
)
from src.ui.styles import (
    render_context_callout,
    render_decision_badge,
    render_metric_card,
    render_scheduled_badge,
    render_severity_badge,
)


def render_scenario_header() -> None:
    """Render the standard Scenario Explorer header and benchmark disclaimer."""
    st.title("Aegis Patch — Scenarios Explorer")
    st.subheader("See how environmental context changes vulnerability priority.")
    st.markdown(
        """
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #1d4ed8; border-radius: 4px; padding: 10px 16px; margin: 10px 0 20px 0; font-size: 0.86rem; color: #475569;">
            🛡️ <strong>Benchmark Disclaimer:</strong> Benchmark scenarios use synthetic enterprise context to demonstrate how environmental factors can change prioritization.
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_scenario_a_view(comp: Dict[str, Any]) -> None:
    """Render Scenario A: Exposure and Criticality Inversion."""
    st.markdown(
        f"""
        <div class="section-header">
            <h3 class="section-title">Scenario A: {comp['title']}</h3>
            <div class="section-subtitle">{comp['demonstration_goal']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_iso, col_exp = st.columns(2)

    iso = comp["isolated"]
    exp = comp["exposed"]

    with col_iso:
        st.markdown(
            f"""
            <div class="detail-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{iso['finding_id']} • {iso['cve_id']}</span>
                    {render_severity_badge(iso['severity'])}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">
                    {iso['title']}
                </div>
                <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 12px;">
                    Target Host: <strong>{iso['hostname']}</strong> (<code>{iso['asset_id']}</code>)
                </div>
                <div class="highlight-diff" style="border-left-color: #94a3b8; background-color: #f8fafc;">
                    <div style="font-size: 0.82rem; color: #475569; line-height: 1.6;">
                        <div><strong>Base CVSS:</strong> <span style="font-size: 1.05rem; font-weight: 700; color: #991b1b;">{iso['cvss_score']}</span> (Theoretical Maximum)</div>
                        <div><strong>Environment:</strong> {iso['environment']}</div>
                        <div><strong>Criticality:</strong> {iso['criticality']}</div>
                        <div><strong>Exposure:</strong> {iso['network_exposure']}</div>
                        <div><strong>Data Sensitivity:</strong> {iso['data_sensitivity']}</div>
                        <div><strong>Environmental Factor Score:</strong> {iso['environmental_score']} / 100</div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Environmental Risk</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #166534;">{iso['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Aegis Decision</div>
                        {render_decision_badge(iso['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_exp:
        st.markdown(
            f"""
            <div class="detail-box" style="border: 2px solid #bfdbfe;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{exp['finding_id']} • {exp['cve_id']}</span>
                    {render_severity_badge(exp['severity'])}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">
                    {exp['title']}
                </div>
                <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 12px;">
                    Target Host: <strong>{exp['hostname']}</strong> (<code>{exp['asset_id']}</code>)
                </div>
                <div class="highlight-diff">
                    <div style="font-size: 0.82rem; color: #1e3a8a; line-height: 1.6;">
                        <div><strong>Base CVSS:</strong> <span style="font-size: 1.05rem; font-weight: 700; color: #c2410c;">{exp['cvss_score']}</span> (Lower than Isolated)</div>
                        <div><strong>Environment:</strong> <strong>{exp['environment']}</strong></div>
                        <div><strong>Criticality:</strong> <strong>{exp['criticality']}</strong></div>
                        <div><strong>Exposure:</strong> <strong>{exp['network_exposure']}</strong></div>
                        <div><strong>Data Sensitivity:</strong> <strong>{exp['data_sensitivity']}</strong></div>
                        <div><strong>Environmental Factor Score:</strong> <strong>{exp['environmental_score']} / 100</strong></div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Environmental Risk</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #1d4ed8;">{exp['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Aegis Decision</div>
                        {render_decision_badge(exp['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Inversion Summary Banner
    st.markdown(
        f"""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 18px; margin: 16px 0; display: flex; justify-content: space-around; align-items: center; text-align: center;">
            <div>
                <div class="detail-label">CVSS Raw Delta</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #991b1b;">+{comp['cvss_delta']} pts (FINDING-059 higher)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Aegis Environmental ERS Delta</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #1d4ed8;">+{comp['ers_delta']} pts (FINDING-006 elevated)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Prioritization Result</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a;">Inversion Verified (PLAN &gt; TRACK)</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(render_context_callout("Key Insight: Context Changes the Ranking", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_b_view(comp: Dict[str, Any]) -> None:
    """Render Scenario B: Threat Intelligence Exploitation Differential."""
    st.markdown(
        f"""
        <div class="section-header">
            <h3 class="section-title">Scenario B: {comp['title']}</h3>
            <div class="section-subtitle">{comp['demonstration_goal']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 14px;">
            📌 <strong>Technical Provenance:</strong> The benchmark dataset intentionally does not contain live external threat feeds.
            Therefore, this scenario contrasts the unaugmented benchmark baseline against a verified-input demonstration fixture
            to illustrate engine responsiveness to active threat signals without data fabrication.
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_base, col_dem = st.columns(2)

    base = comp["baseline_unaugmented"]
    dem = comp["verified_input_demonstration"]

    with col_base:
        st.markdown(
            f"""
            <div class="detail-box">
                <div class="detail-label" style="color: #64748b; margin-bottom: 4px;">Benchmark Baseline</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">
                    {base['finding_id']} • {base['cve_id']}
                </div>
                <p style="font-size: 0.85rem; color: #475569; margin-bottom: 10px;">{base['title']}</p>
                <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-radius: 4px; padding: 8px 12px; font-size: 0.82rem; margin-bottom: 12px;">
                    <div><strong>Base CVSS:</strong> {base['cvss_score']} ({base['severity']})</div>
                    <div><strong>Threat Status:</strong> <em>{base['threat_status']}</em></div>
                    <div><strong>Calculated Threat Score (T):</strong> <span class="math-token">{base['threat_score']}</span></div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 12px 0 8px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Baseline ERS</div>
                        <span style="font-size: 1.5rem; font-weight: 700; color: #475569;">{base['environmental_risk_score']}</span>
                    </div>
                    {render_decision_badge(base['aegis_decision'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_dem:
        st.markdown(
            f"""
            <div class="detail-box" style="border: 2px solid #fed7aa; background-color: #fffaf5;">
                <div class="detail-label" style="color: #c2410c; margin-bottom: 4px;">Verified-Input Demonstration</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">
                    {dem['finding_id']} • {dem['cve_id']}
                </div>
                <p style="font-size: 0.85rem; color: #475569; margin-bottom: 10px;">{dem['title']}</p>
                <div style="background-color: #ffffff; border: 1px solid #fed7aa; border-radius: 4px; padding: 8px 12px; font-size: 0.82rem; margin-bottom: 12px;">
                    <div><strong>Base CVSS:</strong> {dem['cvss_score']} ({dem['severity']})</div>
                    <div><strong>Threat Status:</strong> <strong>{dem['threat_status']}</strong></div>
                    <div><strong>Calculated Threat Score (T):</strong> <span class="math-token" style="background-color: #fff7ed; border-color: #fed7aa; color: #c2410c;">{dem['threat_score']}</span></div>
                </div>
                <hr style="border-color: #fed7aa; margin: 12px 0 8px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Elevated ERS</div>
                        <span style="font-size: 1.5rem; font-weight: 700; color: #c2410c;">{dem['environmental_risk_score']}</span>
                        <span style="font-size: 0.82rem; font-weight: 700; color: #dc2626;"> (+{comp['ers_jump']} pts)</span>
                    </div>
                    {render_decision_badge(dem['aegis_decision'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(render_context_callout("Key Insight: Threat Evidence Modulates Operational Priority", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_c_view(comp: Dict[str, Any]) -> None:
    """Render Scenario C: Compensating Controls Risk Mitigation."""
    st.markdown(
        f"""
        <div class="section-header">
            <h3 class="section-title">Scenario C: {comp['title']}</h3>
            <div class="section-subtitle">{comp['demonstration_goal']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div style="font-size: 0.88rem; color: #0f172a; margin-bottom: 12px;">
            <strong>Underlying Vulnerability:</strong> <code>{comp['shared_cve']}</code> (libcurl heap overflow, CVSS {comp['cvss_score']})
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_prot, col_unprot = st.columns(2)

    prot = comp["protected_asset"]
    unprot = comp["unprotected_asset"]

    with col_prot:
        st.markdown(
            f"""
            <div class="detail-box" style="border: 2px solid #bbf7d0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span class="detail-label">Protected Infrastructure</span>
                    <span class="status-badge status-operational">🛡️ Active Mitigations</span>
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 4px;">
                    {prot['hostname']} (<code>{prot['asset_id']}</code>)
                </div>
                <div style="font-size: 0.82rem; color: #64748b; margin-bottom: 10px;">
                    {prot['environment']} • {prot['criticality']} • {prot['network_exposure']}
                </div>
                <div class="highlight-diff" style="border-left-color: #16a34a; background-color: #f0fdf4;">
                    <div style="font-size: 0.82rem; color: #166534; line-height: 1.55;">
                        <div><strong>Controls:</strong> {", ".join(prot['controls'])}</div>
                        <div><strong>Unmitigated Risk (R):</strong> {prot['unmitigated_risk']} / 100</div>
                        <div><strong>Control Multiplier (M_control):</strong> <span class="math-token">{prot['control_multiplier']}</span> (-15% discount)</div>
                        <div><strong>Residual Risk Dampened:</strong> -{prot['points_dampened']} points</div>
                    </div>
                </div>
                <hr style="border-color: #bbf7d0; margin: 12px 0 8px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Residual ERS</div>
                        <span style="font-size: 1.5rem; font-weight: 700; color: #166534;">{prot['environmental_risk_score']}</span>
                    </div>
                    {render_decision_badge(prot['aegis_decision'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_unprot:
        st.markdown(
            f"""
            <div class="detail-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <span class="detail-label">Unprotected Infrastructure</span>
                    <span style="color: #64748b; font-size: 0.78rem; font-style: italic;">No controls</span>
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 4px;">
                    {unprot['hostname']} (<code>{unprot['asset_id']}</code>)
                </div>
                <div style="font-size: 0.82rem; color: #64748b; margin-bottom: 10px;">
                    {unprot['environment']} • {unprot['criticality']} • {unprot['network_exposure']}
                </div>
                <div class="highlight-diff" style="border-left-color: #cbd5e1; background-color: #f8fafc;">
                    <div style="font-size: 0.82rem; color: #475569; line-height: 1.55;">
                        <div><strong>Controls:</strong> None configured</div>
                        <div><strong>Control Multiplier (M_control):</strong> <span class="math-token">1.00</span> (0% discount)</div>
                        <div><strong>Exposure Mitigation:</strong> None (Full environmental blast radius applies)</div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 12px 0 8px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Environmental ERS</div>
                        <span style="font-size: 1.5rem; font-weight: 700; color: #0f172a;">{unprot['environmental_risk_score']}</span>
                    </div>
                    {render_decision_badge(unprot['aegis_decision'])}
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.markdown(
        f"""
        <div style="font-size: 0.8rem; color: #64748b; margin-top: 8px;">
            ⚠️ <em>{comp['caveat']}</em>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(render_context_callout("Key Insight: Controls Mitigate Risk, Not Vulnerability Existence", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_d_view(comp: Dict[str, Any]) -> None:
    """Render Scenario D: Intra-Asset Hotspot Prioritization."""
    st.markdown(
        f"""
        <div class="section-header">
            <h3 class="section-title">Scenario D: {comp['title']}</h3>
            <div class="section-subtitle">{comp['demonstration_goal']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    asset = comp["asset"]

    # Asset Header Card
    st.markdown(
        f"""
        <div class="detail-box" style="margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap;">
                <div>
                    <div class="detail-label">Asset Concentration Target</div>
                    <div style="font-size: 1.25rem; font-weight: 700; color: #0f172a;">
                        {asset['hostname']} (<code>{asset['asset_id']}</code>)
                    </div>
                    <div style="font-size: 0.85rem; color: #475569; margin-top: 2px;">
                        <strong>Owner:</strong> {asset['owner_team']} &nbsp;|&nbsp;
                        <strong>Environment:</strong> {asset['environment']} &nbsp;|&nbsp;
                        <strong>Criticality:</strong> {asset['criticality']} &nbsp;|&nbsp;
                        <strong>Exposure:</strong> {asset['network_exposure']}
                    </div>
                </div>
                <div style="display: flex; gap: 20px; text-align: right; margin-top: 6px;">
                    <div>
                        <div class="detail-label">Finding Count</div>
                        <span style="font-size: 1.4rem; font-weight: 700; color: #0f172a;">{asset['finding_count']}</span>
                    </div>
                    <div>
                        <div class="detail-label">Maximum Finding ERS</div>
                        <span style="font-size: 1.4rem; font-weight: 700; color: #1d4ed8;">{asset['max_finding_ers']}</span>
                    </div>
                    <div>
                        <div class="detail-label">Priority (ACT + ATTEND)</div>
                        <span style="font-size: 1.4rem; font-weight: 700; color: #ea580c;">{asset['priority_count']}</span>
                    </div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Findings Table
    st.markdown("##### Intra-Asset Remediation Sequencing")
    df_data = []
    for rank_idx, f in enumerate(comp["findings"], start=1):
        df_data.append(
            {
                "Sequence": f"#{rank_idx}",
                "Finding ID": f["finding_id"],
                "CVE ID": f["cve_id"],
                "Vulnerability Title": f["title"],
                "Package": f["affected_package"],
                "Severity": f["severity"],
                "CVSS": f["cvss_score"],
                "ERS Score": f["environmental_risk_score"],
                "Aegis Decision": f["aegis_decision"],
            }
        )

    df = pd.DataFrame(df_data)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Sequence": st.column_config.TextColumn("Seq", width="small"),
            "Finding ID": st.column_config.TextColumn("Finding ID", width="small"),
            "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
            "Vulnerability Title": st.column_config.TextColumn("Title", width="large"),
            "Package": st.column_config.TextColumn("Package", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "CVSS": st.column_config.NumberColumn("CVSS", format="%.1f", width="small"),
            "ERS Score": st.column_config.NumberColumn("ERS Score", format="%.2f", width="small"),
            "Aegis Decision": st.column_config.TextColumn("Decision", width="small"),
        },
    )

    st.markdown(render_context_callout("Key Insight: Intra-Asset Concentration Solves Blast-Radius Sprawl", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_e_view(comp: Dict[str, Any]) -> None:
    """Render Scenario E: Cross-Asset Prevalent Vulnerability Spread."""
    st.markdown(
        f"""
        <div class="section-header">
            <h3 class="section-title">Scenario E: {comp['title']}</h3>
            <div class="section-subtitle">{comp['demonstration_goal']}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        f"""
        <div style="background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 4px; padding: 10px 16px; font-size: 0.88rem; color: #1e3a8a; margin-bottom: 16px;">
            <strong>Tracking Target:</strong> <code>{comp['cve_id']}</code> — {comp['underlying_vulnerability']}<br>
            <span style="font-size: 0.82rem; color: #475569;">Spread across 4 distinct infrastructure tiers producing an ERS spread of <strong>{comp['ers_spread']} points</strong>.</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    df_data = []
    for c in comp["comparisons"]:
        df_data.append(
            {
                "Finding ID": c["finding_id"],
                "Asset ID": c["asset_id"],
                "Target Hostname": c["hostname"],
                "Environment": c["environment"],
                "Criticality": c["criticality"],
                "Network Exposure": c["network_exposure"],
                "Data Sensitivity": c["data_sensitivity"],
                "Base CVSS": c["cvss_score"],
                "Control Multiplier": c["control_multiplier"],
                "Environmental Risk (ERS)": c["environmental_risk_score"],
                "Aegis Decision": c["aegis_decision"],
            }
        )

    df = pd.DataFrame(df_data)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Finding ID": st.column_config.TextColumn("Finding ID", width="small"),
            "Asset ID": st.column_config.TextColumn("Asset ID", width="small"),
            "Target Hostname": st.column_config.TextColumn("Hostname", width="medium"),
            "Environment": st.column_config.TextColumn("Environment", width="small"),
            "Criticality": st.column_config.TextColumn("Criticality", width="small"),
            "Network Exposure": st.column_config.TextColumn("Exposure", width="small"),
            "Data Sensitivity": st.column_config.TextColumn("Sensitivity", width="small"),
            "Base CVSS": st.column_config.NumberColumn("Base CVSS", format="%.1f", width="small"),
            "Control Multiplier": st.column_config.NumberColumn("M_ctrl", format="%.2f", width="small"),
            "Environmental Risk (ERS)": st.column_config.NumberColumn("ERS Score", format="%.2f", width="small"),
            "Aegis Decision": st.column_config.TextColumn("Decision", width="small"),
        },
    )

    st.markdown(render_context_callout("Key Insight: Same Vulnerability, Different Environment, Different Risk", comp["key_insight"]), unsafe_allow_html=True)


def render_what_if_capacity_view(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the interactive Patch Capacity What-If Simulation view."""
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">What-If: Patch Capacity Simulation</h3>
            <div class="section-subtitle">Model remediation planning and maximize risk reduction within limited maintenance capacity</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #0f172a; border-radius: 4px; padding: 10px 16px; margin-bottom: 16px; font-size: 0.85rem; color: #475569;">
            📋 <strong>Planning Simulation:</strong> Models optimal maintenance window scheduling governed by
            <code>POL-SEC-04-patching.md §4.2.2</code> and <code>DATASET_SPEC.md §8</code>.
            Simulates candidate selection; no actual patches are executed.
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Capacity Control Slider
    col_slide, col_preset = st.columns([3, 1])
    with col_slide:
        capacity_hours = st.slider(
            "Maintenance Window Engineering Capacity (Hours)",
            min_value=4.0,
            max_value=32.0,
            value=float(st.session_state.get("sim_capacity_hours", DEFAULT_MAINTENANCE_CAPACITY_HOURS)),
            step=2.0,
            key="slider_capacity_hours",
            help="Total operational labor hours available for this remediation cycle.",
        )
        st.session_state["sim_capacity_hours"] = capacity_hours

    with col_preset:
        st.markdown("<div style='height: 28px;'></div>", unsafe_allow_html=True)
        if st.button("Reset Default (16.0h)", key="btn_reset_capacity", use_container_width=True):
            st.session_state["sim_capacity_hours"] = 16.0
            st.rerun()

    # Build candidates and solve optimization
    candidates = build_patch_candidates(findings, assets, assessments)
    plan_result = optimize_patch_schedule(candidates, capacity_hours, findings, assets)

    # Summary KPI Cards
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown(
            render_metric_card("Maintenance Budget", f"{plan_result['capacity_limit_hours']} hrs", "Approved labor budget"),
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            render_metric_card("Scheduled Effort", f"{plan_result['total_scheduled_effort_hours']} hrs", "Total engineering effort"),
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            render_metric_card("Remaining Budget", f"{plan_result['remaining_capacity_hours']} hrs", "Unallocated window hours"),
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            render_metric_card("Risk Reduction", f"{plan_result['total_expected_risk_reduction']} pts", "Expected ERS eliminated"),
            unsafe_allow_html=True,
        )
    with k5:
        st.markdown(
            render_metric_card("Scheduled Patches", f"{plan_result['scheduled_count']} / {len(candidates)}", "Remediation candidates"),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)

    # Candidate Remediation Plan Table
    st.markdown("##### Candidate Prioritization & Scheduling Queue")
    all_rows = plan_result["scheduled_candidates"] + plan_result["deferred_candidates"]
    all_rows.sort(key=lambda x: x["rank"])

    df_data = []
    for r in all_rows:
        df_data.append(
            {
                "Status": r["status"],
                "Rank": f"#{r['rank']}",
                "Candidate ID": r["candidate_id"],
                "Finding ID": r["finding_id"],
                "CVE ID": r["cve_id"],
                "Target Hostname": r["hostname"],
                "Environment": r["environment"],
                "Risk Tier": r["risk_tier"],
                "Effort (Hours)": r["estimated_cost_hours"],
                "Expected Reduction": r["expected_risk_reduction"],
                "Efficiency Ratio": r["efficiency_ratio"],
            }
        )

    df = pd.DataFrame(df_data)
    st.dataframe(
        df,
        width="stretch",
        hide_index=True,
        column_config={
            "Status": st.column_config.TextColumn("Status", width="small"),
            "Rank": st.column_config.TextColumn("Rank", width="small"),
            "Candidate ID": st.column_config.TextColumn("Candidate", width="small"),
            "Finding ID": st.column_config.TextColumn("Finding ID", width="small"),
            "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
            "Target Hostname": st.column_config.TextColumn("Hostname", width="medium"),
            "Environment": st.column_config.TextColumn("Env", width="small"),
            "Risk Tier": st.column_config.TextColumn("Risk Tier", width="small"),
            "Effort (Hours)": st.column_config.NumberColumn("Effort (h)", format="%.1f", width="small"),
            "Expected Reduction": st.column_config.NumberColumn("Risk Reduction", format="%.2f", width="small"),
            "Efficiency Ratio": st.column_config.NumberColumn("Ratio (Reduction/h)", format="%.2f", width="small"),
        },
    )

    st.markdown(
        render_context_callout(
            "Capacity Constrained Remediation",
            "Patch capacity is limited. Aegis Patch prioritizes remediation candidates to maximize contextual risk reduction "
            "within the available engineering capacity. Candidates exceeding the current maintenance budget are transparently "
            "deferred to the subsequent maintenance cycle per POL-SEC-04-patching.md §4.2.2.",
        ),
        unsafe_allow_html=True,
    )
