"""UI rendering helpers for Aegis Patch Scenario Explorer, What-If Demonstration, and Patch Plan.

Provides interactive visualizations for benchmark counterexample scenarios A through E,
the dedicated 16h maintenance Patch Plan view, and the constrained patch-capacity what-if simulation.
"""

from __future__ import annotations

import html
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
from src.services.vulnerability_service import derive_business_area
from src.ui.styles import (
    render_business_area_tag,
    render_capacity_bar,
    render_context_callout,
    render_decision_badge,
    render_human_approval_callout,
    render_metric_card,
    render_scheduled_badge,
    render_severity_badge,
)


def render_scenario_story_card(before_text: str, change_text: str, after_text: str, why_text: str) -> str:
    """Render a structured Before -> Change -> After -> Why Did It Change card."""
    return f"""
    <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 18px 20px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);">
        <div style="font-size: 0.8rem; font-weight: 700; color: #1d4ed8; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 12px;">
            Contextual Shift Progression
        </div>
        <div style="display: grid; grid-template-columns: 1fr auto 1fr auto 1fr; gap: 12px; align-items: center; margin-bottom: 14px;">
            <div style="background-color: #fef2f2; border: 1px solid #fecaca; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #991b1b; text-transform: uppercase;">1. Before (CVSS Alone)</div>
                <div style="font-size: 0.86rem; font-weight: 600; color: #7f1d1d; margin-top: 4px;">{html.escape(before_text)}</div>
            </div>
            <div style="font-size: 1.2rem; color: #94a3b8; font-weight: bold;">→</div>
            <div style="background-color: #eff6ff; border: 1px solid #bfdbfe; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #1d4ed8; text-transform: uppercase;">2. Environmental Change</div>
                <div style="font-size: 0.86rem; font-weight: 600; color: #1e3a8a; margin-top: 4px;">{html.escape(change_text)}</div>
            </div>
            <div style="font-size: 1.2rem; color: #94a3b8; font-weight: bold;">→</div>
            <div style="background-color: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 10px 14px;">
                <div style="font-size: 0.72rem; font-weight: 700; color: #166534; text-transform: uppercase;">3. After (Aegis Priority)</div>
                <div style="font-size: 0.86rem; font-weight: 600; color: #14532d; margin-top: 4px;">{html.escape(after_text)}</div>
            </div>
        </div>
        <div style="background-color: #f8fafc; border-left: 4px solid #3b82f6; padding: 10px 14px; border-radius: 4px;">
            <div style="font-size: 0.78rem; font-weight: 700; color: #1e293b; margin-bottom: 2px;">💡 Why Did It Change?</div>
            <div style="font-size: 0.85rem; color: #475569; line-height: 1.45;">{html.escape(why_text)}</div>
        </div>
    </div>
    """


def render_scenario_header() -> None:
    """Render the standard Scenario Explorer header and benchmark disclaimer."""
    st.title("Aegis Patch — Scenarios Explorer")
    st.subheader("See how environmental context changes vulnerability priority.")
    st.markdown(
        """
        <div style="background-color: #f8fafc; border: 1px solid #e2e8f0; border-left: 4px solid #1d4ed8; border-radius: 4px; padding: 10px 16px; margin: 10px 0 20px 0; font-size: 0.86rem; color: #475569;">
            🛡️ <strong>Benchmark Grounding:</strong> Benchmark scenarios use synthetic enterprise context to demonstrate how environmental factors, threat intelligence, and compensating controls deterministically alter prioritization.
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

    # Before -> Change -> After -> Why Card
    st.markdown(
        render_scenario_story_card(
            before_text="Isolated air-gapped testbed has CVSS 10.0 (Critical); exposed prod gateway has CVSS 7.5 (High).",
            change_text="Air-gapped lab has 0.0 exposure & no customer data. Prod gateway is Internet-facing with sensitive data.",
            after_text="Exposed prod elevated to ERS 43.00 (PLAN); isolated lab dropped to ERS 28.01 (TRACK).",
            why_text="Attackers cannot reach an air-gapped testbed from the outside. The Internet-facing service presents the actual operational attack surface.",
        ),
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
                <div class="detail-label">Remediation Triage</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a;">Exposed Prod → PLAN | Isolated Test → TRACK</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(render_context_callout("Key Insight: Environmental Inversion", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_b_view(comp: Dict[str, Any]) -> None:
    """Render Scenario B: Threat Intelligence Differential."""
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
        render_scenario_story_card(
            before_text="Standard vulnerability finding evaluated with baseline absence of verified threat intel (T=0.0).",
            change_text="Threat intel feed activates: weaponized public PoC confirmed and EPSS probability rises to 45.0%.",
            after_text="Threat score jumps from 0.0 to 56.0; ERS surges from 43.60 to 61.52 (+17.92 points).",
            why_text="Active exploit code drastically increases the statistical probability of real-world compromise.",
        ),
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
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{base['finding_id']} • {base['cve_id']}</span>
                    {render_severity_badge(base['severity'])}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">{base['title']}</div>
                <div class="highlight-diff" style="border-left-color: #94a3b8; background-color: #f8fafc;">
                    <div style="font-size: 0.82rem; color: #475569; line-height: 1.6;">
                        <div><strong>Threat Feed:</strong> {base['threat_status']}</div>
                        <div><strong>CISA KEV:</strong> Not confirmed</div>
                        <div><strong>EPSS Probability:</strong> Not available (unaugmented)</div>
                        <div><strong>Public PoC:</strong> Not confirmed</div>
                        <div><strong>Threat Factor Score (T):</strong> 0.0 / 100</div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Baseline ERS</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #2563eb;">{base['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Decision</div>
                        {render_decision_badge(base['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_dem:
        st.markdown(
            f"""
            <div class="detail-box" style="border: 2px solid #fed7aa;">
                <div class="detail-label" style="color: #ea580c; margin-bottom: 4px;">Verified Threat Feed Demonstration</div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{dem['finding_id']} • {dem['cve_id']}</span>
                    {render_severity_badge(dem['severity'])}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">{dem['title']}</div>
                <div class="highlight-diff" style="border-left-color: #ea580c; background-color: #fff7ed;">
                    <div style="font-size: 0.82rem; color: #9a3412; line-height: 1.6;">
                        <div><strong>Threat Feed:</strong> Verified Input Demonstration</div>
                        <div><strong>CISA KEV:</strong> Not confirmed in catalog</div>
                        <div><strong>EPSS Probability:</strong> <strong>45.0% (88.0th percentile)</strong></div>
                        <div><strong>Public PoC:</strong> <strong>Weaponized Exploit Available</strong></div>
                        <div><strong>Threat Factor Score (T):</strong> <strong>56.0 / 100</strong></div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Augmented ERS</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #ea580c;">{dem['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Decision</div>
                        {render_decision_badge(dem['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Jump Banner
    st.markdown(
        f"""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 18px; margin: 16px 0; display: flex; justify-content: space-around; align-items: center; text-align: center;">
            <div>
                <div class="detail-label">Threat Factor Jump</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #ea580c;">0.0 → 56.0 (+56.0 pts)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Composite ERS Escalation</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #dc2626;">+{comp['ers_jump']} pts (Accelerated Triage)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Provenance Integrity</div>
                <div style="font-size: 0.95rem; font-weight: 600; color: #475569;">Faithful zero-preservation when unpopulated</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(render_context_callout("Key Insight: Threat Intelligence Acceleration", comp["key_insight"]), unsafe_allow_html=True)


def render_scenario_c_view(comp: Dict[str, Any]) -> None:
    """Render Scenario C: Compensating Control Dampening."""
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
        render_scenario_story_card(
            before_text="Both hosts share CVSS 9.8 (Critical) for CVE-2023-38545 (libcurl heap buffer overflow).",
            change_text="Host 1 has active Cloudflare Enterprise WAF (M_control=0.85); Host 2 has no active L7 filtering (M_control=1.00).",
            after_text="Host 1 risk score is dampened by 8.61 points (57.40 down to 48.79); Host 2 remains at full 57.40 unmitigated risk.",
            why_text="Layer 7 inspection rules mitigate exploitation vectors, reducing operational risk while permanent patch is queued.",
        ),
        unsafe_allow_html=True,
    )

    col_prot, col_unprot = st.columns(2)

    prot = comp["protected_asset"]
    unprot = comp["unprotected_asset"]

    prot_controls_text = ", ".join(prot["controls"]) if prot.get("controls") else "None configured"
    unprot_controls_text = ", ".join(unprot["controls"]) if unprot.get("controls") else "None active"

    with col_prot:
        st.markdown(
            f"""
            <div class="detail-box" style="border: 2px solid #bbf7d0;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{prot['finding_id']} • {comp['shared_cve']}</span>
                    {render_severity_badge('CRITICAL')}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">Protected: {prot['hostname']}</div>
                <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 12px;">Asset ID: <code>{prot['asset_id']}</code> ({prot['environment']})</div>
                <div class="highlight-diff" style="border-left-color: #16a34a; background-color: #f0fdf4;">
                    <div style="font-size: 0.82rem; color: #14532d; line-height: 1.6;">
                        <div><strong>Active Controls:</strong> {prot_controls_text}</div>
                        <div><strong>Control Status:</strong> ACTIVE (Layer 7 Inspection)</div>
                        <div><strong>Unmitigated Risk (R):</strong> {prot['unmitigated_risk']} / 100</div>
                        <div><strong>Control Multiplier (M_control):</strong> <strong>{prot['control_multiplier']} (-15% dampening)</strong></div>
                        <div><strong>Points Dampened:</strong> <span style="font-size: 0.95rem; font-weight: 700; color: #166534;">-{prot['points_dampened']} pts</span></div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Dampened ERS</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #166534;">{prot['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Aegis Decision</div>
                        {render_decision_badge(prot['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with col_unprot:
        st.markdown(
            f"""
            <div class="detail-box">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                    <span class="detail-label">{unprot['finding_id']} • {comp['shared_cve']}</span>
                    {render_severity_badge('CRITICAL')}
                </div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a; margin-bottom: 6px;">Unmitigated: {unprot['hostname']}</div>
                <div style="font-size: 0.85rem; color: #64748b; margin-bottom: 12px;">Asset ID: <code>{unprot['asset_id']}</code> ({unprot['environment']})</div>
                <div class="highlight-diff" style="border-left-color: #94a3b8; background-color: #f8fafc;">
                    <div style="font-size: 0.82rem; color: #475569; line-height: 1.6;">
                        <div><strong>Active Controls:</strong> {unprot_controls_text}</div>
                        <div><strong>Control Multiplier (M_control):</strong> <span class="math-token">{unprot['control_multiplier']}</span> (1.00 = No reduction)</div>
                        <div><strong>Exposure Mitigation:</strong> None (Full environmental blast radius applies)</div>
                    </div>
                </div>
                <hr style="border-color: #e2e8f0; margin: 14px 0 10px 0;">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <div class="detail-label">Full Exposure ERS</div>
                        <span style="font-size: 1.6rem; font-weight: 700; color: #dc2626;">{unprot['environmental_risk_score']}</span>
                        <span style="font-size: 0.8rem; color: #64748b;"> / 100</span>
                    </div>
                    <div style="text-align: right;">
                        <div class="detail-label">Aegis Decision</div>
                        {render_decision_badge(unprot['aegis_decision'])}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Dampening Benefit Banner
    st.markdown(
        f"""
        <div style="background-color: #ffffff; border: 1px solid #e2e8f0; border-radius: 6px; padding: 12px 18px; margin: 16px 0; display: flex; justify-content: space-around; align-items: center; text-align: center;">
            <div>
                <div class="detail-label">Risk Dampening Credit</div>
                <div style="font-size: 1.15rem; font-weight: 700; color: #166534;">-{prot['points_dampened']} pts ({prot['control_multiplier']}x multiplier)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Vulnerability Lifecycle</div>
                <div style="font-size: 1.05rem; font-weight: 700; color: #0f172a;">Mitigated ≠ Removed (Patch Still Required)</div>
            </div>
            <div style="border-left: 1px solid #e2e8f0; height: 32px;"></div>
            <div>
                <div class="detail-label">Operational Benefit</div>
                <div style="font-size: 0.95rem; font-weight: 600; color: #2563eb;">Buys Triage Time for Orderly Maintenance</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(render_context_callout("Key Insight: Defense-in-Depth Dampening", comp["key_insight"]), unsafe_allow_html=True)


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

    st.markdown(
        render_scenario_story_card(
            before_text="5 distinct vulnerabilities on the critical customer database (ASSET-002) with varying CVSS (5.3 to 9.8).",
            change_text="All 5 vulnerabilities reside on the same mission-critical production database server.",
            after_text="A single planned maintenance window patches all 5 issues simultaneously, eliminating maximum compound risk.",
            why_text="Intra-asset sequencing groups patches by physical machine, eliminating compound blast radius in one maintenance shutdown.",
        ),
        unsafe_allow_html=True,
    )

    asset = comp["asset"]
    st.markdown(
        f"""
        <div class="detail-box" style="margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 12px;">
                <div>
                    <span style="font-size: 1.15rem; font-weight: 700; color: #0f172a;">Hotspot Host: {asset['hostname']}</span>
                    <span style="color: #64748b; font-size: 0.9rem; margin-left: 6px;">(<code>{asset['asset_id']}</code>)</span>
                    <div style="font-size: 0.85rem; color: #475569; margin-top: 4px;">
                        Environment: <strong>{asset['environment']}</strong> • Criticality: <strong>{asset['criticality']}</strong> • Exposure: <strong>{asset['network_exposure']}</strong>
                    </div>
                </div>
                <div style="display: flex; gap: 16px; text-align: center;">
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
        render_scenario_story_card(
            before_text="Same CVE-2023-38545 (libcurl) with static CVSS 9.8 present on 4 different machines across the company.",
            change_text="Assets span from Internet-facing production gateway to non-prod sandbox and air-gapped vault.",
            after_text="ERS spreads across 15.02 points (from 48.79 PLAN down to 33.77 TRACK).",
            why_text="Vulnerability danger is not an intrinsic property of software alone—it depends on the machine executing it.",
        ),
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

    # Capacity utilization bar
    st.markdown(render_capacity_bar(plan_result['total_scheduled_effort_hours'], plan_result['capacity_limit_hours']), unsafe_allow_html=True)

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
        finding = findings.get(r["finding_id"])
        asset = assets.get(finding.asset_id) if finding else None
        biz_area = derive_business_area(finding, asset)
        df_data.append(
            {
                "Status": r["status"],
                "Rank": f"#{r['rank']}",
                "Candidate ID": r["candidate_id"],
                "Finding ID": r["finding_id"],
                "CVE ID": r["cve_id"],
                "Business Area": biz_area,
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
            "Business Area": st.column_config.TextColumn("Business Area", width="medium"),
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


def render_patch_plan_view(
    findings: Dict[str, VulnerabilityFinding],
    assets: Dict[str, Asset],
    assessments: Dict[str, RiskAssessment],
) -> None:
    """Render the dedicated enterprise Patch Plan orchestration view."""
    # 1. Header & Purpose
    st.markdown(
        """
        <div class="section-header">
            <h3 class="section-title">Remediation Patch Plan</h3>
            <div class="section-subtitle">Recommended remediation schedule for the upcoming 16-hour maintenance window</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # 2. Mandatory Human Approval Callout
    st.markdown(render_human_approval_callout(), unsafe_allow_html=True)

    # Build candidates and solve optimization for default 16h window
    candidates = build_patch_candidates(findings, assets, assessments)
    plan_result = optimize_patch_schedule(candidates, DEFAULT_MAINTENANCE_CAPACITY_HOURS, findings, assets)

    # 3. Capacity Utilization Progress Bar
    st.markdown(
        render_capacity_bar(
            plan_result["total_scheduled_effort_hours"],
            plan_result["capacity_limit_hours"],
        ),
        unsafe_allow_html=True,
    )

    # 4. Summary Metric Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(
            render_metric_card(
                "Maintenance Window",
                f"{plan_result['capacity_limit_hours']} hrs",
                "Approved operational labor budget",
            ),
            unsafe_allow_html=True,
        )
    with k2:
        st.markdown(
            render_metric_card(
                "Scheduled Effort",
                f"{plan_result['total_scheduled_effort_hours']} hrs",
                f"{plan_result['remaining_capacity_hours']} hrs buffer remaining",
            ),
            unsafe_allow_html=True,
        )
    with k3:
        st.markdown(
            render_metric_card(
                "Total Risk Reduction",
                f"{plan_result['total_expected_risk_reduction']} pts",
                "Contextual ERS eliminated this window",
            ),
            unsafe_allow_html=True,
        )
    with k4:
        st.markdown(
            render_metric_card(
                "Patches Scheduled",
                f"{plan_result['scheduled_count']} of {len(candidates)}",
                f"{plan_result['deferred_count']} deferred to next window",
            ),
            unsafe_allow_html=True,
        )

    st.markdown("<div style='height: 16px;'></div>", unsafe_allow_html=True)

    # 5. Scheduled Candidates Table
    st.markdown(
        f"""
        <div class="section-header">
            <h4 class="section-title" style="color: #166534;">Scheduled for Maintenance ({plan_result['scheduled_count']} Patches)</h4>
            <div class="section-subtitle">Optimal candidate combination fitting within available hours while maximizing risk reduction</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    sched_rows = []
    for r in plan_result["scheduled_candidates"]:
        finding = findings.get(r["finding_id"])
        asset = assets.get(finding.asset_id) if finding else None
        sched_rows.append(
            {
                "Rank": f"#{r['rank']}",
                "Candidate ID": r["candidate_id"],
                "CVE ID": r["cve_id"],
                "Title": finding.title if finding else "Unknown",
                "Business Area": derive_business_area(finding, asset),
                "Target Hostname": r["hostname"],
                "Environment": r["environment"],
                "Risk Tier": r["risk_tier"],
                "Effort (Hours)": r["estimated_cost_hours"],
                "Risk Reduction": r["expected_risk_reduction"],
                "Efficiency Ratio": r["efficiency_ratio"],
            }
        )

    df_sched = pd.DataFrame(sched_rows)
    st.dataframe(
        df_sched,
        width="stretch",
        hide_index=True,
        column_config={
            "Rank": st.column_config.TextColumn("Rank", width="small"),
            "Candidate ID": st.column_config.TextColumn("Candidate", width="small"),
            "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
            "Title": st.column_config.TextColumn("Vulnerability Title", width="large"),
            "Business Area": st.column_config.TextColumn("Business Area", width="medium"),
            "Target Hostname": st.column_config.TextColumn("Target Host", width="medium"),
            "Environment": st.column_config.TextColumn("Env", width="small"),
            "Risk Tier": st.column_config.TextColumn("Risk Tier", width="small"),
            "Effort (Hours)": st.column_config.NumberColumn("Effort (h)", format="%.1f", width="small"),
            "Risk Reduction": st.column_config.NumberColumn("Risk Reduction", format="%.2f", width="small"),
            "Efficiency Ratio": st.column_config.NumberColumn("Efficiency", format="%.2f", width="small"),
        },
    )

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # 6. Deferred Candidates Table with Explicit Reasons
    st.markdown(
        f"""
        <div class="section-header">
            <h4 class="section-title" style="color: #475569;">Deferred Remediation Candidates ({plan_result['deferred_count']} Patches)</h4>
            <div class="section-subtitle">Candidates deferred to the next maintenance cycle with explicit operational rationale</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    def_rows = []
    rem_hours = plan_result["remaining_capacity_hours"]
    for r in plan_result["deferred_candidates"]:
        finding = findings.get(r["finding_id"])
        asset = assets.get(finding.asset_id) if finding else None
        effort = r["estimated_cost_hours"]

        if effort > rem_hours:
            defer_reason = f"Exceeds remaining window buffer ({rem_hours:.1f}h available vs {effort:.1f}h required); queued for cycle 2"
        else:
            defer_reason = f"Lower risk efficiency ratio ({r['efficiency_ratio']:.2f}) than scheduled candidates; deferred per knapsack policy"

        def_rows.append(
            {
                "Rank": f"#{r['rank']}",
                "Candidate ID": r["candidate_id"],
                "CVE ID": r["cve_id"],
                "Business Area": derive_business_area(finding, asset),
                "Target Hostname": r["hostname"],
                "Effort (Hours)": effort,
                "Risk Reduction": r["expected_risk_reduction"],
                "Operational Reason for Deferral": defer_reason,
            }
        )

    df_def = pd.DataFrame(def_rows)
    st.dataframe(
        df_def,
        width="stretch",
        hide_index=True,
        column_config={
            "Rank": st.column_config.TextColumn("Rank", width="small"),
            "Candidate ID": st.column_config.TextColumn("Candidate", width="small"),
            "CVE ID": st.column_config.TextColumn("CVE ID", width="medium"),
            "Business Area": st.column_config.TextColumn("Business Area", width="medium"),
            "Target Hostname": st.column_config.TextColumn("Target Host", width="medium"),
            "Effort (Hours)": st.column_config.NumberColumn("Effort (h)", format="%.1f", width="small"),
            "Risk Reduction": st.column_config.NumberColumn("Risk Reduction", format="%.2f", width="small"),
            "Operational Reason for Deferral": st.column_config.TextColumn("Reason for Deferral", width="large"),
        },
    )

    # 7. Expandable Knapsack & Optimization Explanation
    st.markdown("<div style='height: 14px;'></div>", unsafe_allow_html=True)
    with st.expander("📐 How Patch Plan Optimization Works (Knapsack Algorithm & Safety Constraints)"):
        st.markdown(
            """
            **Optimization Formulation:**
            - **Problem Type:** 0/1 Knapsack Optimization under operational constraints (`POL-SEC-04-patching.md §4.2.2`).
            - **Objective Function:** $\\max \\sum_{i} x_i \\cdot \\Delta R_i$ subject to $\\sum_{i} x_i \\cdot c_i \\le C_{limit}$, where $x_i \\in \\{0, 1\\}$.
            - **Efficiency Ratio:** $\\text{Ratio}_i = \\frac{\\Delta R_i}{c_i}$ (Risk Reduction per Engineering Hour).
            - **Deterministic Tie-Breaking:** If two candidates yield identical efficiency, priority is given to the higher absolute risk reduction, then lower candidate ID.
            - **Safety Guarantee:** Aegis Patch creates prioritized patch plans with explicit rollback verifications. All production deployments require human operator approval.
            """
        )
