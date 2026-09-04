"""Enterprise light theme design styling and theme tokens for Aegis Patch.

Modern, readable, enterprise-grade security styling prioritizing clarity,
progressive disclosure, and visual hierarchy.
"""

from __future__ import annotations
import html
from typing import Any, Dict, List, Optional


SOC_CSS = """
<style>
/* Base typography and body styling */
html, body, [class*="css"] {
    color: #0f172a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* Hide raw sidebar collapse button if needed, or style it */
[data-testid="stSidebarCollapseButton"] {
    display: block;
}

/* Main content spacing */
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 3.5rem;
    max-width: 1380px;
}

/* Top Header Bar */
.aegis-header {
    background: linear-gradient(180deg, #ffffff 0%, #f8fafc 100%);
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px 24px;
    margin-bottom: 24px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.05);
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
}

.aegis-brand-title {
    font-size: 1.45rem;
    font-weight: 800;
    color: #0f172a;
    letter-spacing: -0.02em;
    display: flex;
    align-items: center;
    gap: 8px;
}

.aegis-brand-badge {
    font-size: 0.72rem;
    font-weight: 700;
    background-color: #eff6ff;
    color: #1d4ed8;
    border: 1px solid #bfdbfe;
    padding: 2px 8px;
    border-radius: 9999px;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

.aegis-brand-subtitle {
    font-size: 0.85rem;
    color: #475569;
    font-weight: 500;
    margin-top: 2px;
}

/* Metric card containers */
.soc-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 18px 20px;
    margin-bottom: 14px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.04);
    transition: transform 0.15s ease, box-shadow 0.15s ease;
}

.soc-card:hover {
    box-shadow: 0 4px 6px -1px rgba(15, 23, 42, 0.08);
}

.soc-card-title {
    color: #475569;
    font-size: 0.82rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.04em;
    margin-bottom: 6px;
}

.soc-card-value {
    color: #0f172a;
    font-size: 2.1rem;
    font-weight: 800;
    line-height: 1.15;
}

.soc-card-caption {
    color: #64748b;
    font-size: 0.82rem;
    margin-top: 6px;
    line-height: 1.4;
}

/* Status Badges */
.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 600;
}

.status-operational {
    background-color: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #15803d;
}

.status-loaded {
    background-color: #eff6ff;
    border: 1px solid #bfdbfe;
    color: #1d4ed8;
}

.status-neutral {
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    color: #475569;
}

/* Decision Band Tags */
.decision-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 0.82rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    white-space: nowrap;
}

.decision-act {
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #b91c1c;
}

.decision-attend {
    background-color: #fff7ed;
    border: 1px solid #fed7aa;
    color: #c2410c;
}

.decision-plan {
    background-color: #fefce8;
    border: 1px solid #fef08a;
    color: #854d0e;
}

.decision-track {
    background-color: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #15803d;
}

/* Severity Badges */
.severity-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0.03em;
    white-space: nowrap;
}

.severity-critical {
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
}

.severity-high {
    background-color: #fff7ed;
    border: 1px solid #fed7aa;
    color: #c2410c;
}

.severity-medium {
    background-color: #fefce8;
    border: 1px solid #fef08a;
    color: #854d0e;
}

.severity-low {
    background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #475569;
}

/* Threat Badges */
.threat-badge-confirmed {
    display: inline-block;
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 700;
}

.threat-badge-not-confirmed {
    display: inline-block;
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    color: #475569;
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
}

.threat-badge-not-available {
    display: inline-block;
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    color: #64748b;
    padding: 3px 9px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-style: italic;
}

/* Business Area Tag */
.business-area-tag {
    display: inline-flex;
    align-items: center;
    background-color: #f1f5f9;
    color: #334155;
    border: 1px solid #e2e8f0;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
}

/* Detail Box Container */
.detail-box {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px 20px;
    margin-bottom: 14px;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03);
}

.detail-label {
    color: #64748b;
    font-size: 0.76rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}

.detail-val {
    color: #0f172a;
    font-size: 1.05rem;
    font-weight: 700;
}

/* Context Callout Narrative */
.context-callout {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-left: 5px solid #1d4ed8;
    border-radius: 8px;
    padding: 16px 20px;
    margin: 16px 0 20px 0;
    box-shadow: 0 1px 3px rgba(15, 23, 42, 0.03);
}

.context-callout-title {
    color: #0f172a;
    font-size: 1.05rem;
    font-weight: 700;
    margin-bottom: 6px;
    display: flex;
    align-items: center;
    gap: 8px;
}

.context-callout-body {
    color: #334155;
    font-size: 0.92rem;
    line-height: 1.6;
}

/* Safety & Human Approval Banner */
.human-approval-banner {
    background: linear-gradient(90deg, #f8fafc 0%, #ffffff 100%);
    border: 1px solid #cbd5e1;
    border-left: 5px solid #0f172a;
    border-radius: 8px;
    padding: 14px 20px;
    margin: 16px 0;
    display: flex;
    align-items: center;
    gap: 14px;
}

.human-approval-title {
    font-weight: 800;
    font-size: 0.95rem;
    color: #0f172a;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}

.human-approval-text {
    font-size: 0.88rem;
    color: #475569;
    margin-top: 2px;
}

/* Section Header Component */
.section-header {
    margin: 24px 0 14px 0;
    padding-bottom: 6px;
    border-bottom: 1px solid #f1f5f9;
}

.section-title {
    color: #0f172a;
    font-size: 1.25rem;
    font-weight: 800;
    letter-spacing: -0.01em;
    margin: 0;
}

.section-subtitle {
    color: #64748b;
    font-size: 0.88rem;
    margin-top: 4px;
    line-height: 1.4;
}

/* Specialist Agent Card */
.agent-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    padding: 16px 18px;
    margin-bottom: 12px;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04);
}

.agent-card-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 8px;
}

.agent-card-title {
    font-size: 0.95rem;
    font-weight: 800;
    color: #0f172a;
    display: flex;
    align-items: center;
    gap: 8px;
}

.agent-badge-done {
    background-color: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
    font-size: 0.72rem;
    font-weight: 700;
    padding: 2px 8px;
    border-radius: 9999px;
}

.agent-card-desc {
    font-size: 0.88rem;
    color: #334155;
    line-height: 1.45;
    margin-bottom: 6px;
}

.agent-tools-tag {
    font-family: monospace;
    font-size: 0.75rem;
    background-color: #f1f5f9;
    color: #475569;
    padding: 2px 6px;
    border-radius: 4px;
    border: 1px solid #e2e8f0;
    margin-right: 4px;
}

/* Verification Result Box */
.verif-box {
    border-radius: 8px;
    padding: 18px 22px;
    margin: 16px 0;
}

.verif-box-pass {
    background-color: #f0fdf4;
    border: 1px solid #86efac;
    color: #14532d;
}

.verif-box-review {
    background-color: #fffbeb;
    border: 1px solid #fde68a;
    color: #78350f;
}

.verif-box-fail {
    background-color: #fef2f2;
    border: 1px solid #fca5a5;
    color: #7f1d1d;
}

/* Visual Story Flowchart */
.pipeline-flow {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
    gap: 10px;
    margin: 16px 0 24px 0;
}

.pipeline-step {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 14px;
    text-align: center;
    box-shadow: 0 1px 2px rgba(15, 23, 42, 0.03);
}

.pipeline-step-num {
    font-size: 0.7rem;
    font-weight: 800;
    color: #1d4ed8;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 4px;
}

.pipeline-step-label {
    font-size: 0.85rem;
    font-weight: 700;
    color: #0f172a;
}

/* Capacity Bar */
.capacity-bar-bg {
    background-color: #e2e8f0;
    border-radius: 9999px;
    height: 18px;
    width: 100%;
    overflow: hidden;
    margin: 10px 0 6px 0;
}

.capacity-bar-fill {
    background: linear-gradient(90deg, #2563eb 0%, #1d4ed8 100%);
    height: 100%;
    border-radius: 9999px;
    transition: width 0.3s ease;
}

/* Math Tokens */
.math-token {
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
    font-size: 0.86rem;
    color: #0f172a;
    font-weight: 600;
}

/* Filter Counter */
.filter-counter {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    color: #334155;
    padding: 4px 12px;
    border-radius: 9999px;
    font-size: 0.82rem;
    font-weight: 600;
}

/* Compensating Controls Tag */
.control-tag {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.8rem;
    color: #334155;
    margin-right: 6px;
    margin-bottom: 6px;
}

/* Interactive table container */
.stDataFrame {
    border: 1px solid #e2e8f0;
    border-radius: 8px;
    overflow: hidden;
}
</style>
"""


def render_metric_card(title: str, value: str, caption: str = "") -> str:
    """Render a styled enterprise light metric card HTML snippet."""
    safe_title = html.escape(title)
    safe_value = html.escape(value)
    caption_html = f'<div class="soc-card-caption">{html.escape(caption)}</div>' if caption else ""
    return f"""
    <div class="soc-card">
        <div class="soc-card-title">{safe_title}</div>
        <div class="soc-card-value">{safe_value}</div>
        {caption_html}
    </div>
    """


def render_status_pill(label: str, status_type: str = "operational") -> str:
    """Render an accessible status badge with text and visual indicator."""
    safe_label = html.escape(label)
    css_class = f"status-{status_type}"
    return f'<span class="status-badge {css_class}">● {safe_label}</span>'


def render_decision_badge(decision: str, human_readable: bool = True) -> str:
    """Render a colored badge for Aegis decisions with human-readable action label."""
    clean = decision.strip().upper()
    if clean == "ACT":
        css_class = "decision-act"
        label = "Fix Immediately (ACT)" if human_readable else "ACT"
        symbol = "🚨"
    elif clean == "ATTEND":
        css_class = "decision-attend"
        label = "Review Soon (ATTEND)" if human_readable else "ATTEND"
        symbol = "⚠️"
    elif clean == "PLAN":
        css_class = "decision-plan"
        label = "Plan Fix (PLAN)" if human_readable else "PLAN"
        symbol = "📅"
    elif clean == "TRACK":
        css_class = "decision-track"
        label = "Monitor (TRACK)" if human_readable else "TRACK"
        symbol = "👁️"
    else:
        css_class = "status-neutral"
        label = clean
        symbol = "●"
    return f'<span class="decision-badge {css_class}">{symbol} {html.escape(label)}</span>'


def render_severity_badge(severity: str) -> str:
    """Render a colored badge for CRITICAL, HIGH, MEDIUM, LOW severity."""
    clean = severity.strip().upper()
    css_class = f"severity-{clean.lower()}" if clean.lower() in ("critical", "high", "medium", "low") else "severity-low"
    return f'<span class="severity-badge {css_class}">{html.escape(clean)}</span>'


def render_risk_level_badge(tier: str) -> str:
    """Render a colored badge for Environmental Risk Level (Tier)."""
    return render_severity_badge(tier)


def render_threat_badge(status: str) -> str:
    """Render a threat indicator badge for Confirmed, Not confirmed, or Not available."""
    clean = status.strip().lower()
    if clean == "confirmed":
        return '<span class="threat-badge-confirmed">● Confirmed Active</span>'
    elif "not available" in clean or clean == "n/a":
        return '<span class="threat-badge-not-available">Intelligence not available</span>'
    else:
        return '<span class="threat-badge-not-confirmed">○ Not confirmed</span>'


def render_scheduled_badge(status: str) -> str:
    """Render a badge for SCHEDULED or DEFERRED candidate status."""
    clean = status.strip().upper()
    if clean == "SCHEDULED":
        return '<span class="status-badge status-operational">● Scheduled for Maintenance</span>'
    else:
        return '<span class="status-badge status-neutral">⏳ Deferred to Next Cycle</span>'


def render_business_area_tag(business_area: str) -> str:
    """Render a structured tag identifying the affected business functional area."""
    return f'<span class="business-area-tag">🏢 {html.escape(business_area)}</span>'


def render_context_callout(title: str, body: str) -> str:
    """Render an enterprise narrative callout box."""
    return f"""
    <div class="context-callout">
        <div class="context-callout-title">🛡️ {html.escape(title)}</div>
        <div class="context-callout-body">{html.escape(body)}</div>
    </div>
    """


def render_human_approval_callout() -> str:
    """Render the safety callout indicating human approval is required before patch deployment."""
    return """
    <div class="human-approval-banner">
        <div style="font-size: 1.5rem;">👤</div>
        <div>
            <div class="human-approval-title">Human Approval Required</div>
            <div class="human-approval-text">
                Aegis Patch models, prioritizes, and verifies remediation recommendations. It never silently
                modifies production infrastructure without authorized human operator sign-off.
            </div>
        </div>
    </div>
    """


def render_pipeline_story_cards() -> str:
    """Render the visual 6-stage investigation story pipeline."""
    steps = [
        ("Step 1", "Vulnerabilities Discovered", "Raw scanner findings parsed & deduplicated"),
        ("Step 2", "Environment Investigated", "Asset topology, CMDB & network reachability"),
        ("Step 3", "Threat Context Analyzed", "Real-world KEV, EPSS & exploit intelligence"),
        ("Step 4", "Aegis Risk Prioritized", "Contextual Environmental Risk Score (ERS)"),
        ("Step 5", "Patch Plan Created", "Capacity-aware 0/1 knapsack optimization"),
        ("Step 6", "Recommendation Verified", "Independent mathematical & claim grounding audit"),
    ]
    cards = []
    for num, label, desc in steps:
        cards.append(
            f"""
            <div class="pipeline-step">
                <div class="pipeline-step-num">{html.escape(num)}</div>
                <div class="pipeline-step-label">{html.escape(label)}</div>
                <div style="font-size: 0.74rem; color: #64748b; margin-top: 4px;">{html.escape(desc)}</div>
            </div>
            """
        )
    return f'<div class="pipeline-flow">{"".join(cards)}</div>'


def render_capacity_bar(scheduled_hours: float, capacity_hours: float) -> str:
    """Render a visual capacity utilization bar."""
    pct = min(100.0, max(0.0, (scheduled_hours / capacity_hours * 100.0) if capacity_hours > 0 else 0.0))
    bar_color = "#16a34a" if pct <= 90.0 else ("#ea580c" if pct <= 100.0 else "#dc2626")
    return f"""
    <div style="margin: 12px 0 16px 0;">
        <div style="display: flex; justify-content: space-between; font-size: 0.85rem; font-weight: 700; color: #334155; margin-bottom: 4px;">
            <span>Maintenance Window Capacity: {scheduled_hours:.1f}h planned of {capacity_hours:.1f}h total</span>
            <span>{pct:.1f}% Utilized</span>
        </div>
        <div class="capacity-bar-bg">
            <div class="capacity-bar-fill" style="width: {pct:.1f}%; background-color: {bar_color};"></div>
        </div>
    </div>
    """


def render_filter_counter(active_count: int, total_count: int) -> str:
    """Render filter count badge."""
    if active_count == total_count:
        text = f"Showing all {total_count} findings"
    else:
        text = f"Showing {active_count} of {total_count} findings"
    return f'<span class="filter-counter">🔍 {html.escape(text)}</span>'


def render_agent_card(
    step_num: int,
    agent_name: str,
    status: str,
    simple_desc: str,
    key_result: str,
    tools: List[str],
) -> str:
    """Render a card displaying a Phase 9 specialist agent execution."""
    safe_name = html.escape(agent_name)
    safe_desc = html.escape(simple_desc)
    safe_res = html.escape(key_result)
    tools_html = "".join([f'<span class="agent-tools-tag">{html.escape(t)}</span>' for t in tools])
    return f"""
    <div class="agent-card">
        <div class="agent-card-header">
            <div class="agent-card-title">
                <span style="color: #1d4ed8; font-size: 0.8rem;">Agent {step_num}</span>
                {safe_name}
            </div>
            <span class="agent-badge-done">✓ {html.escape(status)}</span>
        </div>
        <div class="agent-card-desc"><strong>What it checked:</strong> {safe_desc}</div>
        <div style="font-size: 0.84rem; color: #0f172a; margin-bottom: 8px;"><strong>Key outcome:</strong> {safe_res}</div>
        <div style="margin-top: 6px;">
            <span style="font-size: 0.72rem; color: #64748b; font-weight: 600; text-transform: uppercase;">Deterministic Tools:</span>
            {tools_html}
        </div>
    </div>
    """


def render_verification_card(
    status: str,
    overall_passed: bool,
    reasons: List[str],
) -> str:
    """Render the Verification Specialist Agent audit outcome card."""
    clean_status = status.upper()
    if overall_passed or clean_status == "VERIFIED":
        box_class = "verif-box-pass"
        icon = "✓"
        heading = "Recommendation Verified"
        sub = "Independent verification passed: mathematical derivation, claim grounding, and plan constraints validated."
    elif clean_status == "NEEDS_REVIEW":
        box_class = "verif-box-review"
        icon = "⚠️"
        heading = "Verification Notice: Review Required"
        sub = "Certain secondary checks require human operator review."
    else:
        box_class = "verif-box-fail"
        icon = "✕"
        heading = "Verification Rejected"
        sub = "Independent verification detected inconsistencies or unsupported assertions."

    reasons_html = "".join([f"<li>{html.escape(r)}</li>" for r in reasons]) if reasons else ""
    return f"""
    <div class="verif-box {box_class}">
        <div style="display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 1.15rem; margin-bottom: 4px;">
            <span>{icon}</span> {heading}
        </div>
        <div style="font-size: 0.88rem; line-height: 1.5; margin-bottom: 8px;">{sub}</div>
        {f'<ul style="margin: 0; padding-left: 20px; font-size: 0.84rem;">{reasons_html}</ul>' if reasons_html else ''}
    </div>
    """


def render_decision_factor_card(
    icon: str,
    title: str,
    value: str,
    explanation: str,
) -> str:
    """Render one of the 6 core decision factors in the investigation view."""
    return f"""
    <div class="detail-box" style="margin-bottom: 10px;">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 4px;">
            <span class="detail-label">{html.escape(icon)} {html.escape(title)}</span>
        </div>
        <div class="detail-val" style="font-size: 1.05rem; margin-bottom: 4px;">{html.escape(value)}</div>
        <div style="font-size: 0.82rem; color: #475569; line-height: 1.4;">{html.escape(explanation)}</div>
    </div>
    """
