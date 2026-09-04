"""Enterprise light theme design styling and theme tokens for Aegis Patch."""

SOC_CSS = """
<style>
/* Base typography and body styling */
html, body, [class*="css"] {
    color: #0f172a;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
}

/* Metric card containers */
.soc-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 16px 20px;
    margin-bottom: 12px;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
}

.soc-card-title {
    color: #64748b;
    font-size: 0.78rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin-bottom: 6px;
}

.soc-card-value {
    color: #0f172a;
    font-size: 1.8rem;
    font-weight: 700;
    line-height: 1.2;
}

.soc-card-caption {
    color: #64748b;
    font-size: 0.78rem;
    margin-top: 4px;
}

/* Status Badges */
.status-badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
    letter-spacing: 0.02em;
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

/* Decision Band Tags - Light semantic backgrounds */
.decision-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-align: center;
    letter-spacing: 0.04em;
}

.decision-act {
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
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
    color: #166534;
}

/* Section Header */
.section-header {
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 8px;
    margin-top: 24px;
    margin-bottom: 16px;
}

.section-title {
    color: #0f172a;
    font-size: 1.15rem;
    font-weight: 600;
    letter-spacing: 0.01em;
    margin: 0;
}

.section-subtitle {
    color: #64748b;
    font-size: 0.85rem;
    margin-top: 4px;
}

/* Asset and Context Detail Grid */
.detail-box {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 16px 20px;
    height: 100%;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
}

.detail-label {
    color: #64748b;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
}

.detail-val {
    color: #0f172a;
    font-size: 0.95rem;
    font-weight: 600;
    margin-top: 2px;
}

/* Compensating Controls Tag */
.control-tag {
    display: inline-block;
    background-color: #f8fafc;
    border: 1px solid #cbd5e1;
    color: #334155;
    padding: 3px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 500;
    margin-right: 6px;
    margin-bottom: 6px;
}

/* Table styling helpers */
.table-header-row {
    border-bottom: 2px solid #e2e8f0;
    padding-bottom: 8px;
    margin-bottom: 8px;
    font-weight: 600;
    color: #475569;
    font-size: 0.82rem;
    text-transform: uppercase;
    letter-spacing: 0.04em;
}

/* Context Callout Box */
.context-callout {
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    border-left: 4px solid #2563eb;
    border-radius: 6px;
    padding: 16px 20px;
    margin: 16px 0;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.03);
}

.context-callout-title {
    color: #1e3a8a;
    font-size: 0.95rem;
    font-weight: 700;
    margin-bottom: 4px;
}

.context-callout-body {
    color: #334155;
    font-size: 0.88rem;
    line-height: 1.55;
}

/* Filter Card */
.filter-card {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 14px 18px 8px 18px;
    margin-bottom: 20px;
    box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.04);
}

.filter-counter {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    color: #334155;
    padding: 3px 10px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
}

/* Investigation View Styles */
.investigation-banner {
    background-color: #ffffff;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 20px 24px;
    margin-bottom: 16px;
    box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.04);
}

.threat-badge-confirmed {
    display: inline-block;
    background-color: #fef2f2;
    border: 1px solid #fecaca;
    color: #991b1b;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
}

.threat-badge-not-confirmed {
    display: inline-block;
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    color: #475569;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 500;
}

.threat-badge-not-available {
    display: inline-block;
    background-color: #f8fafc;
    border: 1px solid #e2e8f0;
    color: #64748b;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-style: italic;
}

.math-token {
    background-color: #f1f5f9;
    border: 1px solid #cbd5e1;
    padding: 2px 6px;
    border-radius: 3px;
    font-family: monospace;
    font-size: 0.85rem;
    color: #0f172a;
    font-weight: 600;
}

.highlight-diff {
    background-color: #eff6ff;
    border-left: 3px solid #2563eb;
    padding: 8px 12px;
    border-radius: 0 4px 4px 0;
    margin: 4px 0;
}

.status-scheduled {
    display: inline-block;
    background-color: #f0fdf4;
    border: 1px solid #bbf7d0;
    color: #166534;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
}

.status-deferred {
    display: inline-block;
    background-color: #fefce8;
    border: 1px solid #fef08a;
    color: #854d0e;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.78rem;
    font-weight: 600;
}

.severity-badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 0.76rem;
    font-weight: 600;
    text-align: center;
    letter-spacing: 0.04em;
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
</style>
"""


def render_metric_card(title: str, value: str, caption: str = "") -> str:
    """Render a styled enterprise light metric card HTML snippet."""
    caption_html = f'<div class="soc-card-caption">{caption}</div>' if caption else ""
    return f"""
    <div class="soc-card">
        <div class="soc-card-title">{title}</div>
        <div class="soc-card-value">{value}</div>
        {caption_html}
    </div>
    """


def render_status_pill(label: str, status_type: str = "operational") -> str:
    """Render an accessible status badge with text and visual indicator."""
    css_class = f"status-{status_type}"
    return f'<span class="status-badge {css_class}">● {label}</span>'


def render_decision_badge(decision: str) -> str:
    """Render a colored badge for ACT, ATTEND, PLAN, TRACK decisions."""
    css_class = f"decision-{decision.lower()}" if decision.lower() in ("act", "attend", "plan", "track") else "status-neutral"
    return f'<span class="decision-badge {css_class}">{decision}</span>'


def render_severity_badge(severity: str) -> str:
    """Render a colored badge for CRITICAL, HIGH, MEDIUM, LOW severity."""
    css_class = f"severity-{severity.lower()}" if severity.lower() in ("critical", "high", "medium", "low") else "severity-low"
    return f'<span class="severity-badge {css_class}">{severity}</span>'


def render_threat_badge(status: str) -> str:
    """Render a threat indicator badge for Confirmed, Not confirmed, or Not available."""
    clean = status.strip().lower()
    if clean == "confirmed":
        return f'<span class="threat-badge-confirmed">● Confirmed</span>'
    elif "not available" in clean or clean == "n/a":
        return f'<span class="threat-badge-not-available">Not available</span>'
    else:
        return f'<span class="threat-badge-not-confirmed">○ Not confirmed</span>'


def render_context_callout(title: str, body: str) -> str:
    """Render an enterprise narrative callout box."""
    return f"""
    <div class="context-callout">
        <div class="context-callout-title">{title}</div>
        <div class="context-callout-body">{body}</div>
    </div>
    """


def render_filter_counter(active_count: int, total_count: int) -> str:
    """Render filter count badge."""
    if active_count == total_count:
        text = f"Showing all {total_count} findings"
    else:
        text = f"Showing {active_count} of {total_count} findings"
    return f'<span class="filter-counter">🔍 {text}</span>'


def render_scheduled_badge(status: str) -> str:
    """Render a badge for SCHEDULED or DEFERRED candidate status."""
    clean = status.strip().upper()
    if clean == "SCHEDULED":
        return '<span class="status-scheduled">● SCHEDULED</span>'
    else:
        return '<span class="status-deferred">⏳ DEFERRED</span>'



