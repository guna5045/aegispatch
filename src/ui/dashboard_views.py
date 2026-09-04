"""Chart and component rendering helpers for Aegis Patch security dashboard."""

from __future__ import annotations

from typing import Dict
import altair as alt
import pandas as pd


def create_decision_chart(decision_counts: Dict[str, int]) -> alt.Chart:
    """Create a clean horizontal bar chart for Aegis Patch decision distribution."""
    categories = ["ACT", "ATTEND", "PLAN", "TRACK"]
    colors = ["#dc2626", "#ea580c", "#2563eb", "#16a34a"]

    data = pd.DataFrame(
        {
            "Decision": categories,
            "Count": [decision_counts.get(cat, 0) for cat in categories],
        }
    )

    chart = (
        alt.Chart(data)
        .mark_bar(cornerRadiusEnd=3, height=20)
        .encode(
            x=alt.X(
                "Count:Q",
                title="Number of Findings",
                axis=alt.Axis(tickMinStep=1, format="d", gridColor="#f1f5f9"),
            ),
            y=alt.Y(
                "Decision:N",
                sort=categories,
                title=None,
                axis=alt.Axis(labelFontWeight="bold", labelColor="#0f172a"),
            ),
            color=alt.Color(
                "Decision:N",
                scale=alt.Scale(domain=categories, range=colors),
                legend=None,
            ),
            tooltip=["Decision:N", "Count:Q"],
        )
        .properties(height=180)
        .configure_view(strokeWidth=0)
    )

    return chart


def create_severity_chart(severity_counts: Dict[str, int]) -> alt.Chart:
    """Create a clean horizontal bar chart for intrinsic vulnerability severity distribution."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    colors = ["#991b1b", "#c2410c", "#d97706", "#64748b"]

    data = pd.DataFrame(
        {
            "Severity": severities,
            "Count": [severity_counts.get(sev, 0) for sev in severities],
        }
    )

    chart = (
        alt.Chart(data)
        .mark_bar(cornerRadiusEnd=3, height=20)
        .encode(
            x=alt.X(
                "Count:Q",
                title="Number of Findings",
                axis=alt.Axis(tickMinStep=1, format="d", gridColor="#f1f5f9"),
            ),
            y=alt.Y(
                "Severity:N",
                sort=severities,
                title=None,
                axis=alt.Axis(labelFontWeight="bold", labelColor="#0f172a"),
            ),
            color=alt.Color(
                "Severity:N",
                scale=alt.Scale(domain=severities, range=colors),
                legend=None,
            ),
            tooltip=["Severity:N", "Count:Q"],
        )
        .properties(height=180)
        .configure_view(strokeWidth=0)
    )

    return chart


def create_ers_bands_chart(ers_counts: Dict[str, int]) -> alt.Chart:
    """Create a clean horizontal bar chart for Environmental Risk Score (ERS) decision bands."""
    bands = ["ACT (85–100)", "ATTEND (65–<85)", "PLAN (40–<65)", "TRACK (0–<40)"]
    colors = ["#dc2626", "#ea580c", "#2563eb", "#16a34a"]

    data = pd.DataFrame(
        {
            "Score Band": bands,
            "Count": [ers_counts.get(band, 0) for band in bands],
        }
    )

    chart = (
        alt.Chart(data)
        .mark_bar(cornerRadiusEnd=3, height=20)
        .encode(
            x=alt.X(
                "Count:Q",
                title="Number of Findings",
                axis=alt.Axis(tickMinStep=1, format="d", gridColor="#f1f5f9"),
            ),
            y=alt.Y(
                "Score Band:N",
                sort=bands,
                title=None,
                axis=alt.Axis(labelFontWeight="bold", labelColor="#0f172a"),
            ),
            color=alt.Color(
                "Score Band:N",
                scale=alt.Scale(domain=bands, range=colors),
                legend=None,
            ),
            tooltip=["Score Band:N", "Count:Q"],
        )
        .properties(height=180)
        .configure_view(strokeWidth=0)
    )

    return chart
