"""User interface package for Aegis Patch."""

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

__all__ = [
    "SOC_CSS",
    "create_decision_chart",
    "create_ers_bands_chart",
    "create_severity_chart",
    "render_context_callout",
    "render_decision_badge",
    "render_filter_counter",
    "render_metric_card",
    "render_scheduled_badge",
    "render_severity_badge",
    "render_status_pill",
    "render_threat_badge",
    "render_vulnerability_investigation_view",
    # Scenario Views (Phase 4D)
    "render_scenario_header",
    "render_scenario_a_view",
    "render_scenario_b_view",
    "render_scenario_c_view",
    "render_scenario_d_view",
    "render_scenario_e_view",
    "render_what_if_capacity_view",
]
