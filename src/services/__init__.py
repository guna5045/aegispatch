"""Services package for Aegis Patch."""

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
    get_top_findings,
    load_benchmark_findings,
    load_cmdb_assets,
)
from src.services.scenario_service import (
    DEFAULT_MAINTENANCE_CAPACITY_HOURS,
    build_patch_candidates,
    estimate_patch_effort_hours,
    get_scenario_comparison_a,
    get_scenario_comparison_b,
    get_scenario_comparison_c,
    get_scenario_comparison_d,
    get_scenario_comparison_e,
    load_benchmark_scenarios,
    optimize_patch_schedule,
)
from src.services.persistence_service import PersistenceService
from src.services.vulnerability_service import (
    filter_vulnerabilities,
    get_investigation_detail,
    get_prioritized_table_records,
    search_findings,
)

__all__ = [
    "load_cmdb_assets",
    "load_benchmark_findings",
    "evaluate_benchmark_risks",
    "get_top_findings",
    "get_finding_context",
    "compute_dashboard_kpis",
    "compute_decision_distribution",
    "compute_severity_distribution",
    "compute_ers_distribution",
    "aggregate_assets_by_risk",
    "filter_findings",
    "get_priority_preview",
    # Vulnerability Service (Phase 4C)
    "search_findings",
    "filter_vulnerabilities",
    "get_prioritized_table_records",
    "get_investigation_detail",
    # Scenario Service (Phase 4D)
    "DEFAULT_MAINTENANCE_CAPACITY_HOURS",
    "load_benchmark_scenarios",
    "get_scenario_comparison_a",
    "get_scenario_comparison_b",
    "get_scenario_comparison_c",
    "get_scenario_comparison_d",
    "get_scenario_comparison_e",
    "estimate_patch_effort_hours",
    "build_patch_candidates",
    "optimize_patch_schedule",
    # Persistence Service (Phase 5E)
    "PersistenceService",
]
