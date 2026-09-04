"""Deterministic calculation, analysis, and agentic tools package.

Phase 3 calculation functions and decision mapping are fully preserved.
Phase 7 adds 17 deterministic tool capabilities organized under the ToolRegistry.
"""

from src.tools.decision_mapping import (
    DECISION_MEANINGS,
    DECISION_THRESHOLD_ACT,
    DECISION_THRESHOLD_ATTEND,
    DECISION_THRESHOLD_PLAN,
    DECISION_THRESHOLD_TRACK,
    DECISION_TO_REMEDIATION,
    DECISION_TO_RISK_TIER,
    ERS_MAX_SCORE,
    ERS_MIN_SCORE,
    AegisDecision,
    DecisionResult,
    get_decision_details,
    map_ers_to_decision,
    map_ers_to_remediation_decision,
    map_ers_to_risk_tier,
)
from src.tools.risk_config import (
    CONTROL_DISCOUNTS,
    CONTROL_MULTIPLIER_MAX,
    CONTROL_MULTIPLIER_MIN,
    CRITICALITY_SCORES,
    CVSS_BASE_SCALE,
    EXPOSURE_SCORES,
    SENSITIVITY_SCORES,
    THREAT_SCORE_KEV,
    THREAT_WEIGHT_EPSS,
    THREAT_WEIGHT_POC,
    TIER_THRESHOLD_CRITICAL,
    TIER_THRESHOLD_HIGH,
    TIER_THRESHOLD_LOW,
    TIER_THRESHOLD_MEDIUM,
    WEIGHT_BASE_CVSS,
    WEIGHT_ENV_CRITICALITY,
    WEIGHT_ENV_EXPOSURE,
    WEIGHT_ENV_SENSITIVITY,
    WEIGHT_ENVIRONMENTAL,
    WEIGHT_THREAT,
    determine_remediation_decision,
    determine_risk_tier,
)
from src.tools.risk_engine import (
    build_supporting_evidence,
    calculate_base_score,
    calculate_control_multiplier,
    calculate_environmental_score,
    calculate_ers,
    calculate_threat_score,
    calculate_weighted_risk,
    evaluate_risk,
    generate_risk_explanation,
)

# Phase 7 Tools
from src.tools.scan_tools import (
    deduplicate_findings,
    parse_raw_scan,
    validate_finding_schema,
)
from src.tools.threat_tools import (
    lookup_cisa_kev,
    query_epss,
    query_osv_database,
)
from src.tools.asset_tools import (
    get_network_reachability,
    query_asset_cmdb,
    query_rag_policy,
)
from src.tools.risk_tools import (
    calculate_environmental_risk,
    map_ssvc_decision,
)
from src.tools.planning_tools import (
    optimize_patch_capacity,
    resolve_package_dependencies,
    simulate_risk_reduction,
)
from src.tools.verification_tools import (
    detect_hallucinated_claims,
    validate_plan_constraints,
    verify_score_derivation,
)
from src.tools.registry import (
    ToolDefinition,
    ToolRegistry,
    build_default_tool_registry,
    default_tool_registry,
)

__all__ = [
    # Calculation Functions (Phase 3)
    "calculate_base_score",
    "calculate_threat_score",
    "calculate_environmental_score",
    "calculate_control_multiplier",
    "calculate_weighted_risk",
    "calculate_ers",
    "evaluate_risk",
    "generate_risk_explanation",
    "build_supporting_evidence",
    # Decision Mapping (Phase 3B)
    "AegisDecision",
    "DecisionResult",
    "map_ers_to_decision",
    "map_ers_to_risk_tier",
    "map_ers_to_remediation_decision",
    "get_decision_details",
    "DECISION_THRESHOLD_ACT",
    "DECISION_THRESHOLD_ATTEND",
    "DECISION_THRESHOLD_PLAN",
    "DECISION_THRESHOLD_TRACK",
    "ERS_MIN_SCORE",
    "ERS_MAX_SCORE",
    "DECISION_MEANINGS",
    "DECISION_TO_RISK_TIER",
    "DECISION_TO_REMEDIATION",
    # Configuration and Helpers (Phase 3)
    "determine_risk_tier",
    "determine_remediation_decision",
    "TIER_THRESHOLD_CRITICAL",
    "TIER_THRESHOLD_HIGH",
    "TIER_THRESHOLD_MEDIUM",
    "TIER_THRESHOLD_LOW",
    "CVSS_BASE_SCALE",
    "WEIGHT_BASE_CVSS",
    "WEIGHT_THREAT",
    "WEIGHT_ENVIRONMENTAL",
    "WEIGHT_ENV_CRITICALITY",
    "WEIGHT_ENV_EXPOSURE",
    "WEIGHT_ENV_SENSITIVITY",
    "THREAT_SCORE_KEV",
    "THREAT_WEIGHT_EPSS",
    "THREAT_WEIGHT_POC",
    "CRITICALITY_SCORES",
    "EXPOSURE_SCORES",
    "SENSITIVITY_SCORES",
    "CONTROL_DISCOUNTS",
    "CONTROL_MULTIPLIER_MIN",
    "CONTROL_MULTIPLIER_MAX",
    # Phase 7 Deterministic Tools
    "parse_raw_scan",
    "validate_finding_schema",
    "deduplicate_findings",
    "lookup_cisa_kev",
    "query_epss",
    "query_osv_database",
    "query_asset_cmdb",
    "get_network_reachability",
    "query_rag_policy",
    "calculate_environmental_risk",
    "map_ssvc_decision",
    "optimize_patch_capacity",
    "resolve_package_dependencies",
    "simulate_risk_reduction",
    "verify_score_derivation",
    "detect_hallucinated_claims",
    "validate_plan_constraints",
    # Phase 7 Registry
    "ToolDefinition",
    "ToolRegistry",
    "build_default_tool_registry",
    "default_tool_registry",
]
