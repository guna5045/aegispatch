"""Central Tool Registry for Aegis Patch.

Maintains discoverable metadata, schemas, and callables for all 17 deterministic
Phase 7 tools.
Framework-neutral design allows seamless integration with future agents in Phase 8+.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Type
from pydantic import BaseModel

from src.tools.asset_tools import get_network_reachability, query_asset_cmdb, query_rag_policy
from src.tools.planning_tools import optimize_patch_capacity, resolve_package_dependencies, simulate_risk_reduction
from src.tools.risk_tools import calculate_environmental_risk, map_ssvc_decision
from src.tools.scan_tools import deduplicate_findings, parse_raw_scan, validate_finding_schema
from src.tools.schemas import (
    BaseToolResult,
    CalculateEnvironmentalRiskInput,
    CalculateEnvironmentalRiskOutput,
    DeduplicateFindingsInput,
    DeduplicateFindingsOutput,
    DetectHallucinatedClaimsInput,
    DetectHallucinatedClaimsOutput,
    GetNetworkReachabilityInput,
    GetNetworkReachabilityOutput,
    LookupCisaKevInput,
    LookupCisaKevOutput,
    MapSsvcDecisionInput,
    MapSsvcDecisionOutput,
    OptimizePatchCapacityInput,
    OptimizePatchCapacityOutput,
    ParseRawScanInput,
    ParseRawScanOutput,
    QueryAssetCmdbInput,
    QueryAssetCmdbOutput,
    QueryEpssInput,
    QueryEpssOutput,
    QueryOsvDatabaseInput,
    QueryOsvDatabaseOutput,
    QueryRagPolicyInput,
    QueryRagPolicyOutput,
    ResolvePackageDependenciesInput,
    ResolvePackageDependenciesOutput,
    SideEffectClass,
    SimulateRiskReductionInput,
    SimulateRiskReductionOutput,
    ValidateFindingSchemaInput,
    ValidateFindingSchemaOutput,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
    VerifyScoreDerivationInput,
    VerifyScoreDerivationOutput,
)
from src.tools.threat_tools import lookup_cisa_kev, query_epss, query_osv_database
from src.tools.verification_tools import detect_hallucinated_claims, validate_plan_constraints, verify_score_derivation


@dataclass(frozen=True)
class ToolDefinition:
    """Metadata specification and invoker binding for a registered tool."""

    name: str
    description: str
    category: str
    side_effect: SideEffectClass
    input_schema: Type[BaseModel]
    output_schema: Type[BaseModel]
    handler: Callable[..., BaseToolResult]


class ToolRegistry:
    """Registry managing the complete inventory of Aegis Patch deterministic tools."""

    def __init__(self) -> None:
        self._tools: Dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        """Register a new tool definition. Enforces unique naming."""
        if tool.name in self._tools:
            raise ValueError(f"Tool with name '{tool.name}' is already registered.")
        self._tools[tool.name] = tool

    def get(self, name: str) -> Optional[ToolDefinition]:
        """Retrieve tool definition by machine-readable name."""
        return self._tools.get(name)

    def list_tools(self) -> List[ToolDefinition]:
        """Return all registered tools sorted by name."""
        return sorted(self._tools.values(), key=lambda t: t.name)

    def list_by_category(self, category: str) -> List[ToolDefinition]:
        """List registered tools matching a specific functional category."""
        return [t for t in self.list_tools() if t.category.upper() == category.upper()]

    def invoke(self, name: str, input_payload: BaseModel | Dict[str, Any], **kwargs: Any) -> BaseToolResult:
        """Invoke a tool by name with validated input payload."""
        tool = self.get(name)
        if not tool:
            raise KeyError(f"No tool registered under name '{name}'.")

        # Validate input against input_schema if dict is passed
        if isinstance(input_payload, dict):
            validated_input = tool.input_schema.model_validate(input_payload)
        else:
            validated_input = input_payload

        return tool.handler(validated_input, **kwargs)

    @property
    def count(self) -> int:
        """Total number of registered tools."""
        return len(self._tools)


def build_default_tool_registry() -> ToolRegistry:
    """Instantiate and populate the canonical Aegis Patch Tool Registry with all 17 tools."""
    registry = ToolRegistry()

    # 1. parse_raw_scan
    registry.register(
        ToolDefinition(
            name="parse_raw_scan",
            description="Parse raw scanner output JSON or records into normalized VulnerabilityFinding objects.",
            category="SCAN",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=ParseRawScanInput,
            output_schema=ParseRawScanOutput,
            handler=parse_raw_scan,
        )
    )

    # 2. validate_finding_schema
    registry.register(
        ToolDefinition(
            name="validate_finding_schema",
            description="Validate candidate vulnerability data against authoritative VulnerabilityFinding schema.",
            category="SCAN",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=ValidateFindingSchemaInput,
            output_schema=ValidateFindingSchemaOutput,
            handler=validate_finding_schema,
        )
    )

    # 3. deduplicate_findings
    registry.register(
        ToolDefinition(
            name="deduplicate_findings",
            description="Identify duplicate findings using (asset_id, cve_id, package) identity tuples.",
            category="SCAN",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=DeduplicateFindingsInput,
            output_schema=DeduplicateFindingsOutput,
            handler=deduplicate_findings,
        )
    )

    # 4. lookup_cisa_kev
    registry.register(
        ToolDefinition(
            name="lookup_cisa_kev",
            description="Query local CISA Known Exploited Vulnerabilities (KEV) dataset/cache offline.",
            category="THREAT",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=LookupCisaKevInput,
            output_schema=LookupCisaKevOutput,
            handler=lookup_cisa_kev,
        )
    )

    # 5. query_epss
    registry.register(
        ToolDefinition(
            name="query_epss",
            description="Query Exploit Prediction Scoring System (EPSS) telemetry from local database/cache.",
            category="THREAT",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryEpssInput,
            output_schema=QueryEpssOutput,
            handler=query_epss,
        )
    )

    # 6. query_osv_database
    registry.register(
        ToolDefinition(
            name="query_osv_database",
            description="Query local Open Source Vulnerabilities (OSV) package advisory database.",
            category="THREAT",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryOsvDatabaseInput,
            output_schema=QueryOsvDatabaseOutput,
            handler=query_osv_database,
        )
    )

    # 7. query_asset_cmdb
    registry.register(
        ToolDefinition(
            name="query_asset_cmdb",
            description="Retrieve enterprise asset context, tier, exposure, and compensating controls.",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryAssetCmdbInput,
            output_schema=QueryAssetCmdbOutput,
            handler=query_asset_cmdb,
        )
    )

    # 8. get_network_reachability
    registry.register(
        ToolDefinition(
            name="get_network_reachability",
            description="Determine network ingress exposure and perimeter reachability based on CMDB topology.",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=GetNetworkReachabilityInput,
            output_schema=GetNetworkReachabilityOutput,
            handler=get_network_reachability,
        )
    )

    # 9. query_rag_policy
    registry.register(
        ToolDefinition(
            name="query_rag_policy",
            description="Deterministic policy lookup across local organizational security guidelines.",
            category="ASSET",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=QueryRagPolicyInput,
            output_schema=QueryRagPolicyOutput,
            handler=query_rag_policy,
        )
    )

    # 10. calculate_environmental_risk
    registry.register(
        ToolDefinition(
            name="calculate_environmental_risk",
            description="Calculate Environmental Risk Score (ERS) and decision using authoritative Phase 3 engine.",
            category="RISK",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=CalculateEnvironmentalRiskInput,
            output_schema=CalculateEnvironmentalRiskOutput,
            handler=calculate_environmental_risk,
        )
    )

    # 11. map_ssvc_decision
    registry.register(
        ToolDefinition(
            name="map_ssvc_decision",
            description="Map Environmental Risk Score (0-100) to Aegis triage decision band (ACT, ATTEND, PLAN, TRACK).",
            category="RISK",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=MapSsvcDecisionInput,
            output_schema=MapSsvcDecisionOutput,
            handler=map_ssvc_decision,
        )
    )

    # 12. optimize_patch_capacity
    registry.register(
        ToolDefinition(
            name="optimize_patch_capacity",
            description="Solve 0/1 knapsack remediation schedule maximizing risk reduction under capacity limit.",
            category="PLANNING",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=OptimizePatchCapacityInput,
            output_schema=OptimizePatchCapacityOutput,
            handler=optimize_patch_capacity,
        )
    )

    # 13. resolve_package_dependencies
    registry.register(
        ToolDefinition(
            name="resolve_package_dependencies",
            description="Analyze package prerequisites and conflicts for safe remediation planning.",
            category="PLANNING",
            side_effect=SideEffectClass.READ_ONLY,
            input_schema=ResolvePackageDependenciesInput,
            output_schema=ResolvePackageDependenciesOutput,
            handler=resolve_package_dependencies,
        )
    )

    # 14. simulate_risk_reduction
    registry.register(
        ToolDefinition(
            name="simulate_risk_reduction",
            description="Simulate what-if projected ERS and decision after applying hypothetical controls.",
            category="PLANNING",
            side_effect=SideEffectClass.SIMULATION,
            input_schema=SimulateRiskReductionInput,
            output_schema=SimulateRiskReductionOutput,
            handler=simulate_risk_reduction,
        )
    )

    # 15. verify_score_derivation
    registry.register(
        ToolDefinition(
            name="verify_score_derivation",
            description="Independently recompute and verify claimed risk scores and triage decisions.",
            category="VERIFICATION",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=VerifyScoreDerivationInput,
            output_schema=VerifyScoreDerivationOutput,
            handler=verify_score_derivation,
        )
    )

    # 16. detect_hallucinated_claims
    registry.register(
        ToolDefinition(
            name="detect_hallucinated_claims",
            description="Deterministically check whether security assertions are grounded in provided evidence.",
            category="VERIFICATION",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=DetectHallucinatedClaimsInput,
            output_schema=DetectHallucinatedClaimsOutput,
            handler=detect_hallucinated_claims,
        )
    )

    # 17. validate_plan_constraints
    registry.register(
        ToolDefinition(
            name="validate_plan_constraints",
            description="Validate remediation plan against capacity, uniqueness, references, and rollback rules.",
            category="VERIFICATION",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=ValidatePlanConstraintsInput,
            output_schema=ValidatePlanConstraintsOutput,
            handler=validate_plan_constraints,
        )
    )

    return registry


# Canonical singleton instance
default_tool_registry = build_default_tool_registry()
