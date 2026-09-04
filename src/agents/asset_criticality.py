"""Asset Criticality Specialist Agent for Aegis Patch.

Phase 9C: Determines the organizational and infrastructure context of an affected asset:
business importance, network boundary reachability, data sensitivity, compensating controls,
and applicable governance policies.

Architectural Guarantees:
1. Context vs. Risk Distinction: Answers 'How important, exposed, and sensitive is this asset?'
   Does NOT calculate final Environmental Risk Scores (ERS), combine threat intelligence,
   prioritize findings, or create patch plans.
2. Tool Boundary: All queries route strictly through ToolRegistry.invoke.
   Never imports or calls tool functions directly.
3. State Isolation: Complete per-execution state isolation with zero mutable module-level state.
4. Honest Reachability & Policy Semantics: Distinguishes reachable, unreachable, unknown,
   and unavailable. Never converts unknown exposure into false safety ('internal').
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.agents.schemas import (
    AgentAction,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    NoticeSeverity,
)
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    BusinessTier,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
)
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.schemas import (
    GetNetworkReachabilityInput,
    GetNetworkReachabilityOutput,
    PolicyClause,
    QueryAssetCmdbInput,
    QueryAssetCmdbOutput,
    QueryRagPolicyInput,
    QueryRagPolicyOutput,
    ToolStatus,
)


class AssetCriticalityStatus(str, Enum):
    """Categorical execution status of the Asset Criticality Agent."""

    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    NOT_FOUND = "NOT_FOUND"
    INVALID_INPUT = "INVALID_INPUT"
    FAILED = "FAILED"


class AssetSourceAvailability(BaseModel):
    """Telemetry availability status across queried contextual sources."""

    model_config = ConfigDict(extra="forbid")

    cmdb_available: bool = Field(..., description="Whether enterprise CMDB was available")
    network_available: bool = Field(..., description="Whether network reachability tool was available")
    policy_available: bool = Field(..., description="Whether policy corpus was available")
    available_sources_count: int = Field(..., ge=0, le=3, description="Count of queried sources available")
    total_sources_queried: int = Field(default=3, description="Total number of contextual sources evaluated")


class AssetCriticalityInput(BaseModel):
    """Strongly typed input specification for the Asset Criticality Agent."""

    model_config = ConfigDict(extra="forbid")

    asset_id: Optional[str] = Field(
        default=None,
        description="Enterprise asset identifier (e.g. ASSET-001)",
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Optional associated finding identifier for correlation",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-evaluative contextual metadata",
    )


class AssetCriticalityResult(BaseModel):
    """Authoritative outcome delivered by the Asset Criticality Specialist Agent."""

    model_config = ConfigDict(extra="forbid")

    status: AssetCriticalityStatus = Field(
        ...,
        description="Overall deterministic outcome of the asset criticality assessment",
    )
    asset_id: str = Field(
        ...,
        description="Target enterprise asset identifier evaluated",
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Associated finding tracking identifier if provided",
    )
    hostname: Optional[str] = Field(
        default=None,
        description="Authoritative hostname recorded in enterprise CMDB",
    )
    business_criticality: Optional[AssetCriticality] = Field(
        default=None,
        description="Operational criticality rating (CRITICAL, HIGH, MEDIUM, LOW)",
    )
    business_tier: Optional[BusinessTier] = Field(
        default=None,
        description="Organizational tier (MISSION_CRITICAL, BUSINESS_CRITICAL, etc.)",
    )
    environment: Optional[EnvironmentType] = Field(
        default=None,
        description="Deployment lifecycle environment (PRODUCTION, STAGING, DEVELOPMENT, TESTING)",
    )
    network_exposure: Optional[NetworkExposure] = Field(
        default=None,
        description="Network boundary zone (INTERNET_FACING, DMZ, INTERNAL, AIR_GAPPED)",
    )
    data_sensitivity: Optional[DataSensitivity] = Field(
        default=None,
        description="Data classification hosted (RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC)",
    )
    reachable_from_internet: Optional[bool] = Field(
        default=None,
        description="Flag indicating external ingress reachability; None if unknown or unavailable",
    )
    reachability_rationale: Optional[str] = Field(
        default=None,
        description="Audit-friendly justification of network reachability",
    )
    compensating_controls: List[str] = Field(
        default_factory=list,
        description="Names of active compensating security controls on the asset",
    )
    patch_window: Optional[str] = Field(
        default=None,
        description="Scheduled maintenance and patch availability window",
    )
    policy_clauses: List[PolicyClause] = Field(
        default_factory=list,
        description="Applicable governance policy clauses retrieved",
    )
    source_availability: AssetSourceAvailability = Field(
        ...,
        description="Availability summary of contextual data sources",
    )
    assessment_summary: Optional[str] = Field(
        default=None,
        description="Concise deterministic summary of asset importance and exposure",
    )
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list,
        description="Chronological audit traces of each tool execution step",
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list,
        description="Non-fatal operational warnings or unindexed context alerts",
    )
    errors: List[AgentNotice] = Field(
        default_factory=list,
        description="Critical diagnostic errors encountered during assessment",
    )
    assessed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when assessment completed",
    )


class AssetCriticalityAgent:
    """Specialist agent that evaluates enterprise infrastructure context and asset criticality.

    Maintains per-run state isolation and routes all tool invocations through the ToolRegistry.
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
    ) -> None:
        self._registry = registry or default_tool_registry

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def run(
        self,
        asset_id: Optional[Union[str, AssetCriticalityInput, Dict[str, Any]]] = None,
        finding_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AssetCriticalityResult:
        """Convenience invocation accepting input model, dict, or raw keyword arguments."""
        if isinstance(asset_id, (AssetCriticalityInput, dict)):
            return self.assess(asset_id)
        asset_input = AssetCriticalityInput(
            asset_id=asset_id,
            finding_id=finding_id,
            metadata=metadata or {},
        )
        return self.assess(asset_input)

    def assess(
        self,
        input_data: Union[AssetCriticalityInput, Dict[str, Any]],
    ) -> AssetCriticalityResult:
        """Execute the deterministic asset criticality pipeline with isolated local state.

        Steps:
        1. Validate asset identifier.
        2. Tool 1: query_asset_cmdb
        3. Tool 2: get_network_reachability
        4. Tool 3: query_rag_policy
        5. Synthesize asset assessment summary and source availability.
        6. Assemble authoritative AssetCriticalityResult.
        """
        step_traces: List[AgentStepTrace] = []
        errors: List[AgentNotice] = []
        warnings: List[AgentNotice] = []
        step_counter = 1

        # 1. Validate agent input
        if isinstance(input_data, dict):
            try:
                typed_input = AssetCriticalityInput.model_validate(input_data)
            except Exception as val_err:
                return self._create_invalid_input_result(
                    asset_id=input_data.get("asset_id", "UNKNOWN"),
                    finding_id=input_data.get("finding_id"),
                    error_message=f"Agent input validation failed: {val_err}",
                    step_counter=step_counter,
                )
        elif isinstance(input_data, AssetCriticalityInput):
            typed_input = input_data
        else:
            return self._create_invalid_input_result(
                asset_id="UNKNOWN",
                finding_id=None,
                error_message=f"Expected AssetCriticalityInput or dict, got {type(input_data).__name__}",
                step_counter=step_counter,
            )

        asset_id_val = typed_input.asset_id
        if not asset_id_val or not isinstance(asset_id_val, str) or not asset_id_val.strip():
            return self._create_invalid_input_result(
                asset_id=asset_id_val or "MISSING_ASSET_ID",
                finding_id=typed_input.finding_id,
                error_message="Asset ID is required and must be a non-empty string.",
                step_counter=step_counter,
            )

        clean_asset_id = asset_id_val.strip()

        # 2. STEP 1: Query Enterprise CMDB
        cmdb_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="query_asset_cmdb",
            rationale=f"Retrieve enterprise CMDB record and active compensating controls for {clean_asset_id}",
            target_asset_id=clean_asset_id,
            target_finding_id=typed_input.finding_id,
        )

        cmdb_available = False
        asset_found = False
        cmdb_asset: Optional[Asset] = None
        compensating_controls: List[str] = []
        patch_window_str: Optional[str] = None

        try:
            cmdb_input = QueryAssetCmdbInput(asset_id=clean_asset_id)
            cmdb_output = self._registry.invoke("query_asset_cmdb", cmdb_input)
            if not isinstance(cmdb_output, QueryAssetCmdbOutput):
                raise TypeError(f"Expected QueryAssetCmdbOutput from query_asset_cmdb, got {type(cmdb_output).__name__}")

            if cmdb_output.status == ToolStatus.SUCCESS and cmdb_output.asset:
                cmdb_available = True
                asset_found = True
                cmdb_asset = cmdb_output.asset
                compensating_controls = sorted(cmdb_output.compensating_controls)
                patch_window_str = cmdb_output.patch_window
            elif cmdb_output.status == ToolStatus.NOT_FOUND:
                cmdb_available = True
                asset_found = False
                warnings.append(
                    AgentNotice(
                        code="ASSET_NOT_FOUND",
                        message=f"Asset '{clean_asset_id}' was not found in enterprise CMDB.",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                )
            elif cmdb_output.status == ToolStatus.NOT_AVAILABLE:
                cmdb_available = False
                warnings.append(
                    AgentNotice(
                        code="CMDB_UNAVAILABLE",
                        message=f"Enterprise CMDB database/cache is unavailable: {cmdb_output.message}",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                )
            else:
                errors.append(
                    AgentNotice(
                        code="CMDB_QUERY_ERROR",
                        message=f"CMDB query failed with status {cmdb_output.status}: {cmdb_output.message}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )

            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=cmdb_action,
                    tool_result=cmdb_output,
                    status=cmdb_output.status,
                    notes=f"CMDB status: {cmdb_output.status.value}, asset_found: {asset_found}, controls_count: {len(compensating_controls)}",
                )
            )
        except Exception as err:
            errors.append(
                AgentNotice(
                    code="CMDB_TOOL_ERROR",
                    message=f"Tool 'query_asset_cmdb' execution failed: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=cmdb_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during query_asset_cmdb: {err}",
                )
            )
        step_counter += 1

        # 3. STEP 2: Query Network Reachability
        net_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="get_network_reachability",
            rationale=f"Determine network reachability and boundary ingress for {clean_asset_id}",
            target_asset_id=clean_asset_id,
            target_finding_id=typed_input.finding_id,
        )

        network_available = False
        reachable_from_internet: Optional[bool] = None
        reachability_rationale: Optional[str] = None
        net_exposure_from_tool: Optional[NetworkExposure] = None

        try:
            net_input = GetNetworkReachabilityInput(asset_id=clean_asset_id)
            net_output = self._registry.invoke("get_network_reachability", net_input)
            if not isinstance(net_output, GetNetworkReachabilityOutput):
                raise TypeError(
                    f"Expected GetNetworkReachabilityOutput from get_network_reachability, got {type(net_output).__name__}"
                )

            if net_output.status == ToolStatus.SUCCESS:
                network_available = True
                reachable_from_internet = net_output.reachable_from_internet
                reachability_rationale = net_output.rationale
                net_exposure_from_tool = net_output.network_exposure
            elif net_output.status == ToolStatus.NOT_FOUND:
                network_available = True
                reachable_from_internet = None
                reachability_rationale = net_output.rationale
            elif net_output.status == ToolStatus.NOT_AVAILABLE:
                network_available = False
                reachable_from_internet = None
                reachability_rationale = "Network reachability tool unavailable."
                warnings.append(
                    AgentNotice(
                        code="NETWORK_TOOL_UNAVAILABLE",
                        message="Network reachability tool cache/database is unavailable.",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                )
            else:
                network_available = False
                reachable_from_internet = None
                reachability_rationale = f"Network reachability query failed with status {net_output.status}."
                errors.append(
                    AgentNotice(
                        code="NETWORK_TOOL_ERROR",
                        message=f"Network reachability evaluation failed with status {net_output.status}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )

            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=net_action,
                    tool_result=net_output,
                    status=net_output.status,
                    notes=f"Network reachability status: {net_output.status.value}, reachable_from_internet: {reachable_from_internet}",
                )
            )
        except Exception as err:
            errors.append(
                AgentNotice(
                    code="NETWORK_TOOL_ERROR",
                    message=f"Tool 'get_network_reachability' execution failed: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=net_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during get_network_reachability: {err}",
                )
            )
        step_counter += 1

        # 4. STEP 3: Query Governance Policy (RAG)
        policy_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="query_rag_policy",
            rationale=f"Retrieve asset classification and patch policy clauses relevant to {clean_asset_id}",
            target_asset_id=clean_asset_id,
            target_finding_id=typed_input.finding_id,
        )

        policy_available = False
        matched_policies: List[PolicyClause] = []

        try:
            policy_input = QueryRagPolicyInput(query="criticality", policy_id="POL-IT-09")
            policy_output = self._registry.invoke("query_rag_policy", policy_input)
            if not isinstance(policy_output, QueryRagPolicyOutput):
                raise TypeError(f"Expected QueryRagPolicyOutput from query_rag_policy, got {type(policy_output).__name__}")

            if policy_output.status == ToolStatus.SUCCESS:
                policy_available = True
                matched_policies = policy_output.matched_policies
            elif policy_output.status == ToolStatus.NOT_FOUND:
                policy_available = True
                matched_policies = []
            elif policy_output.status == ToolStatus.NOT_AVAILABLE:
                policy_available = False
                warnings.append(
                    AgentNotice(
                        code="POLICY_CORPUS_UNAVAILABLE",
                        message="Organizational policy corpus is unavailable or unindexed offline.",
                        severity=NoticeSeverity.INFO,
                        step_number=step_counter,
                    )
                )
            else:
                policy_available = False
                errors.append(
                    AgentNotice(
                        code="POLICY_TOOL_ERROR",
                        message=f"Policy query failed with status {policy_output.status}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )

            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=policy_action,
                    tool_result=policy_output,
                    status=policy_output.status,
                    notes=f"Policy query status: {policy_output.status.value}, matched_clauses: {len(matched_policies)}",
                )
            )
        except Exception as err:
            errors.append(
                AgentNotice(
                    code="POLICY_TOOL_ERROR",
                    message=f"Tool 'query_rag_policy' execution failed: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=policy_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during query_rag_policy: {err}",
                )
            )
        step_counter += 1

        # 5. Evaluate Source Availability
        available_count = sum([cmdb_available, network_available, policy_available])
        availability = AssetSourceAvailability(
            cmdb_available=cmdb_available,
            network_available=network_available,
            policy_available=policy_available,
            available_sources_count=available_count,
            total_sources_queried=3,
        )

        # 6. Extract Authoritative Asset Context
        hostname = cmdb_asset.hostname if cmdb_asset else None
        crit = cmdb_asset.criticality if cmdb_asset else None
        tier = cmdb_asset.business_tier if cmdb_asset else None
        env = cmdb_asset.environment if cmdb_asset else None
        exposure = cmdb_asset.network_exposure if cmdb_asset else net_exposure_from_tool
        sens = cmdb_asset.data_sensitivity if cmdb_asset else None

        # 7. Synthesize Assessment Summary
        if asset_found and cmdb_asset:
            reach_str = "Direct internet reachability enabled" if reachable_from_internet else "Internet ingress disabled"
            ctrl_str = f"with active controls: {', '.join(compensating_controls)}" if compensating_controls else "without active compensating controls"
            summary = (
                f"Asset {clean_asset_id} ({hostname}) is a {crit.value} {tier.value} host "
                f"in {env.value} with {sens.value} data sensitivity and {exposure.value} network exposure. "
                f"{reach_str} {ctrl_str}."
            )
        elif not cmdb_available:
            summary = f"Context for asset {clean_asset_id} cannot be determined; enterprise CMDB is unavailable."
        else:
            summary = f"Asset {clean_asset_id} was not found in enterprise CMDB."

        # 8. Determine Final Status
        if not asset_found and cmdb_available:
            final_status = AssetCriticalityStatus.NOT_FOUND
        elif available_count == 3:
            final_status = AssetCriticalityStatus.SUCCESS
        elif any(e.severity == NoticeSeverity.ERROR for e in errors) and available_count == 0:
            final_status = AssetCriticalityStatus.FAILED
        else:
            final_status = AssetCriticalityStatus.PARTIAL_SUCCESS

        return AssetCriticalityResult(
            status=final_status,
            asset_id=clean_asset_id,
            finding_id=typed_input.finding_id,
            hostname=hostname,
            business_criticality=crit,
            business_tier=tier,
            environment=env,
            network_exposure=exposure,
            data_sensitivity=sens,
            reachable_from_internet=reachable_from_internet,
            reachability_rationale=reachability_rationale,
            compensating_controls=compensating_controls,
            patch_window=patch_window_str,
            policy_clauses=matched_policies,
            source_availability=availability,
            assessment_summary=summary,
            step_traces=step_traces,
            warnings=warnings,
            errors=errors,
        )

    def _create_invalid_input_result(
        self,
        asset_id: str,
        finding_id: Optional[str],
        error_message: str,
        step_counter: int,
    ) -> AssetCriticalityResult:
        """Construct deterministic response envelope for invalid inputs."""
        empty_avail = AssetSourceAvailability(
            cmdb_available=False,
            network_available=False,
            policy_available=False,
            available_sources_count=0,
            total_sources_queried=3,
        )
        return AssetCriticalityResult(
            status=AssetCriticalityStatus.INVALID_INPUT,
            asset_id=asset_id,
            finding_id=finding_id,
            hostname=None,
            business_criticality=None,
            business_tier=None,
            environment=None,
            network_exposure=None,
            data_sensitivity=None,
            reachable_from_internet=None,
            reachability_rationale=None,
            compensating_controls=[],
            patch_window=None,
            policy_clauses=[],
            source_availability=empty_avail,
            assessment_summary=f"Input rejected: {error_message}",
            step_traces=[],
            warnings=[],
            errors=[
                AgentNotice(
                    code="INVALID_ASSET_INPUT",
                    message=error_message,
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            ],
        )
