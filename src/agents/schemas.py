"""Agent schemas, state representations, and action contracts for Aegis Patch.

Defines the architectural contracts for Agentic AI workflows:
- Agent workflows (INVESTIGATE_FINDING, PRIORITIZE_FINDINGS, PLAN_REMEDIATION, WHAT_IF)
- Strongly typed Workflow Context models (InvestigateFindingContext, PrioritizeFindingsContext, PlanRemediationContext, WhatIfContext, WorkflowContext)
- Agent execution step actions (CALL_TOOL, REPLAN, FINALIZE, FAIL)
- Agent Action hierarchy (AgentAction, CallToolAction, ReplanAction, FinalizeAction, FailAction)
- Planner decision envelope (PlannerDecision)
- Agent run statuses (PENDING, RUNNING, WAITING, COMPLETED, FAILED, MAX_ITERATIONS_REACHED, VERIFICATION_FAILED)
- Structured evidence representations (AgentEvidenceItem, EvidenceType)
- Audit step traces and provenance (AgentStepTrace)
- Structured diagnostic notices (AgentNotice, NoticeSeverity)
- Strongly typed Supervisor result representation (SupervisorFinalResult)
- Strongly typed Supervisor state model (SupervisorState)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from src.schemas.asset import Asset
from src.schemas.plan import PatchPlan
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.decision_mapping import AegisDecision
from src.tools.schemas import BaseToolResult, ToolProvenance, ToolStatus


# ==============================================================================
# 1. Workflow Enums & Typed Workflow Context Models
# ==============================================================================

class AgentWorkflowType(str, Enum):
    """Categorical workflows supported by the Supervisor Agent."""

    INVESTIGATE_FINDING = "INVESTIGATE_FINDING"
    PRIORITIZE_FINDINGS = "PRIORITIZE_FINDINGS"
    PLAN_REMEDIATION = "PLAN_REMEDIATION"
    WHAT_IF = "WHAT_IF"


# Alias for backward and architectural compatibility
SupervisorWorkflowType = AgentWorkflowType


class InvestigateFindingContext(BaseModel):
    """Context required for deep investigation of an individual vulnerability finding."""

    model_config = ConfigDict(extra="forbid")

    target_finding_id: str = Field(
        ..., min_length=1, description="Primary focus vulnerability finding identifier (e.g. FINDING-001)"
    )
    target_asset_id: Optional[str] = Field(
        None, min_length=1, description="Target asset identifier if known upfront"
    )
    require_verification: bool = Field(
        default=True, description="Whether mathematical score derivation verification is mandatory"
    )


class PrioritizeFindingsContext(BaseModel):
    """Context for triaging and ranking a collection of vulnerability findings."""

    model_config = ConfigDict(extra="forbid")

    selected_finding_ids: List[str] = Field(
        default_factory=list, description="Explicit finding IDs in triage scope; empty implies all in working memory"
    )
    target_asset_ids: List[str] = Field(
        default_factory=list, description="Target enterprise assets in triage scope"
    )
    minimum_cvss_filter: Optional[float] = Field(
        None, ge=0.0, le=10.0, description="Optional minimum CVSS cutoff threshold"
    )


class PlanRemediationContext(BaseModel):
    """Context for capacity-constrained remediation and patch scheduling."""

    model_config = ConfigDict(extra="forbid")

    capacity_limit_hours: float = Field(
        default=16.0, gt=0.0, le=168.0, description="Maintenance window capacity in engineering hours"
    )
    target_finding_ids: List[str] = Field(
        default_factory=list, description="Candidate findings for inclusion in patch plan"
    )
    require_rollback_plans: bool = Field(
        default=True, description="Whether each scheduled patch must have a verified rollback procedure"
    )


class WhatIfContext(BaseModel):
    """Context for simulating hypothetical controls, capacity variations, or mitigations."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str = Field(..., min_length=1, description="Target finding identifier for what-if simulation")
    asset_id: str = Field(..., min_length=1, description="Target asset identifier for what-if simulation")
    hypothetical_controls: List[str] = Field(
        default_factory=list, description="Compensating control names assumed to be newly active"
    )
    hypothetical_capacity_hours: Optional[float] = Field(
        None, gt=0.0, description="Hypothetical maintenance window hours to test"
    )


class WorkflowContext(BaseModel):
    """Unified container encapsulating workflow parameters and operational scope."""

    model_config = ConfigDict(extra="forbid")

    workflow_type: AgentWorkflowType = Field(..., description="Target workflow category")
    investigate: Optional[InvestigateFindingContext] = Field(
        None, description="Context for INVESTIGATE_FINDING workflow"
    )
    prioritize: Optional[PrioritizeFindingsContext] = Field(
        None, description="Context for PRIORITIZE_FINDINGS workflow"
    )
    plan_remediation: Optional[PlanRemediationContext] = Field(
        None, description="Context for PLAN_REMEDIATION workflow"
    )
    what_if: Optional[WhatIfContext] = Field(
        None, description="Context for WHAT_IF workflow"
    )

    @model_validator(mode="after")
    def validate_workflow_context_consistency(self) -> WorkflowContext:
        """Ensure the active context matches the designated workflow_type."""
        if self.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING and not self.investigate:
            raise ValueError("investigate context must be provided when workflow_type is INVESTIGATE_FINDING")
        if self.workflow_type == AgentWorkflowType.WHAT_IF and not self.what_if:
            raise ValueError("what_if context must be provided when workflow_type is WHAT_IF")
        return self


# ==============================================================================
# 2. Action Enums & Strongly Typed Action Models
# ==============================================================================

class AgentStepActionType(str, Enum):
    """Discrete action decisions chosen by an agent planner."""

    CALL_TOOL = "CALL_TOOL"
    REPLAN = "REPLAN"
    FINALIZE = "FINALIZE"
    FAIL = "FAIL"


class CallToolAction(BaseModel):
    """Action directive instructing the runtime to execute a registered tool."""

    model_config = ConfigDict(extra="forbid")

    action_type: AgentStepActionType = Field(
        default=AgentStepActionType.CALL_TOOL, description="Action category (CALL_TOOL)"
    )
    tool_name: str = Field(..., min_length=1, description="Machine-readable name of tool in ToolRegistry")
    tool_arguments: Dict[str, Any] = Field(
        default_factory=dict, description="Typed arguments payload passed to the registered tool"
    )
    rationale: str = Field(..., min_length=1, description="Operational audit rationale explaining why tool is called")
    target_finding_id: Optional[str] = Field(None, description="Contextual target finding identifier if applicable")
    target_asset_id: Optional[str] = Field(None, description="Contextual target asset identifier if applicable")

    @property
    def is_terminal(self) -> bool:
        """Indicates whether this action halts agent execution."""
        return False


class ReplanAction(BaseModel):
    """Action directive indicating current path is blocked or incomplete and strategy must be revised."""

    model_config = ConfigDict(extra="forbid")

    action_type: AgentStepActionType = Field(
        default=AgentStepActionType.REPLAN, description="Action category (REPLAN)"
    )
    trigger: str = Field(..., min_length=1, description="Condition triggering replanning (e.g. TELEMETRY_UNAVAILABLE)")
    rationale: str = Field(..., min_length=1, description="Operational audit rationale for replanning")
    missing_information: List[str] = Field(
        default_factory=list, description="List of missing data items triggering the revision"
    )
    suggested_alternative: Optional[str] = Field(
        None, description="Proposed alternative branch or approach (e.g. assess_with_default_threat)"
    )

    @property
    def is_terminal(self) -> bool:
        """Indicates whether this action halts agent execution."""
        return False


class FinalizeAction(BaseModel):
    """Terminal action indicating all required evidence has been collected and workflow can conclude."""

    model_config = ConfigDict(extra="forbid")

    action_type: AgentStepActionType = Field(
        default=AgentStepActionType.FINALIZE, description="Action category (FINALIZE)"
    )
    rationale: str = Field(..., min_length=1, description="Audit rationale confirming why workflow is complete")
    verified: bool = Field(default=True, description="Whether mathematical verification was satisfied")

    @property
    def is_terminal(self) -> bool:
        """Indicates whether this action halts agent execution."""
        return True


class FailAction(BaseModel):
    """Terminal action halting execution due to an unrecoverable error or invalid state."""

    model_config = ConfigDict(extra="forbid")

    action_type: AgentStepActionType = Field(
        default=AgentStepActionType.FAIL, description="Action category (FAIL)"
    )
    error_code: str = Field(..., min_length=1, description="Machine-readable error category code")
    error_message: str = Field(..., min_length=1, description="Clean failure message safe for end-user visibility")
    rationale: str = Field(..., min_length=1, description="Operational rationale explaining why failure is unrecoverable")

    @property
    def is_terminal(self) -> bool:
        """Indicates whether this action halts agent execution."""
        return True


class AgentAction(BaseModel):
    """Unified polymorphic action directive decided by the planner for execution against the environment."""

    model_config = ConfigDict(extra="forbid")

    action_type: AgentStepActionType = Field(..., description="Action category decided by planner")
    tool_name: Optional[str] = Field(None, description="Tool machine-readable name if action_type is CALL_TOOL")
    tool_arguments: Optional[Dict[str, Any]] = Field(
        default_factory=dict, description="Typed arguments payload for the chosen tool"
    )
    rationale: str = Field(..., min_length=1, description="Planner reasoning justifying this action choice")
    target_finding_id: Optional[str] = Field(None, description="Contextual target finding identifier if applicable")
    target_asset_id: Optional[str] = Field(None, description="Contextual target asset identifier if applicable")
    trigger: Optional[str] = Field(None, description="Trigger condition if action_type is REPLAN")
    error_code: Optional[str] = Field(None, description="Error classification if action_type is FAIL")

    @property
    def is_terminal(self) -> bool:
        """Returns True if this action terminates the execution loop (FINALIZE or FAIL)."""
        return self.action_type in (AgentStepActionType.FINALIZE, AgentStepActionType.FAIL)

    @model_validator(mode="after")
    def validate_action_invariants(self) -> AgentAction:
        """Enforce strict field requirements according to action_type."""
        if self.action_type == AgentStepActionType.CALL_TOOL:
            if not self.tool_name or not self.tool_name.strip():
                raise ValueError("tool_name must be non-empty when action_type is CALL_TOOL")
        elif self.action_type == AgentStepActionType.REPLAN:
            if not self.rationale or not self.rationale.strip():
                raise ValueError("rationale is mandatory when action_type is REPLAN")
        elif self.action_type == AgentStepActionType.FAIL:
            if not self.rationale or not self.rationale.strip():
                raise ValueError("rationale is mandatory when action_type is FAIL")
        return self


class PlannerDecision(BaseModel):
    """Envelope wrapping a planner's chosen action along with deliberation metadata."""

    model_config = ConfigDict(extra="forbid")

    action: AgentAction = Field(..., description="Chosen action to execute")
    confidence: float = Field(
        default=1.0, ge=0.0, le=1.0, description="Planner confidence in this decision (1.0 for deterministic)"
    )
    iteration: int = Field(..., ge=0, description="Workflow iteration number during deliberation")
    planner_name: str = Field(default="DeterministicSupervisorPlanner", description="Name of the planning engine")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when decision was produced",
    )


# ==============================================================================
# 3. Agent Lifecycle, Evidence & Diagnostic Notices
# ==============================================================================

class AgentExecutionStatus(str, Enum):
    """Lifecycle status of an entire agent workflow execution run."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    WAITING = "WAITING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    MAX_ITERATIONS_REACHED = "MAX_ITERATIONS_REACHED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"


class EvidenceType(str, Enum):
    """Classification type of evidence collected during agent reasoning."""

    SCAN_DATA = "SCAN_DATA"
    CISA_KEV = "CISA_KEV"
    EPSS = "EPSS"
    OSV = "OSV"
    CMDB_ASSET = "CMDB_ASSET"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    SECURITY_POLICY = "SECURITY_POLICY"
    RISK_EVALUATION = "RISK_EVALUATION"
    VERIFICATION = "VERIFICATION"
    DEPENDENCY_ANALYSIS = "DEPENDENCY_ANALYSIS"
    CAPACITY_SCHEDULE = "CAPACITY_SCHEDULE"
    SIMULATION = "SIMULATION"


class AgentEvidenceItem(BaseModel):
    """Strongly typed factual evidence item observed or retrieved during workflow."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(..., min_length=1, description="Unique evidence tracking identifier")
    evidence_type: EvidenceType = Field(..., description="Classification category of evidence")
    source: str = Field(..., min_length=1, description="Originating provider, dataset, or tool name")
    entity_id: str = Field(..., min_length=1, description="Associated CVE, finding, or asset ID")
    claim_or_property: str = Field(..., min_length=1, description="Factual property name or assertion")
    value: Any = Field(..., description="Observed factual value (e.g. True, 0.92, 'INTERNET_FACING')")
    status: ToolStatus = Field(
        default=ToolStatus.SUCCESS,
        description="Retrieval status (e.g. SUCCESS, NOT_FOUND, NOT_AVAILABLE)",
    )
    provenance: Optional[ToolProvenance] = Field(None, description="Detailed provenance audit metadata")
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when evidence was observed",
    )


class NoticeSeverity(str, Enum):
    """Severity rating of diagnostic warnings or errors observed during run."""

    WARNING = "WARNING"
    ERROR = "ERROR"
    INFO = "INFO"


class AgentNotice(BaseModel):
    """Diagnostic notice tracking warnings, errors, or operational alerts."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., min_length=1, description="Machine-readable notice code (e.g. EPSS_UNAVAILABLE)")
    message: str = Field(..., min_length=1, description="Human-readable description of the condition")
    severity: NoticeSeverity = Field(..., description="Notice severity level")
    step_number: Optional[int] = Field(None, ge=1, description="Execution step where notice occurred")
    context: Dict[str, str] = Field(default_factory=dict, description="Diagnostic key-value context tags")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when notice was generated",
    )


class AgentStepTrace(BaseModel):
    """Audit log entry capturing a discrete action and its observed tool execution result."""

    model_config = ConfigDict(extra="forbid")

    step_number: int = Field(..., ge=1, description="1-indexed sequence number of execution step")
    action: AgentAction = Field(..., description="Action directive executed in this step")
    tool_result: Optional[BaseToolResult] = Field(None, description="Result returned by invoked tool if applicable")
    status: ToolStatus = Field(..., description="Execution outcome status of this step")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when step completed",
    )
    notes: Optional[str] = Field(None, description="Optional diagnostic notes or observations")


# ==============================================================================
# 4. Final Result & Supervisor State Models
# ==============================================================================

class SupervisorFinalResult(BaseModel):
    """Structured conclusion package delivered upon workflow finalization."""

    model_config = ConfigDict(extra="forbid")

    summary: str = Field(..., min_length=1, description="Comprehensive executive summary of the run")
    workflow_type: AgentWorkflowType = Field(..., description="Completed workflow category")
    primary_decision: Optional[AegisDecision] = Field(
        None, description="Overall Aegis triage decision band (ACT, ATTEND, PLAN, TRACK)"
    )
    remediation_decision: Optional[RemediationDecision] = Field(
        None, description="Recommended operational action"
    )
    target_findings: List[str] = Field(default_factory=list, description="IDs of evaluated findings")
    risk_scores: Dict[str, float] = Field(
        default_factory=dict, description="Calculated Environmental Risk Scores keyed by finding_id"
    )
    plan_id: Optional[str] = Field(None, description="Synthesized remediation plan ID if applicable")
    is_verified: bool = Field(default=True, description="Whether all score derivations passed verification")
    notices_count: int = Field(default=0, description="Total diagnostic notices recorded")
    completed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when workflow finalized",
    )

    # Workflow-Specific Strongly Typed Results
    finding_decisions: Dict[str, AegisDecision] = Field(
        default_factory=dict, description="Aegis decisions for each prioritized finding"
    )
    scheduled_finding_ids: Optional[List[str]] = Field(
        None, description="IDs of findings scheduled by patch optimizer"
    )
    deferred_finding_ids: Optional[List[str]] = Field(
        None, description="IDs of findings deferred by patch optimizer"
    )
    capacity_limit_hours: Optional[float] = Field(
        None, ge=0.0, description="Maintenance window capacity limit in hours"
    )
    total_scheduled_effort_hours: Optional[float] = Field(
        None, ge=0.0, description="Total engineering hours scheduled"
    )
    total_expected_risk_reduction: Optional[float] = Field(
        None, ge=0.0, description="Total cumulative expected risk reduction"
    )
    plan_validated: Optional[bool] = Field(
        None, description="Whether plan passed constraint validation"
    )
    is_simulation: bool = Field(
        default=False, description="Flag explicitly declaring whether this result represents a simulation"
    )
    simulation_label: Optional[str] = Field(
        None, description="Simulation label marking non-live hypothetical results (e.g. SIMULATED)"
    )
    baseline_ers: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Baseline ERS before hypothetical intervention"
    )
    simulated_ers: Optional[float] = Field(
        None, ge=0.0, le=100.0, description="Simulated ERS following hypothetical intervention"
    )
    simulated_decision: Optional[AegisDecision] = Field(
        None, description="Simulated Aegis decision following hypothetical intervention"
    )


class SupervisorState(BaseModel):
    """Strongly typed state maintained across workflow iterations by the Supervisor Agent.

    Encapsulates working memory, domain entities, evidence, diagnostics, and audit traces
    without holding non-serializable database sessions or live network/LLM clients.
    """

    model_config = ConfigDict(extra="forbid")

    # 1. Workflow Identity & Goals
    run_id: str = Field(
        ...,
        min_length=1,
        max_length=128,
        description="Safe unique identifier for this agent run (e.g. RUN-2026-001)",
    )
    workflow_type: AgentWorkflowType = Field(..., description="Type of workflow being executed")
    user_goal: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Natural language objective or user prompt",
    )
    context: Optional[WorkflowContext] = Field(
        None, description="Optional structured workflow scope parameters"
    )

    # 2. Lifecycle State & Step Management
    status: AgentExecutionStatus = Field(
        default=AgentExecutionStatus.PENDING,
        description="Current operational lifecycle status of the entire run",
    )
    current_step: int = Field(default=0, ge=0, description="Current execution step number")
    next_action: Optional[AgentAction] = Field(None, description="Next planned action awaiting execution")
    iteration_count: int = Field(default=0, ge=0, description="Number of actions executed so far")
    max_iterations: int = Field(default=20, ge=1, le=100, description="Guardrail limit to prevent infinite loops")

    # 3. Domain Entities in Working Context
    target_finding_id: Optional[str] = Field(None, description="Primary focus finding ID if investigating single issue")
    target_asset_id: Optional[str] = Field(None, description="Primary focus asset ID if contextualizing specific host")
    selected_finding_ids: List[str] = Field(default_factory=list, description="IDs of findings undergoing processing")

    # 4. Accumulated Domain Knowledge
    findings: Dict[str, VulnerabilityFinding] = Field(
        default_factory=dict, description="Loaded vulnerability findings keyed by finding_id"
    )
    assets: Dict[str, Asset] = Field(
        default_factory=dict, description="Loaded enterprise asset context keyed by asset_id"
    )
    evidence: List[AgentEvidenceItem] = Field(
        default_factory=list, description="Chronologically accumulated factual evidence items"
    )
    risk_assessments: Dict[str, RiskAssessment] = Field(
        default_factory=dict, description="Evaluated risk assessments keyed by finding_id"
    )
    patch_plans: Dict[str, PatchPlan] = Field(
        default_factory=dict, description="Remediation plans generated or inspected keyed by plan_id"
    )

    # 5. Diagnostic & Audit Tracking
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list, description="Chronological audit trace of all steps and tool executions"
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list, description="Non-fatal operational warnings observed during run"
    )
    errors: List[AgentNotice] = Field(
        default_factory=list, description="Execution errors or constraint violations encountered"
    )
    missing_information: List[str] = Field(
        default_factory=list, description="Required data elements currently missing or NOT_AVAILABLE"
    )
    scratchpad: Dict[str, Any] = Field(
        default_factory=dict, description="Transient agent working memory across steps"
    )

    # 6. Final Result
    final_result: Optional[SupervisorFinalResult] = Field(
        None, description="Structured final outcome delivered upon workflow completion"
    )

    @field_validator("run_id")
    @classmethod
    def validate_run_id_safe(cls, v: str) -> str:
        """Validate run_id is a clean, machine-safe token without injection hazards."""
        if not re.match(r"^[A-Za-z0-9_\-\.:]+$", v):
            raise ValueError(f"run_id '{v}' contains invalid characters; must be alphanumeric, hyphen, underscore, colon, or period")
        return v

    @model_validator(mode="after")
    def validate_iteration_bounds(self) -> SupervisorState:
        """Enforce iteration count does not exceed max_iterations during valid execution."""
        if self.iteration_count > self.max_iterations:
            raise ValueError(
                f"iteration_count ({self.iteration_count}) cannot exceed max_iterations ({self.max_iterations})"
            )
        return self


# ==============================================================================
# 5. Future LLM Planner Input/Output Boundaries
# ==============================================================================

class FindingSummary(BaseModel):
    """Sanitized finding summary for LLM context without database internals."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    cve_id: str
    severity: str
    cvss_score: float
    asset_id: str
    package_name: Optional[str] = None


class AssetSummary(BaseModel):
    """Sanitized asset context for LLM context without sensitive internals."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str
    asset_type: str
    environment: str
    criticality: str
    network_exposure: str
    data_sensitivity: str


class EvidenceSummary(BaseModel):
    """Sanitized evidence claim for LLM context."""

    model_config = ConfigDict(extra="forbid")

    evidence_type: str
    source: str
    claim: str
    value: Any
    status: str


class ActionTraceSummary(BaseModel):
    """Sanitized history step trace for LLM context."""

    model_config = ConfigDict(extra="forbid")

    step_number: int
    action_type: str
    tool_name: Optional[str] = None
    status: str
    rationale: str


class SupervisorLLMContext(BaseModel):
    """Controlled, sanitized representation of SupervisorState exposed to an LLM planner.

    Explicitly excludes:
    - Database sessions, ORM models, connections
    - Tool callables and Python objects
    - Secret credentials, API keys, and environment variables
    - Raw filesystem paths and host OS commands
    """

    model_config = ConfigDict(extra="forbid")

    run_id: str = Field(..., description="Unique agent run identifier")
    workflow_type: AgentWorkflowType = Field(..., description="Active workflow category")
    user_goal: str = Field(..., description="User prompt or mission objective")
    current_step: int = Field(..., ge=0, description="Current loop step number")
    target_finding_id: Optional[str] = Field(None, description="Primary focus finding ID")
    target_asset_id: Optional[str] = Field(None, description="Primary focus asset ID")
    findings: List[FindingSummary] = Field(default_factory=list, description="Sanitized finding summaries")
    assets: List[AssetSummary] = Field(default_factory=list, description="Sanitized asset context summaries")
    evidence: List[EvidenceSummary] = Field(default_factory=list, description="Accumulated factual evidence")
    risk_scores: Dict[str, float] = Field(default_factory=dict, description="Calculated environmental risk scores")
    recent_actions: List[ActionTraceSummary] = Field(default_factory=list, description="Audit step history")
    allowed_tools: List[str] = Field(default_factory=list, description="Whitelisted tool names for this workflow")
