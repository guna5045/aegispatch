"""Agents package for Aegis Patch.

Exports core agent workflow contracts, state representations, planner interfaces,
bounded runtime, and the Supervisor Agent orchestrator.
"""

from src.agents.planner import (
    AgentPlanner,
    DeterministicSupervisorPlanner,
    FallbackSupervisorPlanner,
    LLMSupervisorPlanner,
    SupervisorPlanner,
    build_llm_planner_input,
    validate_llm_action,
)
from src.agents.runtime import SupervisorRuntime
from src.agents.schemas import (
    ActionTraceSummary,
    AgentAction,
    AgentEvidenceItem,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    AgentWorkflowType,
    AssetSummary,
    CallToolAction,
    EvidenceSummary,
    EvidenceType,
    FailAction,
    FinalizeAction,
    FindingSummary,
    InvestigateFindingContext,
    NoticeSeverity,
    PlanRemediationContext,
    PlannerDecision,
    PrioritizeFindingsContext,
    ReplanAction,
    SupervisorFinalResult,
    SupervisorLLMContext,
    SupervisorState,
    SupervisorWorkflowType,
    WhatIfContext,
    WorkflowContext,
)
from src.agents.asset_criticality import (
    AssetCriticalityAgent,
    AssetCriticalityInput,
    AssetCriticalityResult,
    AssetCriticalityStatus,
    AssetSourceAvailability,
)
from src.agents.risk_combination import (
    RiskCombinationAgent,
    RiskCombinationInput,
    RiskCombinationResult,
    RiskCombinationStatus,
    RiskEvidenceConsistency,
    RiskEvidenceProvenance,
)
from src.agents.patch_plan import (
    DeferralReason,
    DeferredFindingDetail,
    PatchPlanAgent,
    PatchPlanAgentStatus,
    PatchPlanInput,
    PatchPlanProvenance,
    PatchPlanResult,
    ScheduledFindingDetail,
)
from src.agents.exploitability import (
    AssessmentConfidence,
    EvidenceStatus,
    ExploitabilityAgent,
    ExploitabilityAgentStatus,
    ExploitabilityInput,
    ExploitabilityMaturity,
    ExploitabilityResult,
    EpssEvidence,
    KevEvidence,
    OsvEvidence,
    SourceAvailability,
)
from src.agents.scan_intake import (
    ScanIntakeAgent,
    ScanIntakeInput,
    ScanIntakeRejectionNotice,
    ScanIntakeResult,
    ScanIntakeStatus,
)
from src.agents.verification import (
    CheckSeverity,
    CheckStatus,
    VerificationAgent,
    VerificationAgentStatus,
    VerificationCheckResult,
    VerificationInput,
    VerificationProvenance,
    VerificationResult,
)
from src.agents.supervisor import SupervisorAgent

__all__ = [
    # Scan Intake Specialist Agent (Phase 9A)
    "ScanIntakeAgent",
    "ScanIntakeInput",
    "ScanIntakeResult",
    "ScanIntakeStatus",
    "ScanIntakeRejectionNotice",

    # Exploitability Specialist Agent (Phase 9B)
    "ExploitabilityAgent",
    "ExploitabilityInput",
    "ExploitabilityResult",
    "ExploitabilityAgentStatus",
    "ExploitabilityMaturity",
    "AssessmentConfidence",
    "EvidenceStatus",
    "KevEvidence",
    "EpssEvidence",
    "OsvEvidence",
    "SourceAvailability",

    # Asset Criticality Specialist Agent (Phase 9C)
    "AssetCriticalityAgent",
    "AssetCriticalityInput",
    "AssetCriticalityResult",
    "AssetCriticalityStatus",
    "AssetSourceAvailability",

    # Risk Combination Specialist Agent (Phase 9D)
    "RiskCombinationAgent",
    "RiskCombinationInput",
    "RiskCombinationResult",
    "RiskCombinationStatus",
    "RiskEvidenceConsistency",
    "RiskEvidenceProvenance",

    # Patch Plan Specialist Agent (Phase 9E)
    "PatchPlanAgent",
    "PatchPlanInput",
    "PatchPlanResult",
    "PatchPlanAgentStatus",
    "DeferralReason",
    "DeferredFindingDetail",
    "ScheduledFindingDetail",
    "PatchPlanProvenance",

    # Verification Specialist Agent (Phase 9F)
    "VerificationAgent",
    "VerificationInput",
    "VerificationResult",
    "VerificationAgentStatus",
    "CheckStatus",
    "CheckSeverity",
    "VerificationCheckResult",
    "VerificationProvenance",

    # Workflow Types & Contexts
    "AgentWorkflowType",
    "SupervisorWorkflowType",
    "InvestigateFindingContext",
    "PrioritizeFindingsContext",
    "PlanRemediationContext",
    "WhatIfContext",
    "WorkflowContext",
    # Step Action Types & Models
    "AgentStepActionType",
    "AgentAction",
    "CallToolAction",
    "ReplanAction",
    "FinalizeAction",
    "FailAction",
    "PlannerDecision",
    "AgentStepTrace",
    # Lifecycle & Evidence
    "AgentExecutionStatus",
    "AgentEvidenceItem",
    "EvidenceType",
    "AgentNotice",
    "NoticeSeverity",
    # State & Result
    "SupervisorFinalResult",
    "SupervisorState",
    # LLM Boundary Context & Summaries
    "SupervisorLLMContext",
    "FindingSummary",
    "AssetSummary",
    "EvidenceSummary",
    "ActionTraceSummary",
    "build_llm_planner_input",
    "validate_llm_action",
    # Planner, Runtime & Agent
    "AgentPlanner",
    "SupervisorPlanner",
    "DeterministicSupervisorPlanner",
    "LLMSupervisorPlanner",
    "FallbackSupervisorPlanner",
    "SupervisorRuntime",
    "SupervisorAgent",
]
