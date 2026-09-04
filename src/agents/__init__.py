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
from src.agents.supervisor import SupervisorAgent

__all__ = [
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
