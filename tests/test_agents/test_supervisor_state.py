"""Tests for Phase 8B Supervisor Agent State Contract and validation rules."""

from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from src.agents.planner import AgentPlanner
from src.agents.schemas import (
    AgentAction,
    AgentEvidenceItem,
    AgentExecutionStatus,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    AgentWorkflowType,
    EvidenceType,
    NoticeSeverity,
    SupervisorFinalResult,
    SupervisorState,
)
from src.schemas.asset import (
    Asset,
    AssetCriticality,
    AssetType,
    BusinessTier,
    CompensatingControl,
    ControlStatus,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
)
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.threat import ThreatConfidence, ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.decision_mapping import AegisDecision
from src.tools.schemas import ProvenanceSourceType, ToolProvenance, ToolStatus


def test_1_valid_minimal_state():
    state = SupervisorState(
        run_id="RUN-2026-001",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate FINDING-001 on edge gateway",
    )

    assert state.run_id == "RUN-2026-001"
    assert state.workflow_type == AgentWorkflowType.INVESTIGATE_FINDING
    assert state.user_goal == "Investigate FINDING-001 on edge gateway"
    assert state.status == AgentExecutionStatus.PENDING
    assert state.current_step == 0
    assert state.next_action is None
    assert state.iteration_count == 0
    assert state.max_iterations == 20
    assert len(state.findings) == 0
    assert len(state.assets) == 0
    assert len(state.evidence) == 0
    assert len(state.risk_assessments) == 0
    assert len(state.patch_plans) == 0
    assert len(state.step_traces) == 0
    assert len(state.warnings) == 0
    assert len(state.errors) == 0
    assert len(state.missing_information) == 0
    assert state.final_result is None


def test_2_valid_full_state():
    finding = VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow",
        description="Heap overflow in SOCKS5 proxy handshake.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-001",
        source="synthetic_benchmark",
    )
    asset = Asset(
        asset_id="ASSET-001",
        hostname="gw-prod-01",
        asset_type=AssetType.SERVER,
        environment=EnvironmentType.PRODUCTION,
        criticality=AssetCriticality.CRITICAL,
        business_tier=BusinessTier.MISSION_CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        owner_team="SecOps",
        compensating_controls=[
            CompensatingControl(
                control_id="CTRL-01",
                name="WAF",
                description="Cloud WAF",
                status=ControlStatus.ACTIVE,
            )
        ],
    )
    evidence = AgentEvidenceItem(
        evidence_id="EV-001",
        evidence_type=EvidenceType.CISA_KEV,
        source="CISA KEV local cache",
        entity_id="CVE-2023-38545",
        claim_or_property="is_cisa_kev",
        value=True,
        status=ToolStatus.SUCCESS,
        provenance=ToolProvenance(
            source="cisa_kev_local_mirror",
            source_type=ProvenanceSourceType.LOCAL_DATASET,
        ),
    )
    action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="calculate_environmental_risk",
        tool_arguments={"finding_id": "FINDING-001"},
        rationale="Compute environmental risk score using collected asset and threat context.",
        target_finding_id="FINDING-001",
        target_asset_id="ASSET-001",
    )
    trace = AgentStepTrace(
        step_number=1,
        action=action,
        status=ToolStatus.SUCCESS,
        notes="Evaluated successfully.",
    )
    warning = AgentNotice(
        code="EPSS_NOT_INDEXED",
        message="Local EPSS cache did not contain record for CVE-2023-38545; defaulted to 0.0 contribution.",
        severity=NoticeSeverity.WARNING,
        step_number=1,
    )
    final_res = SupervisorFinalResult(
        summary="Investigation complete. Finding prioritized as ACT due to active KEV listing and external exposure.",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        primary_decision=AegisDecision.ACT,
        remediation_decision=RemediationDecision.IMMEDIATE_PATCH,
        target_findings=["FINDING-001"],
        risk_scores={"FINDING-001": 92.5},
        is_verified=True,
    )

    state = SupervisorState(
        run_id="RUN-2026-FULL-01",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate FINDING-001",
        status=AgentExecutionStatus.COMPLETED,
        current_step=1,
        next_action=None,
        iteration_count=1,
        max_iterations=10,
        target_finding_id="FINDING-001",
        target_asset_id="ASSET-001",
        selected_finding_ids=["FINDING-001"],
        findings={"FINDING-001": finding},
        assets={"ASSET-001": asset},
        evidence=[evidence],
        step_traces=[trace],
        warnings=[warning],
        missing_information=[],
        final_result=final_res,
    )

    assert state.status == AgentExecutionStatus.COMPLETED
    assert state.final_result.primary_decision == AegisDecision.ACT
    assert len(state.evidence) == 1
    assert state.evidence[0].value is True
    assert len(state.warnings) == 1
    assert state.warnings[0].code == "EPSS_NOT_INDEXED"


def test_3_workflow_enum_validation():
    for w in ["INVESTIGATE_FINDING", "PRIORITIZE_FINDINGS", "PLAN_REMEDIATION", "WHAT_IF"]:
        assert AgentWorkflowType(w) is not None

    with pytest.raises(ValueError):
        AgentWorkflowType("INVALID_SPECULATIVE_WORKFLOW")


def test_4_execution_status_validation():
    for s in ["PENDING", "RUNNING", "WAITING", "COMPLETED", "FAILED", "MAX_ITERATIONS_REACHED", "VERIFICATION_FAILED"]:
        assert AgentExecutionStatus(s) is not None

    with pytest.raises(ValueError):
        AgentExecutionStatus("UNKNOWN_STATUS")


def test_5_run_id_validation():
    # Valid characters
    s1 = SupervisorState(run_id="RUN_123-abc.45:XYZ", workflow_type=AgentWorkflowType.WHAT_IF, user_goal="goal")
    assert s1.run_id == "RUN_123-abc.45:XYZ"

    # Reject dangerous characters / shell hazards
    with pytest.raises(ValidationError, match="run_id '.*' contains invalid characters"):
        SupervisorState(run_id="RUN; rm -rf /", workflow_type=AgentWorkflowType.WHAT_IF, user_goal="goal")

    with pytest.raises(ValidationError, match="run_id '.*' contains invalid characters"):
        SupervisorState(run_id="RUN$(whoami)", workflow_type=AgentWorkflowType.WHAT_IF, user_goal="goal")


def test_6_iteration_bounds():
    # Valid iteration count within limit
    s = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.WHAT_IF,
        user_goal="goal",
        iteration_count=5,
        max_iterations=10,
    )
    assert s.iteration_count == 5

    # iteration_count exceeding max_iterations must raise ValidationError
    with pytest.raises(ValidationError, match="iteration_count .* cannot exceed max_iterations"):
        SupervisorState(
            run_id="RUN-01",
            workflow_type=AgentWorkflowType.WHAT_IF,
            user_goal="goal",
            iteration_count=15,
            max_iterations=10,
        )

    # Negative iterations must be rejected
    with pytest.raises(ValidationError):
        SupervisorState(
            run_id="RUN-01",
            workflow_type=AgentWorkflowType.WHAT_IF,
            user_goal="goal",
            iteration_count=-1,
        )


def test_7_finding_integration_with_authoritative_contract():
    finding = VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow",
        description="Heap overflow in SOCKS5 proxy handshake.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-001",
        source="synthetic_benchmark",
    )
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate finding",
        findings={"FINDING-001": finding},
    )
    assert state.findings["FINDING-001"].cvss_score == 9.8


def test_8_evidence_model_and_provenance():
    ev = AgentEvidenceItem(
        evidence_id="EV-EPSS-01",
        evidence_type=EvidenceType.EPSS,
        source="FIRST EPSS",
        entity_id="CVE-2023-38545",
        claim_or_property="epss_score",
        value=0.88,
        status=ToolStatus.SUCCESS,
        provenance=ToolProvenance(
            source="first_epss_local_cache",
            source_type=ProvenanceSourceType.LOCAL_CACHE,
        ),
    )
    assert ev.evidence_type == EvidenceType.EPSS
    assert ev.value == 0.88
    assert ev.provenance.source == "first_epss_local_cache"


def test_9_tool_trace_serialization():
    action = AgentAction(
        action_type=AgentStepActionType.CALL_TOOL,
        tool_name="lookup_cisa_kev",
        tool_arguments={"cve_id": "CVE-2023-38545"},
        rationale="Check KEV catalog",
    )
    trace = AgentStepTrace(
        step_number=1,
        action=action,
        status=ToolStatus.SUCCESS,
        notes="Observation noted",
    )
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Investigate",
        step_traces=[trace],
    )
    dumped = state.model_dump()
    assert len(dumped["step_traces"]) == 1
    assert dumped["step_traces"][0]["action"]["tool_name"] == "lookup_cisa_kev"


def test_10_risk_assessment_integration():
    from src.schemas.context import AssetContext
    threat = ThreatEvidence(
        evidence_id="THREAT-01",
        cve_id="CVE-2023-38545",
        threat_source="synthetic_benchmark",
        retrieved_at=datetime.now(timezone.utc),
    )
    ctx = AssetContext(
        context_id="CTX-01",
        asset_id="ASSET-001",
        finding_id="FINDING-001",
        criticality=AssetCriticality.CRITICAL,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.CONFIDENTIAL,
        business_tier=BusinessTier.MISSION_CRITICAL,
        environment=EnvironmentType.PRODUCTION,
    )
    assessment = RiskAssessment(
        assessment_id="RSK-001",
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        asset_id="ASSET-001",
        cvss_score=9.8,
        cvss_contribution=24.5,
        threat_evidence=threat,
        environmental_context=ctx,
        environmental_risk_score=92.5,
        risk_tier=RiskTier.CRITICAL,
        decision=RemediationDecision.IMMEDIATE_PATCH,
        explanation="High environmental risk due to exposed critical asset.",
        assessed_at=datetime.now(timezone.utc),
    )
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Assess risk",
        risk_assessments={"FINDING-001": assessment},
    )
    assert state.risk_assessments["FINDING-001"].environmental_risk_score == 92.5


def test_11_warning_error_distinction():
    warn = AgentNotice(
        code="OSV_CACHE_ABSENT",
        message="Local OSV database cache is not provisioned.",
        severity=NoticeSeverity.WARNING,
    )
    err = AgentNotice(
        code="INVALID_FINDING_SCHEMA",
        message="Scanner output missing required CVE ID field.",
        severity=NoticeSeverity.ERROR,
    )
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.PRIORITIZE_FINDINGS,
        user_goal="Prioritize findings",
        warnings=[warn],
        errors=[err],
    )
    assert len(state.warnings) == 1
    assert state.warnings[0].severity == NoticeSeverity.WARNING
    assert len(state.errors) == 1
    assert state.errors[0].severity == NoticeSeverity.ERROR


def test_12_missing_information_tracking():
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.PLAN_REMEDIATION,
        user_goal="Plan patch schedule",
        missing_information=["cmdb_patch_window", "upstream_package_dependencies"],
    )
    assert "cmdb_patch_window" in state.missing_information
    assert len(state.missing_information) == 2


def test_13_final_result_serialization():
    res = SupervisorFinalResult(
        summary="Remediation plan PLAN-001 created within 16.0h capacity.",
        workflow_type=AgentWorkflowType.PLAN_REMEDIATION,
        primary_decision=AegisDecision.PLAN,
        remediation_decision=RemediationDecision.SCHEDULED_PATCH,
        plan_id="PLAN-001",
        is_verified=True,
    )
    state = SupervisorState(
        run_id="RUN-01",
        workflow_type=AgentWorkflowType.PLAN_REMEDIATION,
        user_goal="Plan patch schedule",
        status=AgentExecutionStatus.COMPLETED,
        final_result=res,
    )
    assert state.final_result.plan_id == "PLAN-001"
    assert state.final_result.primary_decision == AegisDecision.PLAN


def test_14_model_dump_validate_round_trip():
    state = SupervisorState(
        run_id="RUN-ROUNDTRIP-01",
        workflow_type=AgentWorkflowType.INVESTIGATE_FINDING,
        user_goal="Roundtrip verification test",
        status=AgentExecutionStatus.RUNNING,
        current_step=3,
        iteration_count=3,
        max_iterations=15,
        target_finding_id="FINDING-001",
        target_asset_id="ASSET-001",
        missing_information=["threat_telemetry"],
    )
    dumped = state.model_dump()
    reloaded = SupervisorState.model_validate(dumped)

    assert reloaded.run_id == state.run_id
    assert reloaded.workflow_type == state.workflow_type
    assert reloaded.user_goal == state.user_goal
    assert reloaded.iteration_count == 3
    assert reloaded.missing_information == ["threat_telemetry"]


def test_15_invalid_state_rejection():
    # Missing required run_id
    with pytest.raises(ValidationError):
        SupervisorState(workflow_type=AgentWorkflowType.WHAT_IF, user_goal="goal")

    # CALL_TOOL missing tool_name
    with pytest.raises(ValidationError, match="tool_name must be non-empty when action_type is CALL_TOOL"):
        AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name=None,
            rationale="Trying to call tool without name",
        )


def test_16_concurrent_independent_state_isolation():
    """Verify that multiple concurrent SupervisorState instances do not share mutable lists or dicts."""
    s1 = SupervisorState(run_id="RUN-A", workflow_type=AgentWorkflowType.WHAT_IF, user_goal="Goal A")
    s2 = SupervisorState(run_id="RUN-B", workflow_type=AgentWorkflowType.WHAT_IF, user_goal="Goal B")

    s1.missing_information.append("gap_in_A")
    s1.findings["F1"] = VulnerabilityFinding(
        finding_id="F1",
        cve_id="CVE-2023-38545",
        title="curl overflow",
        description="test",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1",
        asset_id="ASSET-001",
        source="test",
    )

    assert "gap_in_A" in s1.missing_information
    assert "gap_in_A" not in s2.missing_information
    assert "F1" in s1.findings
    assert "F1" not in s2.findings
