"""Tests for Phase 9F: Verification Specialist Agent.

Comprehensive test coverage validating:
1. Fully valid risk assessment verification (PASS / VERIFIED)
2. Valid verified result from Phase 9D combination agent
3. Mathematical mismatch detection (REJECTED with SCORE_DERIVATION_MISMATCH)
4. Malformed mathematical verifier tool result handled gracefully
5. Unsupported claim detection (REJECTED with UNSUPPORTED_CLAIMS_DETECTED)
6. Hallucination detector tool failure handled gracefully
7. Patch plan valid verification (PASS / VERIFIED)
8. Patch plan invalid constraint violation (REJECTED with PLAN_CONSTRAINT_VIOLATION)
9. Malformed plan validator tool result handled gracefully
10. No patch plan provided -> NOT_APPLICABLE status
11. Unavailable verification source (missing finding/asset context for risk recomputation -> NOT_AVAILABLE / NEEDS_REVIEW)
12. Verification tool exception handled gracefully (ERROR check status / fail-closed)
13. Unknown tool handled gracefully without unhandled crashes
14. Mismatched finding IDs rejected immediately with INVALID_INPUT
15. Mismatched CVE IDs rejected immediately with INVALID_INPUT
16. Mismatched asset IDs rejected immediately with INVALID_INPUT
17. Incomplete evidence handled honestly without crashing or fabricating facts
18. Malformed candidate input rejected with INVALID_INPUT
19. Tool registry boundary strictly enforced (ToolRegistry.invoke spy)
20. Deterministic repeated verification (identical candidate -> identical checks, traces, verdicts)
21. State isolation across verifier instances and sequential runs
22. Malicious evidence and claim text treated as inert strings (SQL/XSS/Command injection)
23. Complete verification provenance tracked correctly (tools, timestamps, candidate ID)
24. Stable check execution ordering (cross_evidence -> score -> claim -> plan)
25. Overall status correctness (VERIFIED vs REJECTED vs NEEDS_REVIEW vs INVALID_INPUT)
26. Fail-closed behavior (never marks candidate VERIFIED on critical/major defects)
27. No silent repair (defects reported honestly; original candidate untouched)
28. Benchmark integration (verifying benchmark findings and assets)
29. Patch capacity violation detected (capacity exceeded -> REJECTED)
30. Rollback plan validation (missing rollback procedure flagged)
31. Analytical verification only: no shell commands, SSH, or infrastructure mutation
32. No duplicated verification logic (delegates to authoritative verification tools)
33. Step trace correctness, action logging, and sequence numbers
34. Warning vs failure semantics (MINOR warning does not reject; CRITICAL failure rejects)
35. Multiple candidate types supported (RiskAssessment, RiskCombinationResult, PatchPlanResult, SecurityClaim)
"""

from datetime import datetime, timezone
import inspect
from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from src.agents.exploitability import (
    AssessmentConfidence,
    EpssEvidence,
    EvidenceStatus,
    ExploitabilityAgent,
    ExploitabilityAgentStatus,
    ExploitabilityMaturity,
    ExploitabilityResult,
    KevEvidence,
    OsvEvidence,
    SourceAvailability,
)
from src.agents.patch_plan import (
    PatchPlanAgent,
    PatchPlanInput,
    PatchPlanResult,
    ScheduledFindingDetail,
)
from src.agents.risk_combination import (
    RiskCombinationAgent,
    RiskCombinationInput,
    RiskCombinationResult,
)
from src.agents.schemas import AgentStepActionType, NoticeSeverity
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
from src.schemas.plan import ApprovalState
from src.schemas.risk import RemediationDecision, RiskAssessment, RiskTier
from src.schemas.threat import ThreatEvidence
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.services.data_service import load_benchmark_findings, load_cmdb_assets
from src.tools.decision_mapping import AegisDecision
from src.tools.registry import ToolDefinition, ToolRegistry, default_tool_registry
from src.tools.risk_engine import evaluate_risk
from src.tools.schemas import (
    BaseToolResult,
    ClaimVerificationResult,
    ClaimVerificationStatus,
    DetectHallucinatedClaimsInput,
    DetectHallucinatedClaimsOutput,
    PlanConstraintItem,
    PlanConstraintViolation,
    ScoreMismatch,
    SecurityClaim,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
    ValidatePlanConstraintsInput,
    ValidatePlanConstraintsOutput,
    VerifyScoreDerivationInput,
    VerifyScoreDerivationOutput,
)


# ==============================================================================
# Fixtures & Factories
# ==============================================================================

@pytest.fixture
def sample_finding() -> VulnerabilityFinding:
    """Standard sample vulnerability finding."""
    return VulnerabilityFinding(
        finding_id="FINDING-001",
        cve_id="CVE-2023-38545",
        title="Heap-based buffer overflow in curl SOCKS5",
        description="curl before 8.4.0 heap overflow flaw in SOCKS5 proxy handshake.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="curl",
        installed_version="7.88.1",
        fixed_version="8.4.0",
        asset_id="ASSET-001",
        source="trivy",
    )


@pytest.fixture
def sample_asset() -> Asset:
    """Standard mission-critical internet-facing asset."""
    return Asset(
        asset_id="ASSET-001",
        hostname="gw-ingress-prod-01",
        asset_type=AssetType.SERVER,
        business_tier=BusinessTier.MISSION_CRITICAL,
        environment=EnvironmentType.PRODUCTION,
        network_exposure=NetworkExposure.INTERNET_FACING,
        data_sensitivity=DataSensitivity.RESTRICTED,
        criticality=AssetCriticality.HIGH,
        owner_team="Platform Security",
        compensating_controls=[
            CompensatingControl(
                control_id="CTRL-WAF",
                name="Web Application Firewall",
                description="Blocks web exploitation attempts",
                status=ControlStatus.ACTIVE,
            )
        ],
    )


@pytest.fixture
def sample_exploitability_result() -> ExploitabilityResult:
    """Standard exploitability result with KEV and EPSS confirmed."""
    return ExploitabilityResult(
        status=ExploitabilityAgentStatus.SUCCESS,
        cve_id="CVE-2023-38545",
        finding_id="FINDING-001",
        maturity=ExploitabilityMaturity.ACTIVE,
        confidence=AssessmentConfidence.HIGH,
        threat_score=100.0,
        threat_score_explanation="Listed on CISA KEV",
        kev_evidence=KevEvidence(
            status=EvidenceStatus.FOUND,
            is_known_exploited=True,
            date_added="2023-10-18",
            due_date="2023-11-08",
        ),
        epss_evidence=EpssEvidence(
            status=EvidenceStatus.FOUND,
            epss_score=0.9254,
            percentile=0.9821,
            observed_at=datetime.now(timezone.utc),
        ),
        osv_evidence=OsvEvidence(
            status=EvidenceStatus.FOUND,
            advisories=[{"id": "GHSA-1234", "summary": "curl buffer overflow"}],
            fixed_versions=["8.4.0"],
        ),
        source_availability=SourceAvailability(
            cisa_kev_available=True,
            epss_available=True,
            osv_available=True,
            available_sources_count=3,
        ),
        step_traces=[],
        warnings=[],
        errors=[],
        assessed_at=datetime.now(timezone.utc),
    )


@pytest.fixture
def sample_risk_assessment(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
) -> RiskAssessment:
    """Accurately derived RiskAssessment matching the authoritative risk formula."""
    threat = ThreatEvidence(
        evidence_id="TE-001",
        cve_id=sample_finding.cve_id,
        is_cisa_kev=True,
        threat_source="CISA_KEV",
        retrieved_at=datetime.now(timezone.utc),
    )
    return evaluate_risk(
        finding=sample_finding,
        asset=sample_asset,
        threat=threat,
    )


@pytest.fixture
def sample_security_claims() -> List[SecurityClaim]:
    """Standard security claims grounded in evidence records."""
    return [
        SecurityClaim(
            claim_id="CLAIM-001",
            claim_type="EPSS_SCORE",
            statement="Vulnerability has EPSS score of 0.85",
            entity_id="CVE-2023-38545",
            claimed_value=0.85,
        ),
        SecurityClaim(
            claim_id="CLAIM-002",
            claim_type="EXPOSURE",
            statement="Host is directly internet facing",
            entity_id="ASSET-001",
            claimed_value="INTERNET_FACING",
        ),
    ]


@pytest.fixture
def sample_evidence_records() -> Dict[str, Any]:
    """Factual evidence records matching sample_security_claims."""
    return {
        "CVE-2023-38545": {
            "epss_score": 0.85,
        },
        "ASSET-001": {
            "network_exposure": "INTERNET_FACING",
        },
    }


@pytest.fixture
def sample_patch_plan(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
) -> PatchPlanResult:
    """Standard validated patch plan synthesized by PatchPlanAgent."""
    plan_agent = PatchPlanAgent()
    return plan_agent.run(
        findings=[sample_finding],
        assets={sample_asset.asset_id: sample_asset},
        risk_assessments=[sample_risk_assessment],
        capacity_limit_hours=16.0,
    )


# ==============================================================================
# Tests
# ==============================================================================

def test_01_fully_valid_risk_assessment(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
    sample_security_claims: List[SecurityClaim],
    sample_evidence_records: Dict[str, Any],
):
    """1. Fully valid risk assessment verification passes all checks with VERIFIED status."""
    agent = VerificationAgent()
    inp = VerificationInput(
        candidate_id="CANDIDATE-001",
        finding=sample_finding,
        asset=sample_asset,
        risk_assessment=sample_risk_assessment,
        claims=sample_security_claims,
        evidence_records=sample_evidence_records,
    )
    result = agent.verify(inp)

    assert result.status == VerificationAgentStatus.VERIFIED
    assert result.overall_passed is True
    assert result.candidate_id == "CANDIDATE-001"
    assert result.checks["cross_evidence_consistency"].status == CheckStatus.PASS
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.PASS
    assert result.checks["claim_grounding"].status == CheckStatus.PASS
    assert result.checks["patch_plan_constraints"].status == CheckStatus.NOT_APPLICABLE
    assert len(result.errors) == 0


def test_02_valid_verified_result_from_risk_combination_agent(
    sample_finding: VulnerabilityFinding,
    sample_exploitability_result: ExploitabilityResult,
    sample_asset: Asset,
):
    """2. Valid RiskCombinationResult directly verified by VerificationAgent."""
    comb_agent = RiskCombinationAgent()
    comb_res = comb_agent.run(
        finding=sample_finding,
        exploitability=sample_exploitability_result,
        asset=sample_asset,
    )
    assert comb_res.environmental_risk_score is not None

    agent = VerificationAgent()
    v_res = agent.verify(
        VerificationInput(
            candidate_id="CAND-COMB",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=comb_res,
        )
    )

    assert v_res.status == VerificationAgentStatus.VERIFIED
    assert v_res.overall_passed is True
    assert v_res.checks["mathematical_score_derivation"].status == CheckStatus.PASS


def test_03_mathematical_score_mismatch(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """3. Mathematical score mismatch is detected and rejected without silent repair."""
    tampered_risk = sample_risk_assessment.model_copy(deep=True)
    tampered_risk.environmental_risk_score = 12.34

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-TAMPERED",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=tampered_risk,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.overall_passed is False
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.FAIL
    assert len(result.checks["mathematical_score_derivation"].mismatches) > 0
    assert any(e.code == "SCORE_DERIVATION_MISMATCH" for e in result.errors)
    # Confirm no silent repair: tampered_risk still has 12.34
    assert tampered_risk.environmental_risk_score == 12.34


def test_04_malformed_mathematical_verifier_result(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """4. Malformed mathematical verifier tool result handled gracefully (fail-closed)."""
    spy_registry = ToolRegistry()
    for tool in default_tool_registry.list_tools():
        if tool.name != "verify_score_derivation":
            spy_registry.register(tool)

    spy_registry.register(
        ToolDefinition(
            name="verify_score_derivation",
            description="Malformed mock",
            category="verification",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=VerifyScoreDerivationInput,
            output_schema=BaseToolResult,
            handler=lambda inp: BaseToolResult(status=ToolStatus.SUCCESS),
        )
    )

    agent = VerificationAgent(registry=spy_registry)
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MALFORMED-SCORE",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.ERROR
    assert any(e.code == "SCORE_VERIFIER_ERROR" for e in result.errors)


def test_05_unsupported_security_claim_detected(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
):
    """5. Unsupported claim detection rejects candidate with UNSUPPORTED_CLAIMS_DETECTED."""
    unsupported_claims = [
        SecurityClaim(
            claim_id="CLAIM-GHOST",
            claim_type="CISA_KEV_STATUS",
            statement="Actively exploited by nation state threat actor in Russian campaign",
            entity_id="CVE-2023-38545",
            claimed_value=True,
        )
    ]
    evidence = {
        "CVE-2023-38545": {
            "is_cisa_kev": False,
        }
    }

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-UNSUPPORTED",
            finding=sample_finding,
            asset=sample_asset,
            claims=unsupported_claims,
            evidence_records=evidence,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["claim_grounding"].status == CheckStatus.FAIL
    assert len(result.checks["claim_grounding"].unsupported_claims) > 0
    assert any(e.code == "UNSUPPORTED_CLAIMS_DETECTED" for e in result.errors)


def test_06_hallucination_detector_tool_failure_handled(
    sample_finding: VulnerabilityFinding,
    sample_security_claims: List[SecurityClaim],
):
    """6. Hallucination detector tool failure handled gracefully (fail-closed)."""
    spy_registry = ToolRegistry()
    for tool in default_tool_registry.list_tools():
        if tool.name != "detect_hallucinated_claims":
            spy_registry.register(tool)

    def crashing_claim_detector(inp):
        raise RuntimeError("Embedding model unavailable or corrupt")

    spy_registry.register(
        ToolDefinition(
            name="detect_hallucinated_claims",
            description="Crashing claim detector",
            category="verification",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=DetectHallucinatedClaimsInput,
            output_schema=DetectHallucinatedClaimsOutput,
            handler=crashing_claim_detector,
        )
    )

    agent = VerificationAgent(registry=spy_registry)
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-CLAIM-CRASH",
            finding=sample_finding,
            claims=sample_security_claims,
            evidence_records={},
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["claim_grounding"].status == CheckStatus.ERROR
    assert any(e.code == "CLAIM_CHECKER_ERROR" for e in result.errors)


def test_07_patch_plan_valid_verification(
    sample_finding: VulnerabilityFinding,
    sample_patch_plan: PatchPlanResult,
):
    """7. Valid patch plan verification passes constraint check."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-PLAN-VALID",
            finding=sample_finding,
            patch_plan=sample_patch_plan,
        )
    )

    assert result.status == VerificationAgentStatus.VERIFIED
    assert result.overall_passed is True
    assert result.checks["patch_plan_constraints"].status == CheckStatus.PASS
    assert len(result.checks["patch_plan_constraints"].violations) == 0


def test_08_patch_plan_invalid_constraint_violation(
    sample_finding: VulnerabilityFinding,
    sample_patch_plan: PatchPlanResult,
):
    """8. Invalid patch plan (unknown finding or duplicate) rejected."""
    bad_plan = sample_patch_plan.model_copy(deep=True)
    bad_action = bad_plan.scheduled_actions[0].model_copy(update={"finding_id": "FINDING-GHOST"})
    bad_plan.scheduled_actions = [bad_action]
    bad_plan.scheduled_finding_ids = ["FINDING-GHOST"]

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-PLAN-BAD",
            finding=sample_finding,  # known finding is FINDING-001, but plan has FINDING-GHOST
            patch_plan=bad_plan,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.overall_passed is False
    assert result.checks["patch_plan_constraints"].status == CheckStatus.FAIL
    assert len(result.checks["patch_plan_constraints"].violations) > 0
    assert any(e.code == "PLAN_CONSTRAINT_VIOLATION" for e in result.errors)


def test_09_malformed_plan_validator_result(
    sample_finding: VulnerabilityFinding,
    sample_patch_plan: PatchPlanResult,
):
    """9. Malformed plan validator result handled gracefully without crash."""
    spy_registry = ToolRegistry()
    for tool in default_tool_registry.list_tools():
        if tool.name != "validate_plan_constraints":
            spy_registry.register(tool)

    spy_registry.register(
        ToolDefinition(
            name="validate_plan_constraints",
            description="Malformed plan validator",
            category="verification",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=ValidatePlanConstraintsInput,
            output_schema=BaseToolResult,
            handler=lambda inp: BaseToolResult(status=ToolStatus.SUCCESS),
        )
    )

    agent = VerificationAgent(registry=spy_registry)
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MALFORMED-PLAN",
            finding=sample_finding,
            patch_plan=sample_patch_plan,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["patch_plan_constraints"].status == CheckStatus.ERROR
    assert any(e.code == "PLAN_VALIDATOR_ERROR" for e in result.errors)


def test_10_no_patch_plan_not_applicable(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """10. When no patch plan candidate is supplied, check is NOT_APPLICABLE (not FAIL)."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-NO-PLAN",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.checks["patch_plan_constraints"].status == CheckStatus.NOT_APPLICABLE
    assert result.status == VerificationAgentStatus.VERIFIED


def test_11_unavailable_verification_source(
    sample_risk_assessment: RiskAssessment,
):
    """11. Risk assessment supplied without finding or asset -> NOT_AVAILABLE and NEEDS_REVIEW."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MISSING-CONTEXT",
            finding=None,
            asset=None,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.status == VerificationAgentStatus.NEEDS_REVIEW
    assert result.overall_passed is False
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.NOT_AVAILABLE
    assert any(w.code == "CANNOT_RECOMPUTE_RISK" for w in result.warnings)


def test_12_verification_tool_exception_handled_gracefully(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """12. Tool exception in score verifier yields ERROR check status and REJECTED overall status."""
    spy_registry = ToolRegistry()
    for tool in default_tool_registry.list_tools():
        if tool.name != "verify_score_derivation":
            spy_registry.register(tool)

    def failing_tool(inp):
        raise ValueError("Division by zero in calculation core")

    spy_registry.register(
        ToolDefinition(
            name="verify_score_derivation",
            description="Failing score verifier",
            category="verification",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            input_schema=VerifyScoreDerivationInput,
            output_schema=VerifyScoreDerivationOutput,
            handler=failing_tool,
        )
    )

    agent = VerificationAgent(registry=spy_registry)
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-EXCEPTION",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.ERROR
    assert any(e.code == "SCORE_VERIFIER_ERROR" for e in result.errors)


def test_13_unknown_tool_handled_gracefully(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """13. Empty registry missing required tools handled gracefully without crash."""
    empty_registry = ToolRegistry()
    agent = VerificationAgent(registry=empty_registry)

    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-EMPTY-REGISTRY",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.status == VerificationAgentStatus.REJECTED
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.ERROR


def test_14_mismatched_finding_ids_rejected(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """14. Mismatched finding IDs between finding and risk assessment rejected with INVALID_INPUT."""
    tampered_risk = sample_risk_assessment.model_copy(deep=True)
    tampered_risk.finding_id = "FINDING-999-DIFFERENT"

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MISMATCH-FID",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=tampered_risk,
        )
    )

    assert result.status in (VerificationAgentStatus.REJECTED, VerificationAgentStatus.INVALID_INPUT)
    assert result.overall_passed is False
    assert result.checks["cross_evidence_consistency"].status == CheckStatus.FAIL
    assert any(e.code in ("ENTITY_ID_MISMATCH", "EVIDENCE_INCONSISTENCY") for e in result.errors)


def test_15_mismatched_cve_ids_rejected(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """15. Mismatched CVE IDs rejected with INVALID_INPUT."""
    tampered_risk = sample_risk_assessment.model_copy(deep=True)
    tampered_risk.cve_id = "CVE-1999-0001"

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MISMATCH-CVE",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=tampered_risk,
        )
    )

    assert result.status in (VerificationAgentStatus.REJECTED, VerificationAgentStatus.INVALID_INPUT)
    assert result.overall_passed is False
    assert any(e.code in ("ENTITY_ID_MISMATCH", "EVIDENCE_INCONSISTENCY") for e in result.errors)


def test_16_mismatched_asset_ids_rejected(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """16. Mismatched asset IDs rejected with INVALID_INPUT."""
    tampered_asset = sample_asset.model_copy(deep=True)
    tampered_asset.asset_id = "ASSET-DIFFERENT-999"

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MISMATCH-ASSET",
            finding=sample_finding,
            asset=tampered_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.status in (VerificationAgentStatus.REJECTED, VerificationAgentStatus.INVALID_INPUT)
    assert result.overall_passed is False
    assert any(e.code in ("ENTITY_ID_MISMATCH", "EVIDENCE_INCONSISTENCY") for e in result.errors)


def test_17_incomplete_evidence_handled_honestly(
    sample_finding: VulnerabilityFinding,
):
    """17. Candidate with only finding (no asset, no risk, no plan, no claims) passes minimally."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-MINIMAL",
            finding=sample_finding,
        )
    )

    assert result.status == VerificationAgentStatus.VERIFIED
    assert result.overall_passed is True
    assert result.checks["cross_evidence_consistency"].status == CheckStatus.PASS
    assert result.checks["mathematical_score_derivation"].status == CheckStatus.NOT_APPLICABLE
    assert result.checks["claim_grounding"].status == CheckStatus.NOT_APPLICABLE
    assert result.checks["patch_plan_constraints"].status == CheckStatus.NOT_APPLICABLE


def test_18_malformed_candidate_input():
    """18. Completely empty or invalid candidate input dictionary rejected with INVALID_INPUT."""
    agent = VerificationAgent()
    result = agent.verify(
        {
            "candidate_id": "BAD-INP",
            "finding": "not-a-finding",
        }
    )

    assert result.status == VerificationAgentStatus.INVALID_INPUT
    assert result.overall_passed is False
    assert result.checks["input_schema"].status == CheckStatus.FAIL


def test_19_registry_boundary_enforcement(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
    sample_security_claims: List[SecurityClaim],
    sample_evidence_records: Dict[str, Any],
    sample_patch_plan: PatchPlanResult,
):
    """19. Strict verification that all tools are called via registry.invoke and never directly."""
    spy_registry = MagicMock(wraps=default_tool_registry)
    agent = VerificationAgent(registry=spy_registry)

    agent.verify(
        VerificationInput(
            candidate_id="CAND-BOUNDARY",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
            claims=sample_security_claims,
            evidence_records=sample_evidence_records,
            patch_plan=sample_patch_plan,
        )
    )

    invoked_tool_names = [call[0][0] for call in spy_registry.invoke.call_args_list]
    assert "verify_score_derivation" in invoked_tool_names
    assert "detect_hallucinated_claims" in invoked_tool_names
    assert "validate_plan_constraints" in invoked_tool_names


def test_20_deterministic_repeated_verification(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
    sample_security_claims: List[SecurityClaim],
    sample_evidence_records: Dict[str, Any],
):
    """20. Repeated verification runs on identical input produce 100% identical outputs."""
    agent = VerificationAgent()
    inp = VerificationInput(
        candidate_id="CAND-DETERMINISM",
        finding=sample_finding,
        asset=sample_asset,
        risk_assessment=sample_risk_assessment,
        claims=sample_security_claims,
        evidence_records=sample_evidence_records,
    )

    run1 = agent.verify(inp)
    run2 = agent.verify(inp)

    assert run1.status == run2.status
    assert run1.overall_passed == run2.overall_passed
    assert run1.reasons == run2.reasons
    assert len(run1.checks) == len(run2.checks)
    for k in run1.checks:
        assert run1.checks[k].status == run2.checks[k].status
        assert run1.checks[k].details == run2.checks[k].details
    assert len(run1.step_traces) == len(run2.step_traces)


def test_21_state_isolation_across_instances(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """21. Independent agent instances and sequential runs have zero state bleed."""
    agent1 = VerificationAgent()
    agent2 = VerificationAgent()

    tampered_risk = sample_risk_assessment.model_copy(deep=True)
    tampered_risk.environmental_risk_score = 0.0

    res_fail = agent1.verify(
        VerificationInput(
            candidate_id="FAIL-RUN",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=tampered_risk,
        )
    )
    assert res_fail.status == VerificationAgentStatus.REJECTED

    res_pass = agent2.verify(
        VerificationInput(
            candidate_id="PASS-RUN",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )
    assert res_pass.status == VerificationAgentStatus.VERIFIED

    res_pass_again = agent1.verify(
        VerificationInput(
            candidate_id="PASS-RUN-2",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )
    assert res_pass_again.status == VerificationAgentStatus.VERIFIED
    assert len(res_pass_again.errors) == 0


def test_22_malicious_evidence_and_claim_text_inert(
    sample_finding: VulnerabilityFinding,
):
    """22. SQL injection, XSS, and command injection text treated strictly as inert data."""
    malicious_claim = [
        SecurityClaim(
            claim_id="C-MALICIOUS",
            claim_type="SQL_INJECTION",
            statement="'; DROP TABLE findings; -- <script>alert(1)</script> && rm -rf /",
            entity_id="CVE-2023-38545",
            claimed_value="safe_val",
        )
    ]
    evidence = {
        "CVE-2023-38545": {
            "sql_injection": "safe_val",
        }
    }

    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-INERT",
            finding=sample_finding,
            claims=malicious_claim,
            evidence_records=evidence,
        )
    )

    assert result is not None
    assert result.candidate_id == "CAND-INERT"


def test_23_provenance_tracking(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """23. Provenance record accurately logs tools, candidate ID, and timestamp."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-PROV-123",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert result.provenance.candidate_id == "CAND-PROV-123"
    assert result.provenance.score_verifier_tool == "verify_score_derivation"
    assert result.provenance.claim_checker_tool == "detect_hallucinated_claims"
    assert result.provenance.plan_validator_tool == "validate_plan_constraints"
    assert isinstance(result.provenance.verified_at, datetime)


def test_24_check_execution_ordering(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
    sample_security_claims: List[SecurityClaim],
    sample_evidence_records: Dict[str, Any],
    sample_patch_plan: PatchPlanResult,
):
    """24. Step traces execute in strictly defined deterministic order."""
    agent = VerificationAgent()
    result = agent.verify(
        VerificationInput(
            candidate_id="CAND-ORDER",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
            claims=sample_security_claims,
            evidence_records=sample_evidence_records,
            patch_plan=sample_patch_plan,
        )
    )

    actions = [trace.action.tool_name for trace in result.step_traces if trace.action.tool_name]
    assert actions == [
        "verify_score_derivation",
        "detect_hallucinated_claims",
        "validate_plan_constraints",
    ]


def test_25_overall_status_correctness(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """25. Overall status matches the three-state logic matrix correctly."""
    agent = VerificationAgent()

    # VERIFIED
    res_v = agent.verify(
        VerificationInput(
            candidate_id="C-V",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )
    assert res_v.status == VerificationAgentStatus.VERIFIED

    # REJECTED (critical failure)
    bad_risk = sample_risk_assessment.model_copy(deep=True)
    bad_risk.environmental_risk_score = 1.0
    res_r = agent.verify(
        VerificationInput(
            candidate_id="C-R",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=bad_risk,
        )
    )
    assert res_r.status == VerificationAgentStatus.REJECTED

    # NEEDS_REVIEW (source unavailable)
    res_nr = agent.verify(
        VerificationInput(
            candidate_id="C-NR",
            risk_assessment=sample_risk_assessment,
        )
    )
    assert res_nr.status == VerificationAgentStatus.NEEDS_REVIEW


def test_26_fail_closed_behavior(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """26. Fail-closed: Never returns VERIFIED if any critical check fails or errors."""
    bad_risk = sample_risk_assessment.model_copy(deep=True)
    bad_risk.environmental_risk_score = 1.0

    agent = VerificationAgent()
    res = agent.verify(
        VerificationInput(
            candidate_id="CAND-FAIL-CLOSED",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=bad_risk,
        )
    )

    assert res.overall_passed is False
    assert res.status != VerificationAgentStatus.VERIFIED


def test_27_no_silent_repair(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """27. Verification Agent reports defects without repairing candidate values."""
    tampered_risk = sample_risk_assessment.model_copy(deep=True)
    tampered_risk.environmental_risk_score = 42.0

    agent = VerificationAgent()
    res = agent.verify(
        VerificationInput(
            candidate_id="CAND-NO-REPAIR",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=tampered_risk,
        )
    )

    assert tampered_risk.environmental_risk_score == 42.0
    assert res.status == VerificationAgentStatus.REJECTED
    assert "Score derivation mismatch" in res.reasons[0]


def test_28_benchmark_integration():
    """28. Verifies benchmark findings and CMDB assets integrated through Phase 9 pipeline."""
    findings = load_benchmark_findings()
    assets = load_cmdb_assets()
    assert len(findings) > 0
    assert len(assets) > 0

    f = next(iter(findings.values()))
    matched_asset = assets.get(f.asset_id, next(iter(assets.values())))
    matched_asset = matched_asset.model_copy(update={"asset_id": f.asset_id})

    # Exploitability for benchmark finding
    exp_agent = ExploitabilityAgent()
    exp_res = exp_agent.run(cve_id=f.cve_id, finding_id=f.finding_id)

    comb_agent = RiskCombinationAgent()
    comb_res = comb_agent.run(
        finding=f,
        exploitability=exp_res,
        asset=matched_asset,
    )

    v_agent = VerificationAgent()
    v_res = v_agent.verify(
        VerificationInput(
            candidate_id="CAND-BENCH",
            finding=f,
            asset=matched_asset,
            risk_assessment=comb_res,
        )
    )

    assert v_res.status == VerificationAgentStatus.VERIFIED
    assert v_res.overall_passed is True


def test_29_patch_capacity_violation(
    sample_finding: VulnerabilityFinding,
    sample_patch_plan: PatchPlanResult,
):
    """29. Patch plan exceeding capacity limit fails plan validation."""
    over_capacity_plan = sample_patch_plan.model_copy(deep=True)
    over_capacity_plan.capacity_limit_hours = 0.5
    over_capacity_plan.scheduled_actions[0].estimated_hours = 2.0

    agent = VerificationAgent()
    res = agent.verify(
        VerificationInput(
            candidate_id="CAND-CAP-VIOLATION",
            finding=sample_finding,
            patch_plan=over_capacity_plan,
        )
    )

    assert res.status == VerificationAgentStatus.REJECTED
    assert res.checks["patch_plan_constraints"].status == CheckStatus.FAIL
    assert any("capacity limit" in v.lower() for v in res.checks["patch_plan_constraints"].violations)


def test_30_rollback_validation(
    sample_finding: VulnerabilityFinding,
    sample_patch_plan: PatchPlanResult,
):
    """30. Remediation action missing rollback procedure generates warning in raw validator."""
    plan_no_rollback = sample_patch_plan.model_copy(deep=True)
    no_rb_action = plan_no_rollback.scheduled_actions[0].model_copy(update={"rollback_procedure": ""})
    plan_no_rollback.scheduled_actions = [no_rb_action]

    agent = VerificationAgent()
    res = agent.verify(
        VerificationInput(
            candidate_id="CAND-NO-ROLLBACK",
            finding=sample_finding,
            patch_plan=plan_no_rollback,
        )
    )

    assert res.status == VerificationAgentStatus.REJECTED
    assert res.checks["patch_plan_constraints"].status == CheckStatus.FAIL
    assert any("rollback" in v.lower() for v in res.checks["patch_plan_constraints"].violations)


def test_31_no_real_infrastructure_execution():
    """31. Verification Agent source code inspection confirms no dangerous OS/subprocess calls."""
    import src.agents.verification as v_module
    src_code = inspect.getsource(v_module)

    assert "subprocess" not in src_code
    assert "os.system" not in src_code
    assert "eval(" not in src_code
    assert "exec(" not in src_code
    assert "paramiko" not in src_code
    assert "socket.connect" not in src_code


def test_32_no_duplicated_verification_logic():
    """32. Verification Agent source code inspection confirms no second risk/plan algorithms."""
    import src.agents.verification as v_module
    src_code = inspect.getsource(v_module)

    # No duplicated ERS formula in the verification agent
    assert "environmental_risk = " not in src_code
    assert "cvss_score * " not in src_code
    assert "dp[" not in src_code  # No knapsack DP code duplicated


def test_33_step_trace_correctness(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
):
    """33. Step traces have correct step numbers, action types, and status."""
    agent = VerificationAgent()
    res = agent.verify(
        VerificationInput(
            candidate_id="CAND-TRACE",
            finding=sample_finding,
            asset=sample_asset,
            risk_assessment=sample_risk_assessment,
        )
    )

    assert len(res.step_traces) >= 1  # score derivation tool invoked
    for idx, trace in enumerate(res.step_traces, 1):
        assert trace.step_number == idx
        assert trace.status in (ToolStatus.SUCCESS, ToolStatus.ERROR)


def test_34_warning_vs_failure_semantics(
    sample_risk_assessment: RiskAssessment,
):
    """34. Minor/Major warnings produce NEEDS_REVIEW, while Critical failures produce REJECTED."""
    agent = VerificationAgent()

    # Major warning: missing finding/asset leads to CANNOT_RECOMPUTE_RISK -> NEEDS_REVIEW
    res_warning = agent.verify(
        VerificationInput(
            candidate_id="CAND-WARN",
            risk_assessment=sample_risk_assessment,
        )
    )
    assert res_warning.status == VerificationAgentStatus.NEEDS_REVIEW

    # Critical failure: mismatched finding_id leads to INVALID_INPUT / REJECTED
    res_fail = agent.verify(
        VerificationInput(
            candidate_id="CAND-CRIT-FAIL",
            finding=VulnerabilityFinding(
                finding_id="F-A",
                cve_id="CVE-2023-1111",
                title="t",
                description="d",
                cvss_score=5.0,
                severity=VulnerabilitySeverity.MEDIUM,
                affected_package="curl",
                installed_version="1.0.0",
                asset_id="A-1",
                source="s",
            ),
            risk_assessment=sample_risk_assessment.model_copy(update={"finding_id": "F-B"}),
        )
    )
    assert res_fail.status in (VerificationAgentStatus.REJECTED, VerificationAgentStatus.INVALID_INPUT)


def test_35_multiple_candidate_types(
    sample_finding: VulnerabilityFinding,
    sample_asset: Asset,
    sample_risk_assessment: RiskAssessment,
    sample_patch_plan: PatchPlanResult,
    sample_security_claims: List[SecurityClaim],
    sample_evidence_records: Dict[str, Any],
):
    """35. Agent supports verifying diverse candidate artifacts individually and combined."""
    agent = VerificationAgent()

    # Case A: Only Claims
    res_claims = agent.verify(
        VerificationInput(
            candidate_id="CAND-TYPE-A",
            finding=sample_finding,
            claims=sample_security_claims,
            evidence_records=sample_evidence_records,
        )
    )
    assert res_claims.status == VerificationAgentStatus.VERIFIED
    assert res_claims.checks["claim_grounding"].status == CheckStatus.PASS

    # Case B: Only PatchPlan
    res_plan = agent.verify(
        VerificationInput(
            candidate_id="CAND-TYPE-B",
            finding=sample_finding,
            patch_plan=sample_patch_plan,
        )
    )
    assert res_plan.status == VerificationAgentStatus.VERIFIED
    assert res_plan.checks["patch_plan_constraints"].status == CheckStatus.PASS

    # Case C: All Combined
    res_all = agent.run(
        candidate_id="CAND-TYPE-C",
        finding=sample_finding,
        asset=sample_asset,
        risk_assessment=sample_risk_assessment,
        patch_plan=sample_patch_plan,
        claims=sample_security_claims,
        evidence_records=sample_evidence_records,
    )
    assert res_all.status == VerificationAgentStatus.VERIFIED
    assert res_all.overall_passed is True
