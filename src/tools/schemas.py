"""Pydantic v2 schemas and structured data contracts for Aegis Patch deterministic tools."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.schemas.asset import Asset, AssetCriticality, BusinessTier, EnvironmentType, NetworkExposure
from src.schemas.plan import PatchCandidate
from src.schemas.risk import RemediationDecision, RiskTier
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.decision_mapping import AegisDecision


# ======================================================================
# Tool Status & Side-Effect Enums
# ======================================================================

class ToolStatus(str, Enum):
    """Execution status returned by deterministic tools."""

    SUCCESS = "SUCCESS"
    NOT_FOUND = "NOT_FOUND"
    NOT_AVAILABLE = "NOT_AVAILABLE"
    INVALID_INPUT = "INVALID_INPUT"
    CONFLICT = "CONFLICT"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    ERROR = "ERROR"


class SideEffectClass(str, Enum):
    """Categorical classification of tool operational behavior."""

    READ_ONLY = "READ_ONLY"
    COMPUTE_ONLY = "COMPUTE_ONLY"
    PERSISTENCE_WRITE = "PERSISTENCE_WRITE"
    SIMULATION = "SIMULATION"


class ProvenanceSourceType(str, Enum):
    """Origin category for audit and intelligence data."""

    LOCAL_DATASET = "LOCAL_DATASET"
    LOCAL_CACHE = "LOCAL_CACHE"
    SYNTHETIC = "SYNTHETIC"
    BENCHMARK = "BENCHMARK"
    PERSISTED_DATABASE = "PERSISTED_DATABASE"
    CALCULATED = "CALCULATED"


class ClaimVerificationStatus(str, Enum):
    """Verification state for security claims against available evidence."""

    SUPPORTED = "SUPPORTED"
    UNSUPPORTED = "UNSUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"


# ======================================================================
# Common Provenance & Envelope Models
# ======================================================================

class ToolProvenance(BaseModel):
    """Audit metadata capturing source origins and observation timestamps."""

    model_config = ConfigDict(extra="forbid")

    source: str = Field(..., description="Origin name of the data or engine")
    source_type: ProvenanceSourceType = Field(..., description="Classification of provenance origin")
    observed_at: Optional[datetime] = Field(None, description="Timestamp telemetry or finding was observed")
    dataset_version: Optional[str] = Field(None, description="Version identifier of underlying dataset")
    confidence: Optional[str] = Field(None, description="Reported source confidence level")
    reference: Optional[str] = Field(None, description="Documentation or file path reference")


class BaseToolResult(BaseModel):
    """Common envelope returned by all deterministic tools."""

    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(..., description="Unique machine-readable tool identifier")
    status: ToolStatus = Field(..., description="Standardized execution outcome status")
    message: str = Field(..., description="Human-readable execution summary or failure reason")
    side_effect: SideEffectClass = Field(..., description="Side-effect classification")
    provenance: Optional[ToolProvenance] = Field(None, description="Evidence provenance metadata")


# ======================================================================
# 1. parse_raw_scan
# ======================================================================

class ParseRawScanInput(BaseModel):
    """Input payload for raw scanner output parsing."""

    model_config = ConfigDict(extra="forbid")

    raw_payload: Union[str, Dict[str, Any], List[Any]] = Field(
        ..., description="Raw scan findings (JSON string, dict, or list of scan records)"
    )
    scanner_name: Optional[str] = Field(None, description="Scanner name if known (e.g., Trivy, Grype)")
    target_asset_id: Optional[str] = Field(None, description="Default target asset ID if not embedded in records")


class ParseRawScanOutput(BaseToolResult):
    """Normalized finding records parsed from raw scan data."""

    findings: List[VulnerabilityFinding] = Field(default_factory=list, description="Parsed normalized findings")
    parsed_count: int = Field(0, description="Count of successfully parsed finding records")
    error_count: int = Field(0, description="Count of records failing structure or normalization")
    errors: List[str] = Field(default_factory=list, description="Descriptions of malformed or skipped items")


# ======================================================================
# 2. validate_finding_schema
# ======================================================================

class ValidateFindingSchemaInput(BaseModel):
    """Input finding data to validate against the authoritative schema."""

    model_config = ConfigDict(extra="forbid")

    finding_data: Dict[str, Any] = Field(..., description="Candidate finding dictionary to validate")


class ValidateFindingSchemaOutput(BaseToolResult):
    """Outcome of contract validation against VulnerabilityFinding schema."""

    is_valid: bool = Field(..., description="Whether the finding conforms to contract")
    validated_finding: Optional[VulnerabilityFinding] = Field(None, description="Instantiated schema if valid")
    validation_errors: List[str] = Field(default_factory=list, description="List of schema constraint violations")


# ======================================================================
# 3. deduplicate_findings
# ======================================================================

class DeduplicateFindingsInput(BaseModel):
    """List of findings to deduplicate based on identity tuples."""

    model_config = ConfigDict(extra="forbid")

    findings: List[VulnerabilityFinding] = Field(..., description="Candidate vulnerability findings")


class DuplicateFindingGroup(BaseModel):
    """Group of duplicated findings sharing identical identity characteristics."""

    model_config = ConfigDict(extra="forbid")

    identity_key: str = Field(..., description="Hash/key tuple representing identity (asset_id, cve_id, package)")
    retained_finding_id: str = Field(..., description="Selected unique finding identifier")
    duplicate_finding_ids: List[str] = Field(..., description="Finding identifiers considered duplicates")


class DeduplicateFindingsOutput(BaseToolResult):
    """Deduplication analysis results."""

    unique_findings: List[VulnerabilityFinding] = Field(default_factory=list, description="Deduplicated unique findings")
    total_input_count: int = Field(0, description="Total input findings evaluated")
    unique_count: int = Field(0, description="Unique findings count")
    duplicate_count: int = Field(0, description="Duplicate findings count")
    duplicate_groups: List[DuplicateFindingGroup] = Field(default_factory=list, description="Identified duplicate sets")


# ======================================================================
# 4. lookup_cisa_kev
# ======================================================================

class LookupCisaKevInput(BaseModel):
    """Target CVE identifier for local CISA KEV query."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Standard CVE identifier")


class LookupCisaKevOutput(BaseToolResult):
    """Outcome of local CISA KEV inspection."""

    cve_id: str = Field(..., description="Queried CVE identifier")
    is_known_exploited: bool = Field(False, description="Whether the CVE is present in local KEV cache")
    date_added: Optional[str] = Field(None, description="Date added to KEV catalog if recorded")
    due_date: Optional[str] = Field(None, description="Remediation due date if recorded")
    notes: Optional[str] = Field(None, description="Advisory or mitigation notes")


# ======================================================================
# 5. query_epss
# ======================================================================

class QueryEpssInput(BaseModel):
    """Target CVE identifier for local EPSS lookup."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str = Field(..., pattern=r"^CVE-\d{4}-\d{4,7}$", description="Standard CVE identifier")


class QueryEpssOutput(BaseToolResult):
    """Locally stored EPSS score and percentile."""

    cve_id: str = Field(..., description="Queried CVE identifier")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Exploit Prediction Scoring System probability")
    percentile: Optional[float] = Field(None, ge=0.0, le=1.0, description="EPSS percentile ranking")
    observed_at: Optional[datetime] = Field(None, description="Timestamp EPSS observation was recorded")


# ======================================================================
# 6. query_osv_database
# ======================================================================

class QueryOsvDatabaseInput(BaseModel):
    """Package coordinate and vulnerability query for local OSV dataset."""

    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(..., min_length=1, description="Ecosystem package name")
    version: Optional[str] = Field(None, description="Installed component version string")
    cve_id: Optional[str] = Field(None, pattern=r"^CVE-\d{4}-\d{4,7}$", description="Specific CVE identifier")


class QueryOsvDatabaseOutput(BaseToolResult):
    """Open Source Vulnerability (OSV) local intelligence results."""

    package_name: str
    version: Optional[str] = None
    advisories: List[Dict[str, Any]] = Field(default_factory=list, description="Matching local OSV advisory records")
    fixed_versions: List[str] = Field(default_factory=list, description="Known patched upstream releases")


# ======================================================================
# 7. query_asset_cmdb
# ======================================================================

class QueryAssetCmdbInput(BaseModel):
    """Asset domain identifier to inspect."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., min_length=1, description="Enterprise asset identifier (e.g., ASSET-001)")


class QueryAssetCmdbOutput(BaseToolResult):
    """Enterprise asset operational context and compensating controls."""

    asset: Optional[Asset] = Field(None, description="Standardized Asset schema instance")
    compensating_controls: List[str] = Field(default_factory=list, description="Active security controls on asset")
    patch_window: Optional[str] = Field(None, description="Scheduled operational maintenance window")


# ======================================================================
# 8. get_network_reachability
# ======================================================================

class GetNetworkReachabilityInput(BaseModel):
    """Target asset identifier to evaluate boundary exposure."""

    model_config = ConfigDict(extra="forbid")

    asset_id: str = Field(..., min_length=1, description="Target asset identifier")


class GetNetworkReachabilityOutput(BaseToolResult):
    """Network reachability assessment based on CMDB topology."""

    asset_id: str
    network_exposure: NetworkExposure = Field(..., description="Operational network boundary zone")
    reachable_from_internet: bool = Field(..., description="Flag indicating external ingress reachability")
    rationale: str = Field(..., description="Justification derived from asset metadata and compensating controls")


# ======================================================================
# 9. query_rag_policy
# ======================================================================

class QueryRagPolicyInput(BaseModel):
    """Policy query keyword, topic, or policy ID."""

    model_config = ConfigDict(extra="forbid")

    query: str = Field(..., min_length=1, description="Search term or policy identifier (e.g., POL-SEC-04, SLA)")
    policy_id: Optional[str] = Field(None, description="Direct policy ID lookup if known")


class PolicyClause(BaseModel):
    """Structured clause or metadata extracted from a policy document."""

    model_config = ConfigDict(extra="forbid")

    policy_id: str
    title: str
    section: Optional[str] = None
    content: str
    relevance_rationale: str


class QueryRagPolicyOutput(BaseToolResult):
    """Deterministic local policy retrieval results."""

    retrieval_mode: str = Field(default="LOCAL_DETERMINISTIC", description="Mode of retrieval")
    matched_policies: List[PolicyClause] = Field(default_factory=list, description="Relevant policy excerpts")


# ======================================================================
# 10. calculate_environmental_risk
# ======================================================================

class CalculateEnvironmentalRiskInput(BaseModel):
    """Input evidence required for Phase 3 contextual risk calculation."""

    model_config = ConfigDict(extra="forbid")

    finding: VulnerabilityFinding = Field(..., description="Target scanner finding")
    asset: Asset = Field(..., description="Target enterprise asset")
    is_cisa_kev: bool = Field(default=False, description="Whether vulnerability is listed in CISA KEV")
    epss_score: Optional[float] = Field(default=None, ge=0.0, le=1.0, description="Observed EPSS probability")
    public_poc_available: bool = Field(default=False, description="Public Proof-of-Concept exploit code existence")


class CalculateEnvironmentalRiskOutput(BaseToolResult):
    """Deterministic contextual risk assessment results."""

    assessment_id: str
    finding_id: str
    cve_id: str
    asset_id: str

    base_score: float = Field(..., description="Base vulnerability score B (CVSS scaled to 0-10)")
    threat_score: float = Field(..., description="Threat telemetry score T (0-10)")
    environmental_score: float = Field(..., description="Asset environmental score E (0-10)")
    raw_risk_score: float = Field(..., description="Composite unmitigated risk score R (0-100)")
    control_multiplier: float = Field(..., description="Compensating control mitigation multiplier M_control (0.0-1.0)")
    environmental_risk_score: float = Field(..., description="Final Environmental Risk Score ERS (0-100)")

    risk_tier: RiskTier = Field(..., description="Environmental risk tier")
    decision: AegisDecision = Field(..., description="Aegis triage decision band (ACT, ATTEND, PLAN, TRACK)")
    remediation_decision: RemediationDecision = Field(..., description="Operational triage recommendation")
    explanation: str = Field(..., description="Deterministic human-readable explanation")
    supporting_evidence: List[str] = Field(default_factory=list, description="Audit trace items")
    engine_version: str = Field(default="aegis_ers_deterministic_v1", description="Engine version")


# ======================================================================
# 11. map_ssvc_decision
# ======================================================================

class MapSsvcDecisionInput(BaseModel):
    """Environmental Risk Score and mitigating control status to map."""

    model_config = ConfigDict(extra="forbid")

    ers_score: float = Field(..., ge=0.0, le=100.0, description="Calculated Environmental Risk Score (0-100)")
    has_compensating_controls: bool = Field(default=False, description="Whether active controls exist on asset")


class MapSsvcDecisionOutput(BaseToolResult):
    """Decision classification based on transparent project thresholds."""

    ers_score: float
    decision: AegisDecision = Field(..., description="Aegis decision band (ACT, ATTEND, PLAN, TRACK)")
    risk_tier: RiskTier = Field(..., description="Environmental risk tier")
    remediation_decision: RemediationDecision = Field(..., description="Operational action recommendation")
    meaning: str = Field(..., description="Operational definition of the decision band")


# ======================================================================
# 12. optimize_patch_capacity
# ======================================================================

class OptimizePatchCapacityInput(BaseModel):
    """Candidate remediation tasks and engineering capacity limit."""

    model_config = ConfigDict(extra="forbid")

    candidates: List[PatchCandidate] = Field(..., description="List of candidate vulnerabilities to schedule")
    capacity_limit_hours: float = Field(default=16.0, ge=0.0, description="Maintenance window capacity in hours")


class OptimizePatchCapacityOutput(BaseToolResult):
    """Deterministic knapsack optimization schedule."""

    capacity_limit_hours: float
    total_scheduled_effort_hours: float
    total_expected_risk_reduction: float
    remaining_capacity_hours: float
    capacity_utilization_percent: float
    scheduled_candidates: List[PatchCandidate] = Field(default_factory=list)
    deferred_candidates: List[PatchCandidate] = Field(default_factory=list)
    algorithm: str = Field(default="deterministic_0_1_knapsack_dp", description="Optimization algorithm used")


# ======================================================================
# 13. resolve_package_dependencies
# ======================================================================

class ResolvePackageDependenciesInput(BaseModel):
    """Package and target asset coordinates to evaluate dependencies."""

    model_config = ConfigDict(extra="forbid")

    package_name: str = Field(..., min_length=1)
    target_version: str = Field(..., min_length=1)
    installed_version: Optional[str] = None
    asset_id: Optional[str] = None


class DependencyItem(BaseModel):
    """Identified prerequisite package requirement."""

    model_config = ConfigDict(extra="forbid")

    package_name: str
    required_version: str
    dependency_type: str = Field(..., description="'DIRECT', 'TRANSITIVE', or 'CONFLICT'")


class ResolvePackageDependenciesOutput(BaseToolResult):
    """Package dependency analysis outcome."""

    package_name: str
    target_version: str
    prerequisites: List[DependencyItem] = Field(default_factory=list)
    conflicts: List[str] = Field(default_factory=list)
    has_conflicts: bool = False


# ======================================================================
# 14. simulate_risk_reduction
# ======================================================================

class SimulateRiskReductionInput(BaseModel):
    """Baseline finding and asset with proposed hypothetical control/remediation changes."""

    model_config = ConfigDict(extra="forbid")

    finding: VulnerabilityFinding = Field(..., description="Current vulnerability finding")
    asset: Asset = Field(..., description="Current enterprise asset")
    hypothetical_controls_added: List[str] = Field(
        default_factory=list, description="Controls assumed to be newly active"
    )
    is_cisa_kev: bool = False
    epss_score: Optional[float] = None
    public_poc_available: bool = False


class SimulateRiskReductionOutput(BaseToolResult):
    """What-if projected risk reduction simulation results."""

    current_ers: float = Field(..., description="Baseline Environmental Risk Score")
    simulated_ers: float = Field(..., description="Projected Environmental Risk Score after intervention")
    projected_risk_reduction: float = Field(..., description="Difference: current_ers - simulated_ers")
    current_decision: AegisDecision
    simulated_decision: AegisDecision
    simulation_label: str = Field(default="SIMULATED", description="Label highlighting non-live simulation")


# ======================================================================
# 15. verify_score_derivation
# ======================================================================

class VerifyScoreDerivationInput(BaseModel):
    """Claimed risk evaluation components to independently verify."""

    model_config = ConfigDict(extra="forbid")

    finding: VulnerabilityFinding
    asset: Asset
    claimed_base_score: float
    claimed_threat_score: float
    claimed_environmental_score: float
    claimed_control_multiplier: float
    claimed_ers: float
    claimed_decision: str
    is_cisa_kev: bool = False
    epss_score: Optional[float] = None
    public_poc_available: bool = False
    tolerance: float = Field(default=0.01, ge=0.0, description="Allowable floating-point difference")


class ScoreMismatch(BaseModel):
    """Difference detected between claimed and independently calculated value."""

    model_config = ConfigDict(extra="forbid")

    field: str
    claimed: Union[float, str]
    calculated: Union[float, str]
    difference: Optional[float] = None


class VerifyScoreDerivationOutput(BaseToolResult):
    """Verification outcome proving mathematical integrity."""

    is_verified: bool = Field(..., description="Whether all components matched within tolerance")
    mismatches: List[ScoreMismatch] = Field(default_factory=list, description="List of detected discrepancies")
    recomputed_ers: float = Field(..., description="Authoritatively recomputed ERS")
    recomputed_decision: str = Field(..., description="Authoritatively recomputed decision")


# ======================================================================
# 16. detect_hallucinated_claims
# ======================================================================

class SecurityClaim(BaseModel):
    """Specific factual claim to verify against evidence."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    claim_type: str = Field(..., description="e.g. 'CISA_KEV_STATUS', 'CVSS_SCORE', 'EXPOSURE'")
    statement: str = Field(..., description="Natural language assertion")
    entity_id: str = Field(..., description="Associated CVE or Asset ID (e.g. CVE-2023-38545)")
    claimed_value: Any = Field(..., description="Claimed factual property value")


class ClaimVerificationResult(BaseModel):
    """Audit outcome for an individual claim."""

    model_config = ConfigDict(extra="forbid")

    claim_id: str
    status: ClaimVerificationStatus
    evidence_reference: Optional[str] = None
    rationale: str


class DetectHallucinatedClaimsInput(BaseModel):
    """Claims to verify against available ground-truth evidence records."""

    model_config = ConfigDict(extra="forbid")

    claims: List[SecurityClaim] = Field(..., description="List of assertions to verify")
    evidence_records: Dict[str, Any] = Field(
        ..., description="Map of factual records (e.g. {'CVE-2023-38545': {...}, 'ASSET-001': {...}})"
    )


class DetectHallucinatedClaimsOutput(BaseToolResult):
    """Verification of assertions against provided evidence."""

    all_claims_supported: bool
    results: List[ClaimVerificationResult] = Field(default_factory=list)
    unsupported_count: int = 0


# ======================================================================
# 17. validate_plan_constraints
# ======================================================================

class PlanConstraintItem(BaseModel):
    """Individual item within a plan undergoing constraint validation."""

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    sequence_order: int
    estimated_hours: float
    has_rollback_plan: bool = False


class ValidatePlanConstraintsInput(BaseModel):
    """Proposed patch plan configuration to validate against hard rules."""

    model_config = ConfigDict(extra="forbid")

    plan_id: str
    capacity_limit_hours: float
    items: List[PlanConstraintItem]
    known_finding_ids: List[str] = Field(..., description="Set of legitimate finding IDs in database")


class PlanConstraintViolation(BaseModel):
    """Specific violated operational constraint rule."""

    model_config = ConfigDict(extra="forbid")

    rule_name: str
    violation_message: str
    severity: str = "ERROR"


class ValidatePlanConstraintsOutput(BaseToolResult):
    """Validation report ensuring plan adheres to capacity, integrity, and safety rules."""

    is_valid: bool
    violations: List[PlanConstraintViolation] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    total_estimated_hours: float
    capacity_limit_hours: float
