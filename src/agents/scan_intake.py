"""Scan Intake Specialist Agent for Aegis Patch.

Phase 9A: Transforms raw incoming vulnerability scan payloads into trustworthy,
normalized, validated, and deduplicated findings for downstream security reasoning.

Architectural Guarantees:
1. Tool Boundary: All tools are invoked exclusively via ToolRegistry.invoke.
   Never imports or calls tool implementation functions directly.
2. State Isolation: Complete per-execution state isolation with zero mutable module-level state.
3. Strict Determinism: Deterministic processing, sorting, and diagnostic assignment.
4. Security: Treats all scanner inputs as untrusted data; no eval, shell, network, or DB calls.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
import json
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, ConfigDict, Field

from src.agents.schemas import (
    AgentAction,
    AgentNotice,
    AgentStepActionType,
    AgentStepTrace,
    NoticeSeverity,
)
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.registry import ToolRegistry, default_tool_registry
from src.tools.schemas import (
    BaseToolResult,
    DeduplicateFindingsInput,
    DeduplicateFindingsOutput,
    DuplicateFindingGroup,
    ParseRawScanInput,
    ParseRawScanOutput,
    ToolStatus,
    ValidateFindingSchemaInput,
    ValidateFindingSchemaOutput,
)


class ScanIntakeStatus(str, Enum):
    """Categorical execution status of the Scan Intake Agent."""

    SUCCESS = "SUCCESS"
    PARTIAL_SUCCESS = "PARTIAL_SUCCESS"
    EMPTY_INPUT = "EMPTY_INPUT"
    INVALID_INPUT = "INVALID_INPUT"
    FAILED = "FAILED"


class ScanIntakeInput(BaseModel):
    """Strongly typed input specification for the Scan Intake Agent."""

    model_config = ConfigDict(extra="forbid")

    raw_payload: Optional[Any] = Field(
        default=None,
        description="Raw scanner output payload (JSON string, single dictionary, or list of records)",
    )
    scanner_name: Optional[str] = Field(
        default="generic_scanner",
        description="Name of the reporting scanner engine (e.g. snyk, trivy, qualys)",
    )
    target_asset_id: Optional[str] = Field(
        default=None,
        description="Optional fallback enterprise asset identifier to attach to findings missing an asset_id",
    )
    scan_id: Optional[str] = Field(
        default=None,
        description="Optional tracking identifier for this vulnerability scan batch",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Optional non-evaluative scanner run metadata",
    )


class ScanIntakeRejectionNotice(BaseModel):
    """Structured notice explaining why a candidate finding was rejected during intake."""

    model_config = ConfigDict(extra="forbid")

    finding_index: Optional[int] = Field(
        default=None,
        description="0-indexed position in raw input records if applicable",
    )
    finding_id: Optional[str] = Field(
        default=None,
        description="Candidate finding identifier if present in the raw record",
    )
    reason: str = Field(
        ...,
        description="Clear explanation of the schema violation or failure",
    )
    raw_record_snippet: Optional[str] = Field(
        default=None,
        description="Safe truncated snippet of the offending record without secret exposure",
    )


class ScanIntakeResult(BaseModel):
    """Authoritative outcome delivered by the Scan Intake Agent."""

    model_config = ConfigDict(extra="forbid")

    status: ScanIntakeStatus = Field(
        ...,
        description="Overall deterministic outcome of the scan intake workflow",
    )
    clean_findings: List[VulnerabilityFinding] = Field(
        default_factory=list,
        description="Normalized, validated, deduplicated findings ready for security reasoning",
    )
    raw_count: int = Field(
        default=0,
        ge=0,
        description="Total raw records observed in incoming payload",
    )
    parsed_count: int = Field(
        default=0,
        ge=0,
        description="Number of records successfully parsed by parser tool",
    )
    validated_count: int = Field(
        default=0,
        ge=0,
        description="Number of findings successfully passing schema validation",
    )
    rejected_count: int = Field(
        default=0,
        ge=0,
        description="Number of candidate records rejected during parsing or validation",
    )
    duplicate_count: int = Field(
        default=0,
        ge=0,
        description="Number of duplicate findings identified and pruned",
    )
    unique_count: int = Field(
        default=0,
        ge=0,
        description="Number of unique findings retained in clean_findings",
    )
    rejection_notices: List[ScanIntakeRejectionNotice] = Field(
        default_factory=list,
        description="Detailed notices for rejected or invalid candidate findings",
    )
    duplicate_groups: List[DuplicateFindingGroup] = Field(
        default_factory=list,
        description="Audit groups mapping retained findings to pruned duplicate IDs",
    )
    step_traces: List[AgentStepTrace] = Field(
        default_factory=list,
        description="Chronological audit traces of each tool execution step",
    )
    errors: List[AgentNotice] = Field(
        default_factory=list,
        description="Blocking or critical diagnostic errors encountered",
    )
    warnings: List[AgentNotice] = Field(
        default_factory=list,
        description="Non-fatal operational warnings or parsing discrepancies",
    )
    scan_id: Optional[str] = Field(
        default=None,
        description="Originating scan identifier if provided",
    )
    scanner_name: Optional[str] = Field(
        default=None,
        description="Originating scanner name if provided",
    )
    processed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when intake processing completed",
    )


class ScanIntakeAgent:
    """Specialist agent that normalizes, validates, and deduplicates raw vulnerability scans.

    Maintains per-run state isolation and routes all tool invocations through the ToolRegistry.
    """

    def __init__(
        self,
        registry: Optional[ToolRegistry] = None,
        max_findings: int = 5000,
    ) -> None:
        self._registry = registry or default_tool_registry
        self._max_findings = max_findings

    @property
    def registry(self) -> ToolRegistry:
        """Active tool registry."""
        return self._registry

    def run(
        self,
        raw_payload: Optional[Union[Any, ScanIntakeInput]] = None,
        scanner_name: Optional[str] = "generic_scanner",
        target_asset_id: Optional[str] = None,
        scan_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> ScanIntakeResult:
        """Convenience invocation accepting input model, dict, or raw arguments."""
        if isinstance(raw_payload, ScanIntakeInput):
            return self.process(raw_payload)
        if isinstance(raw_payload, dict) and "raw_payload" in raw_payload:
            return self.process(raw_payload)
        intake_input = ScanIntakeInput(
            raw_payload=raw_payload,
            scanner_name=scanner_name,
            target_asset_id=target_asset_id,
            scan_id=scan_id,
            metadata=metadata or {},
        )
        return self.process(intake_input)

    def process(
        self,
        input_data: Union[ScanIntakeInput, Dict[str, Any]],
    ) -> ScanIntakeResult:
        """Execute the deterministic intake pipeline with isolated local state.

        Steps:
        1. Validate agent input schema and check for empty payload.
        2. Tool 1: parse_raw_scan
        3. Tool 2: validate_finding_schema (per parsed finding)
        4. Tool 3: deduplicate_findings (on validated pool)
        5. Normalize and assemble final ScanIntakeResult.
        """
        step_traces: List[AgentStepTrace] = []
        errors: List[AgentNotice] = []
        warnings: List[AgentNotice] = []
        rejection_notices: List[ScanIntakeRejectionNotice] = []
        step_counter = 1

        # 1. Validate agent input
        if isinstance(input_data, dict):
            try:
                typed_input = ScanIntakeInput.model_validate(input_data)
            except Exception as val_err:
                return ScanIntakeResult(
                    status=ScanIntakeStatus.INVALID_INPUT,
                    errors=[
                        AgentNotice(
                            code="INVALID_AGENT_INPUT",
                            message=f"Agent input validation failed: {val_err}",
                            severity=NoticeSeverity.ERROR,
                            step_number=step_counter,
                        )
                    ],
                )
        elif isinstance(input_data, ScanIntakeInput):
            typed_input = input_data
        else:
            return ScanIntakeResult(
                status=ScanIntakeStatus.INVALID_INPUT,
                errors=[
                    AgentNotice(
                        code="UNSUPPORTED_INPUT_TYPE",
                        message=f"Expected ScanIntakeInput or dict, got {type(input_data).__name__}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                ],
            )

        raw = typed_input.raw_payload

        # 2. Check for empty payload
        if raw is None or (isinstance(raw, str) and not raw.strip()) or (isinstance(raw, (list, dict)) and len(raw) == 0):
            return ScanIntakeResult(
                status=ScanIntakeStatus.EMPTY_INPUT,
                warnings=[
                    AgentNotice(
                        code="EMPTY_PAYLOAD",
                        message="Incoming raw scan payload is empty.",
                        severity=NoticeSeverity.WARNING,
                        step_number=step_counter,
                    )
                ],
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        if not isinstance(raw, (str, dict, list)):
            return ScanIntakeResult(
                status=ScanIntakeStatus.INVALID_INPUT,
                rejection_notices=[
                    ScanIntakeRejectionNotice(
                        reason=f"Unsupported raw_payload type: {type(raw).__name__}",
                    )
                ],
                errors=[
                    AgentNotice(
                        code="UNSUPPORTED_PAYLOAD_TYPE",
                        message=f"Raw payload must be str, dict, or list, got {type(raw).__name__}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                ],
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        # Estimate raw count if list or single dict
        raw_count = 1
        if isinstance(raw, list):
            raw_count = len(raw)
        elif isinstance(raw, str):
            try:
                parsed_json = json.loads(raw)
                if isinstance(parsed_json, list):
                    raw_count = len(parsed_json)
                elif isinstance(parsed_json, dict):
                    raw_count = 1
            except Exception:
                raw_count = 1

        if raw_count > self._max_findings:
            return ScanIntakeResult(
                status=ScanIntakeStatus.FAILED,
                errors=[
                    AgentNotice(
                        code="PAYLOAD_LIMIT_EXCEEDED",
                        message=f"Scan payload contains {raw_count} records, exceeding max boundary of {self._max_findings}.",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                ],
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        # 3. STEP 1: Tool parse_raw_scan
        parse_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="parse_raw_scan",
            rationale="Parse raw scanner payload into structured candidate vulnerability findings",
        )
        try:
            parse_input = ParseRawScanInput(
                raw_payload=typed_input.raw_payload,
                scanner_name=typed_input.scanner_name,
                target_asset_id=typed_input.target_asset_id,
            )
            parse_output = self._registry.invoke("parse_raw_scan", parse_input)
            if not isinstance(parse_output, ParseRawScanOutput):
                raise TypeError(f"Expected ParseRawScanOutput from parse_raw_scan, got {type(parse_output).__name__}")
        except Exception as err:
            err_notice = AgentNotice(
                code="PARSE_TOOL_ERROR",
                message=f"Tool 'parse_raw_scan' execution failed: {err}",
                severity=NoticeSeverity.ERROR,
                step_number=step_counter,
            )
            errors.append(err_notice)
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=parse_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during parse_raw_scan: {err}",
                )
            )
            return ScanIntakeResult(
                status=ScanIntakeStatus.FAILED,
                step_traces=step_traces,
                errors=errors,
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        step_traces.append(
            AgentStepTrace(
                step_number=step_counter,
                action=parse_action,
                tool_result=parse_output,
                status=parse_output.status,
                notes=f"Parsed {parse_output.parsed_count} candidate findings, encountered {parse_output.error_count} parser errors.",
            )
        )
        step_counter += 1

        # Check parser fatal failure
        if parse_output.status in (ToolStatus.INVALID_INPUT, ToolStatus.ERROR) and parse_output.parsed_count == 0:
            is_syntax_or_type_error = (
                isinstance(raw, str)
                or not isinstance(raw, (list, dict))
                or any("neither a list nor an object" in e or "Unsupported raw_payload type" in e or "Failed to parse raw JSON" in e for e in parse_output.errors)
            )
            final_fail_status = (
                ScanIntakeStatus.INVALID_INPUT if is_syntax_or_type_error else ScanIntakeStatus.FAILED
            )
            for parse_err in parse_output.errors:
                errors.append(
                    AgentNotice(
                        code="PARSER_FAILURE" if is_syntax_or_type_error else "VALIDATION_FAILURE",
                        message=parse_err,
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter - 1,
                    )
                )
                rejection_notices.append(
                    ScanIntakeRejectionNotice(
                        reason=f"Parser/Validation rejection: {parse_err}",
                    )
                )
            return ScanIntakeResult(
                status=final_fail_status,
                raw_count=raw_count,
                parsed_count=0,
                rejected_count=raw_count,
                rejection_notices=rejection_notices,
                step_traces=step_traces,
                errors=errors,
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        # Collect parser non-blocking warnings/errors
        for parse_err in parse_output.errors:
            warnings.append(
                AgentNotice(
                    code="PARSER_WARNING",
                    message=parse_err,
                    severity=NoticeSeverity.WARNING,
                    step_number=step_counter - 1,
                )
            )
            rejection_notices.append(
                ScanIntakeRejectionNotice(
                    reason=f"Parser record error: {parse_err}",
                )
            )

        candidate_findings = parse_output.findings
        parsed_count = len(candidate_findings)

        if parsed_count == 0:
            return ScanIntakeResult(
                status=ScanIntakeStatus.EMPTY_INPUT if not parse_output.errors else ScanIntakeStatus.INVALID_INPUT,
                raw_count=raw_count,
                parsed_count=0,
                rejected_count=raw_count,
                rejection_notices=rejection_notices,
                step_traces=step_traces,
                warnings=warnings,
                errors=errors,
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        # 4. STEP 2: Tool validate_finding_schema (per candidate finding)
        validated_findings: List[VulnerabilityFinding] = []
        validation_errors_count = 0

        validate_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="validate_finding_schema",
            rationale=f"Validate schema conformance for {parsed_count} candidate findings against VulnerabilityFinding contract",
        )

        last_val_result: Optional[BaseToolResult] = None
        for idx, candidate in enumerate(candidate_findings):
            try:
                val_input = ValidateFindingSchemaInput(
                    finding_data=candidate.model_dump()
                )
                val_output = self._registry.invoke("validate_finding_schema", val_input)
                if not isinstance(val_output, ValidateFindingSchemaOutput):
                    raise TypeError(
                        f"Expected ValidateFindingSchemaOutput from validate_finding_schema, got {type(val_output).__name__}"
                    )
                last_val_result = val_output

                if val_output.status == ToolStatus.SUCCESS and val_output.is_valid:
                    validated_finding = val_output.validated_finding or candidate
                    validated_findings.append(validated_finding)
                else:
                    validation_errors_count += 1
                    err_msg = "; ".join(val_output.validation_errors) if val_output.validation_errors else val_output.message
                    rejection_notices.append(
                        ScanIntakeRejectionNotice(
                            finding_index=idx,
                            finding_id=candidate.finding_id,
                            reason=f"Schema validation failed: {err_msg}",
                            raw_record_snippet=f"cve_id={candidate.cve_id}, package={candidate.affected_package}",
                        )
                    )
                    warnings.append(
                        AgentNotice(
                            code="VALIDATION_REJECTION",
                            message=f"Finding '{candidate.finding_id}' rejected: {err_msg}",
                            severity=NoticeSeverity.WARNING,
                            step_number=step_counter,
                        )
                    )
            except Exception as err:
                validation_errors_count += 1
                rejection_notices.append(
                    ScanIntakeRejectionNotice(
                        finding_index=idx,
                        finding_id=candidate.finding_id,
                        reason=f"Validation invocation exception: {err}",
                    )
                )
                errors.append(
                    AgentNotice(
                        code="VALIDATION_TOOL_ERROR",
                        message=f"Validation failed with exception on finding '{candidate.finding_id}': {err}",
                        severity=NoticeSeverity.ERROR,
                        step_number=step_counter,
                    )
                )

        step_traces.append(
            AgentStepTrace(
                step_number=step_counter,
                action=validate_action,
                tool_result=last_val_result,
                status=ToolStatus.SUCCESS if validation_errors_count == 0 else ToolStatus.INVALID_INPUT,
                notes=f"Validated {len(validated_findings)}/{parsed_count} candidate findings. Rejected {validation_errors_count}.",
            )
        )
        step_counter += 1

        validated_count = len(validated_findings)
        rejected_count = (raw_count - parsed_count) + validation_errors_count

        # If zero findings passed validation
        if validated_count == 0:
            return ScanIntakeResult(
                status=ScanIntakeStatus.FAILED,
                raw_count=raw_count,
                parsed_count=parsed_count,
                validated_count=0,
                rejected_count=rejected_count,
                rejection_notices=rejection_notices,
                step_traces=step_traces,
                warnings=warnings,
                errors=errors,
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        # 5. STEP 3: Tool deduplicate_findings
        dedup_action = AgentAction(
            action_type=AgentStepActionType.CALL_TOOL,
            tool_name="deduplicate_findings",
            rationale=f"Deduplicate {validated_count} validated findings based on (asset_id, cve_id, affected_package)",
        )
        try:
            dedup_input = DeduplicateFindingsInput(findings=validated_findings)
            dedup_output = self._registry.invoke("deduplicate_findings", dedup_input)
            if not isinstance(dedup_output, DeduplicateFindingsOutput):
                raise TypeError(
                    f"Expected DeduplicateFindingsOutput from deduplicate_findings, got {type(dedup_output).__name__}"
                )
        except Exception as err:
            errors.append(
                AgentNotice(
                    code="DEDUPLICATION_TOOL_ERROR",
                    message=f"Tool 'deduplicate_findings' execution failed: {err}",
                    severity=NoticeSeverity.ERROR,
                    step_number=step_counter,
                )
            )
            step_traces.append(
                AgentStepTrace(
                    step_number=step_counter,
                    action=dedup_action,
                    tool_result=None,
                    status=ToolStatus.ERROR,
                    notes=f"Exception during deduplicate_findings: {err}",
                )
            )
            return ScanIntakeResult(
                status=ScanIntakeStatus.FAILED,
                raw_count=raw_count,
                parsed_count=parsed_count,
                validated_count=validated_count,
                rejected_count=rejected_count,
                rejection_notices=rejection_notices,
                step_traces=step_traces,
                warnings=warnings,
                errors=errors,
                scan_id=typed_input.scan_id,
                scanner_name=typed_input.scanner_name,
            )

        step_traces.append(
            AgentStepTrace(
                step_number=step_counter,
                action=dedup_action,
                tool_result=dedup_output,
                status=dedup_output.status,
                notes=f"Identified {dedup_output.unique_count} unique findings and {dedup_output.duplicate_count} duplicates.",
            )
        )
        step_counter += 1

        # Sort clean findings deterministically by finding_id for stable reproducibility
        clean_findings = sorted(dedup_output.unique_findings, key=lambda f: (f.finding_id, f.asset_id, f.cve_id))
        duplicate_count = dedup_output.duplicate_count
        unique_count = len(clean_findings)

        # 6. Determine final status
        if rejected_count > 0 and unique_count > 0:
            final_status = ScanIntakeStatus.PARTIAL_SUCCESS
        elif unique_count > 0:
            final_status = ScanIntakeStatus.SUCCESS
        elif unique_count == 0 and rejected_count > 0:
            final_status = ScanIntakeStatus.FAILED
        else:
            final_status = ScanIntakeStatus.EMPTY_INPUT

        return ScanIntakeResult(
            status=final_status,
            clean_findings=clean_findings,
            raw_count=raw_count,
            parsed_count=parsed_count,
            validated_count=validated_count,
            rejected_count=rejected_count,
            duplicate_count=duplicate_count,
            unique_count=unique_count,
            rejection_notices=rejection_notices,
            duplicate_groups=dedup_output.duplicate_groups,
            step_traces=step_traces,
            errors=errors,
            warnings=warnings,
            scan_id=typed_input.scan_id,
            scanner_name=typed_input.scanner_name,
        )
