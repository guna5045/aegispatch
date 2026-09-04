"""Scan intake, validation, and deduplication tools for Aegis Patch.

All tools in this module operate deterministically with explicit typing and side-effect guarantees.
None of these tools calculate risk, prioritize findings, call LLMs, or invoke external APIs.
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import ValidationError

from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.schemas import (
    DeduplicateFindingsInput,
    DeduplicateFindingsOutput,
    DuplicateFindingGroup,
    ParseRawScanInput,
    ParseRawScanOutput,
    ProvenanceSourceType,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
    ValidateFindingSchemaInput,
    ValidateFindingSchemaOutput,
)


def parse_raw_scan(input_data: ParseRawScanInput) -> ParseRawScanOutput:
    """Convert raw scanner input into normalized vulnerability finding records.

    Accepts raw JSON payloads, single finding dictionaries, or lists of records.
    Normalizes keys and populates VulnerabilityFinding contracts without discarding
    malformed records silently.
    """
    raw = input_data.raw_payload
    errors: List[str] = []
    parsed_findings: List[VulnerabilityFinding] = []

    # 1. Parse JSON string if payload is string
    raw_list: List[Any] = []
    if isinstance(raw, str):
        try:
            loaded = json.loads(raw)
            if isinstance(loaded, list):
                raw_list = loaded
            elif isinstance(loaded, dict):
                raw_list = [loaded]
            else:
                return ParseRawScanOutput(
                    tool_name="parse_raw_scan",
                    status=ToolStatus.INVALID_INPUT,
                    message="Raw JSON payload must be a JSON object or array of objects.",
                    side_effect=SideEffectClass.COMPUTE_ONLY,
                    provenance=ToolProvenance(
                        source=input_data.scanner_name or "scanner_intake",
                        source_type=ProvenanceSourceType.BENCHMARK,
                    ),
                    findings=[],
                    parsed_count=0,
                    error_count=1,
                    errors=["Raw JSON payload was neither a list nor an object"],
                )
        except Exception as err:
            return ParseRawScanOutput(
                tool_name="parse_raw_scan",
                status=ToolStatus.INVALID_INPUT,
                message=f"Failed to parse raw JSON payload: {err}",
                side_effect=SideEffectClass.COMPUTE_ONLY,
                provenance=ToolProvenance(
                    source=input_data.scanner_name or "scanner_intake",
                    source_type=ProvenanceSourceType.BENCHMARK,
                ),
                findings=[],
                parsed_count=0,
                error_count=1,
                errors=[str(err)],
            )
    elif isinstance(raw, dict):
        raw_list = [raw]
    elif isinstance(raw, list):
        raw_list = raw
    else:
        return ParseRawScanOutput(
            tool_name="parse_raw_scan",
            status=ToolStatus.INVALID_INPUT,
            message=f"Unsupported raw_payload type: {type(raw).__name__}",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            provenance=ToolProvenance(
                source=input_data.scanner_name or "scanner_intake",
                source_type=ProvenanceSourceType.BENCHMARK,
            ),
            findings=[],
            parsed_count=0,
            error_count=1,
            errors=[f"Invalid type: {type(raw).__name__}"],
        )

    # 2. Normalize and validate each record
    for idx, item in enumerate(raw_list):
        if not isinstance(item, dict):
            errors.append(f"Record at index {idx} is not a dictionary: {type(item).__name__}")
            continue

        item_dict = dict(item)
        if input_data.target_asset_id and "asset_id" not in item_dict:
            item_dict["asset_id"] = input_data.target_asset_id

        # Normalize common scanner field aliases if present
        if "id" in item_dict and "finding_id" not in item_dict:
            item_dict["finding_id"] = item_dict["id"]
        if "cve" in item_dict and "cve_id" not in item_dict:
            item_dict["cve_id"] = item_dict["cve"]
        if "package" in item_dict and "affected_package" not in item_dict:
            item_dict["affected_package"] = item_dict["package"]
        if "version" in item_dict and "installed_version" not in item_dict:
            item_dict["installed_version"] = item_dict["version"]
        if "description" not in item_dict:
            item_dict["description"] = item_dict.get("title", "No description provided.")
        if "source" not in item_dict:
            item_dict["source"] = input_data.scanner_name or "scanner_intake"

        try:
            finding = VulnerabilityFinding.model_validate(item_dict)
            parsed_findings.append(finding)
        except ValidationError as val_err:
            errors.append(f"Record {item_dict.get('finding_id', f'at index {idx}')} schema violation: {val_err.errors()}")
        except Exception as general_err:
            errors.append(f"Record {item_dict.get('finding_id', f'at index {idx}')} error: {str(general_err)}")

    status = ToolStatus.SUCCESS if len(errors) == 0 else (
        ToolStatus.SUCCESS if parsed_findings else ToolStatus.INVALID_INPUT
    )
    msg = f"Successfully parsed {len(parsed_findings)} findings."
    if errors:
        msg += f" Encountered {len(errors)} validation errors."

    return ParseRawScanOutput(
        tool_name="parse_raw_scan",
        status=status,
        message=msg,
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source=input_data.scanner_name or "scanner_intake",
            source_type=ProvenanceSourceType.BENCHMARK,
        ),
        findings=parsed_findings,
        parsed_count=len(parsed_findings),
        error_count=len(errors),
        errors=errors,
    )


def validate_finding_schema(input_data: ValidateFindingSchemaInput) -> ValidateFindingSchemaOutput:
    """Validate whether a vulnerability finding conforms to the project's finding contract.

    Reuses existing Pydantic VulnerabilityFinding schema directly.
    """
    try:
        finding = VulnerabilityFinding.model_validate(input_data.finding_data)
        return ValidateFindingSchemaOutput(
            tool_name="validate_finding_schema",
            status=ToolStatus.SUCCESS,
            message="Finding conforms to authoritative VulnerabilityFinding schema.",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            provenance=ToolProvenance(
                source="pydantic_contract_validator",
                source_type=ProvenanceSourceType.CALCULATED,
            ),
            is_valid=True,
            validated_finding=finding,
            validation_errors=[],
        )
    except ValidationError as err:
        err_messages = [f"{e.get('loc')}: {e.get('msg')}" for e in err.errors()]
        return ValidateFindingSchemaOutput(
            tool_name="validate_finding_schema",
            status=ToolStatus.INVALID_INPUT,
            message=f"Finding violates contract with {len(err_messages)} validation errors.",
            side_effect=SideEffectClass.COMPUTE_ONLY,
            provenance=ToolProvenance(
                source="pydantic_contract_validator",
                source_type=ProvenanceSourceType.CALCULATED,
            ),
            is_valid=False,
            validated_finding=None,
            validation_errors=err_messages,
        )


def deduplicate_findings(input_data: DeduplicateFindingsInput) -> DeduplicateFindingsOutput:
    """Identify duplicate scanner findings without collapsing findings across distinct assets.

    Deduplication identity key is the tuple: (asset_id, cve_id, affected_package).
    A single CVE across multiple assets is NOT considered a duplicate.
    Analytical only: does not delete source data.
    """
    findings = input_data.findings
    seen_identities: Dict[Tuple[str, str, str], str] = {}
    duplicate_groups_map: Dict[Tuple[str, str, str], List[str]] = {}
    unique_findings: List[VulnerabilityFinding] = []

    for f in findings:
        identity_key = (f.asset_id, f.cve_id, f.affected_package.lower())
        if identity_key in seen_identities:
            # Duplicate found
            if identity_key not in duplicate_groups_map:
                duplicate_groups_map[identity_key] = []
            duplicate_groups_map[identity_key].append(f.finding_id)
        else:
            seen_identities[identity_key] = f.finding_id
            unique_findings.append(f)

    duplicate_groups: List[DuplicateFindingGroup] = []
    total_duplicates = 0
    for key, dup_ids in duplicate_groups_map.items():
        retained = seen_identities[key]
        key_str = f"asset={key[0]}|cve={key[1]}|pkg={key[2]}"
        duplicate_groups.append(
            DuplicateFindingGroup(
                identity_key=key_str,
                retained_finding_id=retained,
                duplicate_finding_ids=dup_ids,
            )
        )
        total_duplicates += len(dup_ids)

    return DeduplicateFindingsOutput(
        tool_name="deduplicate_findings",
        status=ToolStatus.SUCCESS,
        message=f"Evaluated {len(findings)} findings. Identified {len(unique_findings)} unique findings and {total_duplicates} duplicates.",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        provenance=ToolProvenance(
            source="deduplication_engine",
            source_type=ProvenanceSourceType.CALCULATED,
        ),
        unique_findings=unique_findings,
        total_input_count=len(findings),
        unique_count=len(unique_findings),
        duplicate_count=total_duplicates,
        duplicate_groups=duplicate_groups,
    )
