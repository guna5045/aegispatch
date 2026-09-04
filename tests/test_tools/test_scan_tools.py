"""Tests for Phase 7 scan tools: parse_raw_scan, validate_finding_schema, and deduplicate_findings."""

import json
from src.schemas.vulnerability import VulnerabilityFinding, VulnerabilitySeverity
from src.tools.scan_tools import (
    deduplicate_findings,
    parse_raw_scan,
    validate_finding_schema,
)
from src.tools.schemas import (
    DeduplicateFindingsInput,
    ParseRawScanInput,
    SideEffectClass,
    ToolStatus,
    ValidateFindingSchemaInput,
)


def test_parse_raw_scan_single_dict():
    raw = {
        "finding_id": "FINDING-001",
        "cve_id": "CVE-2023-38545",
        "title": "curl SOCKS5 overflow",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_package": "libcurl4",
        "installed_version": "7.88.1-10",
        "asset_id": "ASSET-001",
    }
    inp = ParseRawScanInput(raw_payload=raw)
    out = parse_raw_scan(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.COMPUTE_ONLY
    assert out.parsed_count == 1
    assert out.error_count == 0
    assert len(out.findings) == 1
    assert out.findings[0].cve_id == "CVE-2023-38545"


def test_parse_raw_scan_json_string():
    raw_str = json.dumps([
        {
            "finding_id": "FINDING-002",
            "cve_id": "CVE-2023-44487",
            "title": "HTTP/2 Rapid Reset",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "affected_package": "nghttp2",
            "installed_version": "1.52.0-1",
            "asset_id": "ASSET-001",
        }
    ])
    inp = ParseRawScanInput(raw_payload=raw_str, scanner_name="trivy")
    out = parse_raw_scan(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.parsed_count == 1
    assert out.findings[0].finding_id == "FINDING-002"
    assert out.provenance.source == "trivy"


def test_parse_raw_scan_invalid_json():
    inp = ParseRawScanInput(raw_payload="INVALID_JSON{")
    out = parse_raw_scan(inp)

    assert out.status == ToolStatus.INVALID_INPUT
    assert out.parsed_count == 0
    assert out.error_count == 1
    assert len(out.errors) == 1


def test_parse_raw_scan_malformed_records():
    raw = [
        {"finding_id": "F1"},  # Missing required fields
        "not-a-dict",
    ]
    inp = ParseRawScanInput(raw_payload=raw)
    out = parse_raw_scan(inp)

    assert out.status == ToolStatus.INVALID_INPUT
    assert out.parsed_count == 0
    assert out.error_count == 2
    assert len(out.errors) == 2


def test_validate_finding_schema_valid():
    valid_data = {
        "finding_id": "FINDING-010",
        "cve_id": "CVE-2024-3094",
        "title": "xz backdoor",
        "description": "Malicious code in upstream xz tarballs.",
        "cvss_score": 10.0,
        "severity": "CRITICAL",
        "affected_package": "xz-utils",
        "installed_version": "5.6.0",
        "asset_id": "ASSET-002",
        "source": "synthetic_benchmark",
    }
    inp = ValidateFindingSchemaInput(finding_data=valid_data)
    out = validate_finding_schema(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.is_valid is True
    assert out.validated_finding is not None
    assert out.validated_finding.cve_id == "CVE-2024-3094"
    assert len(out.validation_errors) == 0


def test_validate_finding_schema_invalid():
    invalid_data = {
        "finding_id": "F-01",
        "cve_id": "INVALID-CVE",
        "cvss_score": 15.0,  # Invalid CVSS > 10
    }
    inp = ValidateFindingSchemaInput(finding_data=invalid_data)
    out = validate_finding_schema(inp)

    assert out.status == ToolStatus.INVALID_INPUT
    assert out.is_valid is False
    assert out.validated_finding is None
    assert len(out.validation_errors) > 0


def test_deduplicate_findings_same_asset_same_cve_package():
    f1 = VulnerabilityFinding(
        finding_id="F1",
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
    f2 = VulnerabilityFinding(
        finding_id="F2",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow duplicate",
        description="Heap overflow in SOCKS5 proxy handshake duplicate.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-001",
        source="synthetic_benchmark",
    )
    inp = DeduplicateFindingsInput(findings=[f1, f2])
    out = deduplicate_findings(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.total_input_count == 2
    assert out.unique_count == 1
    assert out.duplicate_count == 1
    assert len(out.duplicate_groups) == 1
    assert out.duplicate_groups[0].retained_finding_id == "F1"
    assert out.duplicate_groups[0].duplicate_finding_ids == ["F2"]


def test_deduplicate_findings_different_assets_not_collapsed():
    """Verify deduplication does NOT collapse findings across different assets."""
    f1 = VulnerabilityFinding(
        finding_id="F1",
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
    f2 = VulnerabilityFinding(
        finding_id="F2",
        cve_id="CVE-2023-38545",
        title="curl SOCKS5 overflow on another asset",
        description="Heap overflow in SOCKS5 proxy handshake on another asset.",
        cvss_score=9.8,
        severity=VulnerabilitySeverity.CRITICAL,
        affected_package="libcurl4",
        installed_version="7.88.1-10",
        asset_id="ASSET-002",
        source="synthetic_benchmark",
    )
    inp = DeduplicateFindingsInput(findings=[f1, f2])
    out = deduplicate_findings(inp)

    assert out.status == ToolStatus.SUCCESS
    assert out.total_input_count == 2
    assert out.unique_count == 2
    assert out.duplicate_count == 0
    assert len(out.unique_findings) == 2
