"""Tests for Phase 9A: Scan Intake Specialist Agent.

Comprehensive test coverage validating:
1. Valid scan intake
2. Multiple findings
3. Empty input
4. Malformed input
5. Parser failure
6. Validation rejection
7. Partial success
8. Malformed validation result
9. Duplicate findings
10. Deduplication result
11. Malformed deduplication result
12. Unknown tool
13. Tool exception
14. State isolation
15. Deterministic repeated execution
16. Registry boundary enforcement
17. Security/injection-style scan content
18. Correct counters/statistics
19. Correct final status
20. Trace correctness
"""

import json
from typing import Any, Dict, List
from unittest.mock import MagicMock
import pytest

from src.agents.scan_intake import (
    ScanIntakeAgent,
    ScanIntakeInput,
    ScanIntakeResult,
    ScanIntakeStatus,
)
from src.agents.schemas import AgentStepActionType, NoticeSeverity
from src.services.data_service import load_benchmark_findings
from src.schemas.vulnerability import VulnerabilityFinding
from src.tools.registry import ToolDefinition, ToolRegistry, default_tool_registry
from src.tools.schemas import (
    BaseToolResult,
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


@pytest.fixture
def benchmark_findings() -> Dict[str, VulnerabilityFinding]:
    """Load canonical benchmark findings."""
    return load_benchmark_findings()


@pytest.fixture
def agent() -> ScanIntakeAgent:
    """Instantiate fresh ScanIntakeAgent with default registry."""
    return ScanIntakeAgent()


# 1. Valid Scan Intake
def test_1_valid_scan_intake(agent: ScanIntakeAgent):
    raw = {
        "finding_id": "FINDING-901",
        "cve_id": "CVE-2023-38545",
        "title": "curl SOCKS5 heap overflow",
        "description": "Buffer overflow in SOCKS5 proxy handshake.",
        "cvss_score": 9.8,
        "severity": "CRITICAL",
        "affected_package": "libcurl4",
        "installed_version": "7.88.1-10",
        "asset_id": "ASSET-001",
    }
    res = agent.run(raw_payload=raw, scanner_name="qualys", scan_id="SCAN-001")

    assert res.status == ScanIntakeStatus.SUCCESS
    assert res.raw_count == 1
    assert res.parsed_count == 1
    assert res.validated_count == 1
    assert res.unique_count == 1
    assert res.duplicate_count == 0
    assert res.rejected_count == 0
    assert len(res.clean_findings) == 1
    assert res.clean_findings[0].finding_id == "FINDING-901"
    assert res.scan_id == "SCAN-001"
    assert res.scanner_name == "qualys"


# 2. Multiple Findings
def test_2_multiple_findings(agent: ScanIntakeAgent):
    raw_list = [
        {
            "finding_id": f"FINDING-BATCH-{i}",
            "cve_id": f"CVE-2023-{1000 + i}",
            "title": f"Vulnerability {i}",
            "description": f"Detailed description {i}",
            "cvss_score": 7.0 + (i * 0.5),
            "severity": "HIGH",
            "affected_package": f"pkg-{i}",
            "installed_version": "1.0.0",
            "asset_id": "ASSET-001",
        }
        for i in range(5)
    ]
    res = agent.run(raw_payload=raw_list, scanner_name="trivy")

    assert res.status == ScanIntakeStatus.SUCCESS
    assert res.raw_count == 5
    assert res.parsed_count == 5
    assert res.validated_count == 5
    assert res.unique_count == 5
    assert res.rejected_count == 0
    assert len(res.clean_findings) == 5


# 3. Empty Input
@pytest.mark.parametrize("empty_payload", [None, "", "   ", [], {}])
def test_3_empty_input(agent: ScanIntakeAgent, empty_payload: Any):
    res = agent.run(raw_payload=empty_payload)
    assert res.status == ScanIntakeStatus.EMPTY_INPUT
    assert res.unique_count == 0
    assert len(res.clean_findings) == 0
    assert any(w.code == "EMPTY_PAYLOAD" for w in res.warnings)


# 4. Malformed Input (Unparseable JSON string)
def test_4_malformed_input(agent: ScanIntakeAgent):
    malformed_json = '{"finding_id": "F1", "unclosed: true'
    res = agent.run(raw_payload=malformed_json)

    assert res.status == ScanIntakeStatus.INVALID_INPUT
    assert res.raw_count == 1
    assert res.parsed_count == 0
    assert res.unique_count == 0
    assert res.rejected_count == 1
    assert len(res.rejection_notices) >= 1
    assert any(e.code == "PARSER_FAILURE" for e in res.errors)


# 5. Parser Failure (Non-dict records or invalid types)
def test_5_parser_failure(agent: ScanIntakeAgent):
    # Payload is integer, unsupported by parser
    res = agent.run(raw_payload=12345)  # type: ignore[arg-type]

    assert res.status == ScanIntakeStatus.INVALID_INPUT
    assert res.parsed_count == 0
    assert res.unique_count == 0
    assert len(res.rejection_notices) >= 1


# 6. Validation Rejection (Missing mandatory fields)
def test_6_validation_rejection(agent: ScanIntakeAgent):
    invalid_records = [
        {
            "finding_id": "BAD-01",
            "cve_id": "CVE-2023-1111",
            # missing cvss_score, severity, asset_id, affected_package
        }
    ]
    res = agent.run(raw_payload=invalid_records)

    assert res.status == ScanIntakeStatus.FAILED
    assert res.raw_count == 1
    assert res.parsed_count == 0
    assert res.rejected_count == 1
    assert res.unique_count == 0
    assert len(res.rejection_notices) == 1


# 7. Partial Success (Mixed valid and invalid records)
def test_7_partial_success(agent: ScanIntakeAgent):
    mixed_records = [
        {
            "finding_id": "GOOD-01",
            "cve_id": "CVE-2023-0001",
            "title": "Valid vulnerability",
            "description": "Clean description",
            "cvss_score": 8.0,
            "severity": "HIGH",
            "affected_package": "openssl",
            "installed_version": "1.1.1",
            "asset_id": "ASSET-001",
        },
        {
            "finding_id": "BAD-RECORD",
            "asset_id": "ASSET-001",
            # missing required fields
        },
    ]
    res = agent.run(raw_payload=mixed_records)

    assert res.status == ScanIntakeStatus.PARTIAL_SUCCESS
    assert res.raw_count == 2
    assert res.parsed_count == 1
    assert res.validated_count == 1
    assert res.rejected_count == 1
    assert res.unique_count == 1
    assert len(res.clean_findings) == 1
    assert len(res.rejection_notices) == 1


# 8. Malformed Validation Result (Corrupted registry return)
def test_8_malformed_validation_result():
    bad_registry = ToolRegistry()
    # Register genuine parse_raw_scan
    bad_registry.register(default_tool_registry.get("parse_raw_scan"))

    # Register rogue validate_finding_schema returning unexpected object
    rogue_tool = ToolDefinition(
        name="validate_finding_schema",
        description="Corrupted tool",
        category="SCAN",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        input_schema=ValidateFindingSchemaInput,
        output_schema=ValidateFindingSchemaOutput,
        handler=lambda inp: "NOT_AN_OUTPUT_OBJECT",  # type: ignore[return-value]
    )
    bad_registry.register(rogue_tool)
    bad_registry.register(default_tool_registry.get("deduplicate_findings"))

    rogue_agent = ScanIntakeAgent(registry=bad_registry)
    valid_record = {
        "finding_id": "F-01",
        "cve_id": "CVE-2023-0001",
        "title": "Title",
        "description": "Desc",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    res = rogue_agent.run(raw_payload=[valid_record])

    # Caught gracefully, marked as failure
    assert res.status == ScanIntakeStatus.FAILED
    assert any(e.code == "VALIDATION_TOOL_ERROR" for e in res.errors)


# 9. Duplicate Findings Identification
def test_9_duplicate_findings_deduplication(agent: ScanIntakeAgent):
    # Two findings with same (asset_id, cve_id, affected_package)
    dups = [
        {
            "finding_id": "FINDING-DUP-1",
            "cve_id": "CVE-2023-38545",
            "title": "Curl issue 1",
            "description": "Reported by scanner 1",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_package": "libcurl4",
            "installed_version": "7.88.1-10",
            "asset_id": "ASSET-001",
        },
        {
            "finding_id": "FINDING-DUP-2",
            "cve_id": "CVE-2023-38545",
            "title": "Curl issue 2",
            "description": "Reported by scanner 2 duplicate",
            "cvss_score": 9.8,
            "severity": "CRITICAL",
            "affected_package": "libcurl4",
            "installed_version": "7.88.1-10",
            "asset_id": "ASSET-001",
        },
    ]
    res = agent.run(raw_payload=dups)

    assert res.status == ScanIntakeStatus.SUCCESS
    assert res.raw_count == 2
    assert res.parsed_count == 2
    assert res.validated_count == 2
    assert res.duplicate_count == 1
    assert res.unique_count == 1
    assert len(res.clean_findings) == 1
    assert res.clean_findings[0].finding_id == "FINDING-DUP-1"


# 10. Deduplication Result & Group Mapping
def test_10_deduplication_result_groups(agent: ScanIntakeAgent):
    dups = [
        {
            "finding_id": "F-ORIGINAL",
            "cve_id": "CVE-2024-1111",
            "title": "Vulnerability A",
            "description": "Original",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "affected_package": "openssh",
            "installed_version": "8.9",
            "asset_id": "ASSET-002",
        },
        {
            "finding_id": "F-DUPLICATE",
            "cve_id": "CVE-2024-1111",
            "title": "Vulnerability A dup",
            "description": "Duplicate",
            "cvss_score": 7.5,
            "severity": "HIGH",
            "affected_package": "openssh",
            "installed_version": "8.9",
            "asset_id": "ASSET-002",
        },
    ]
    res = agent.run(raw_payload=dups)

    assert len(res.duplicate_groups) == 1
    group = res.duplicate_groups[0]
    assert group.retained_finding_id == "F-ORIGINAL"
    assert "F-DUPLICATE" in group.duplicate_finding_ids
    assert "asset=ASSET-002|cve=CVE-2024-1111|pkg=openssh" in group.identity_key


# 11. Malformed Deduplication Result
def test_11_malformed_deduplication_result():
    bad_registry = ToolRegistry()
    bad_registry.register(default_tool_registry.get("parse_raw_scan"))
    bad_registry.register(default_tool_registry.get("validate_finding_schema"))

    rogue_tool = ToolDefinition(
        name="deduplicate_findings",
        description="Corrupted dedup tool",
        category="SCAN",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        input_schema=DeduplicateFindingsInput,
        output_schema=DeduplicateFindingsOutput,
        handler=lambda inp: "CORRUPTED_DEDUP_OUTPUT",  # type: ignore[return-value]
    )
    bad_registry.register(rogue_tool)

    rogue_agent = ScanIntakeAgent(registry=bad_registry)
    valid_record = {
        "finding_id": "F-01",
        "cve_id": "CVE-2023-0001",
        "title": "Title",
        "description": "Desc",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    res = rogue_agent.run(raw_payload=[valid_record])

    assert res.status == ScanIntakeStatus.FAILED
    assert any(e.code == "DEDUPLICATION_TOOL_ERROR" for e in res.errors)


# 12. Unknown Tool Handling
def test_12_unknown_tool_handling():
    # Empty registry missing required tools
    empty_registry = ToolRegistry()
    agent_missing_tools = ScanIntakeAgent(registry=empty_registry)

    valid_record = {
        "finding_id": "F-01",
        "cve_id": "CVE-2023-0001",
        "title": "Title",
        "description": "Desc",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    res = agent_missing_tools.run(raw_payload=[valid_record])

    assert res.status == ScanIntakeStatus.FAILED
    assert any(e.code == "PARSE_TOOL_ERROR" for e in res.errors)
    assert any("No tool registered under name 'parse_raw_scan'" in e.message for e in res.errors)


# 13. Tool Exception Handling
def test_13_tool_exception_handling():
    failing_registry = ToolRegistry()

    def exploding_parser(inp):
        raise RuntimeError("Catastrophic parser crash!")

    failing_tool = ToolDefinition(
        name="parse_raw_scan",
        description="Failing tool",
        category="SCAN",
        side_effect=SideEffectClass.COMPUTE_ONLY,
        input_schema=ParseRawScanInput,
        output_schema=ParseRawScanOutput,
        handler=exploding_parser,
    )
    failing_registry.register(failing_tool)
    failing_agent = ScanIntakeAgent(registry=failing_registry)

    res = failing_agent.run(raw_payload=[{"test": "val"}])

    assert res.status == ScanIntakeStatus.FAILED
    assert any(e.code == "PARSE_TOOL_ERROR" for e in res.errors)
    assert any("Catastrophic parser crash!" in e.message for e in res.errors)


# 14. State Isolation Across Instances and Invocations
def test_14_state_isolation(agent: ScanIntakeAgent):
    agent_a = ScanIntakeAgent()
    agent_b = ScanIntakeAgent()

    rec_a = {
        "finding_id": "F-AAA",
        "cve_id": "CVE-2023-0001",
        "title": "Title A",
        "description": "Desc A",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg_a",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    rec_b = {
        "finding_id": "F-BBB",
        "cve_id": "CVE-2023-0002",
        "title": "Title B",
        "description": "Desc B",
        "cvss_score": 6.0,
        "severity": "MEDIUM",
        "affected_package": "pkg_b",
        "installed_version": "2.0",
        "asset_id": "ASSET-002",
    }

    res_a = agent_a.run(raw_payload=[rec_a])
    res_b = agent_b.run(raw_payload=[rec_b])

    assert len(res_a.clean_findings) == 1
    assert res_a.clean_findings[0].finding_id == "F-AAA"

    assert len(res_b.clean_findings) == 1
    assert res_b.clean_findings[0].finding_id == "F-BBB"

    # Sequential execution on same instance is also completely isolated
    res_a_2 = agent_a.run(raw_payload=[rec_b])
    assert len(res_a_2.clean_findings) == 1
    assert res_a_2.clean_findings[0].finding_id == "F-BBB"


# 15. Deterministic Repeated Execution
def test_15_deterministic_repeated_execution(agent: ScanIntakeAgent):
    records = [
        {
            "finding_id": "F-Z",
            "cve_id": "CVE-2023-9999",
            "title": "Title Z",
            "description": "Desc Z",
            "cvss_score": 9.0,
            "severity": "CRITICAL",
            "affected_package": "pkg_z",
            "installed_version": "1.0",
            "asset_id": "ASSET-001",
        },
        {
            "finding_id": "F-A",
            "cve_id": "CVE-2023-1111",
            "title": "Title A",
            "description": "Desc A",
            "cvss_score": 7.0,
            "severity": "HIGH",
            "affected_package": "pkg_a",
            "installed_version": "1.0",
            "asset_id": "ASSET-001",
        },
    ]

    res1 = agent.run(raw_payload=records)
    res2 = agent.run(raw_payload=records)

    assert [f.finding_id for f in res1.clean_findings] == [f.finding_id for f in res2.clean_findings]
    assert [f.finding_id for f in res1.clean_findings] == ["F-A", "F-Z"]  # Deterministically sorted
    assert res1.unique_count == res2.unique_count
    assert res1.duplicate_count == res2.duplicate_count
    assert len(res1.step_traces) == len(res2.step_traces)


# 16. Registry Boundary Enforcement
def test_16_registry_boundary_enforcement():
    spy_registry = MagicMock(wraps=default_tool_registry)
    spy_agent = ScanIntakeAgent(registry=spy_registry)

    rec = {
        "finding_id": "F-SPY",
        "cve_id": "CVE-2023-0001",
        "title": "Spy Title",
        "description": "Spy Desc",
        "cvss_score": 6.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    res = spy_agent.run(raw_payload=[rec])

    assert res.status == ScanIntakeStatus.SUCCESS
    # Verify registry.invoke was called for parse, validate, and deduplicate
    assert spy_registry.invoke.call_count == 3
    invoked_tools = [call[0][0] for call in spy_registry.invoke.call_args_list]
    assert invoked_tools == ["parse_raw_scan", "validate_finding_schema", "deduplicate_findings"]


# 17. Security / Injection-Style Scan Content Safety
def test_17_security_injection_scan_content(agent: ScanIntakeAgent):
    malicious_inputs = [
        {
            "finding_id": "DROP TABLE findings; --",
            "cve_id": "CVE-2023-0001",
            "title": "<script>alert('xss')</script>",
            "description": "__import__('os').system('echo pwned; rm -rf /')",
            "cvss_score": 9.9,
            "severity": "CRITICAL",
            "affected_package": "bash`whoami`",
            "installed_version": "1.0",
            "asset_id": "ASSET-'; DROP DATABASE;--",
            "raw_evidence": {"exploit": "'; DROP TABLE users; --"},
        }
    ]
    res = agent.run(raw_payload=malicious_inputs)

    assert res.status == ScanIntakeStatus.SUCCESS
    assert len(res.clean_findings) == 1
    safe_finding = res.clean_findings[0]
    # Injections remain safe passive strings
    assert safe_finding.finding_id == "DROP TABLE findings; --"
    assert safe_finding.cve_id == "CVE-2023-0001"
    assert "<script>" in safe_finding.title
    assert "__import__" in safe_finding.description
    assert safe_finding.asset_id == "ASSET-'; DROP DATABASE;--"
    assert safe_finding.affected_package == "bash`whoami`"



# 18. Correct Counters and Statistics
def test_18_accurate_counters(agent: ScanIntakeAgent):
    records = [
        # Valid item 1
        {
            "finding_id": "F-01",
            "cve_id": "CVE-2023-0001",
            "title": "T1",
            "description": "D1",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "affected_package": "pkg1",
            "installed_version": "1.0",
            "asset_id": "ASSET-001",
        },
        # Valid item 2 (duplicate of item 1)
        {
            "finding_id": "F-02",
            "cve_id": "CVE-2023-0001",
            "title": "T2",
            "description": "D2",
            "cvss_score": 5.0,
            "severity": "MEDIUM",
            "affected_package": "pkg1",
            "installed_version": "1.0",
            "asset_id": "ASSET-001",
        },
        # Valid item 3 (unique)
        {
            "finding_id": "F-03",
            "cve_id": "CVE-2023-0002",
            "title": "T3",
            "description": "D3",
            "cvss_score": 7.0,
            "severity": "HIGH",
            "affected_package": "pkg2",
            "installed_version": "1.0",
            "asset_id": "ASSET-001",
        },
        # Invalid item 4
        {
            "finding_id": "F-INVALID",
            "asset_id": "ASSET-001",
        },
    ]

    res = agent.run(raw_payload=records)

    assert res.status == ScanIntakeStatus.PARTIAL_SUCCESS
    assert res.raw_count == 4
    assert res.parsed_count == 3
    assert res.validated_count == 3
    assert res.rejected_count == 1
    assert res.duplicate_count == 1
    assert res.unique_count == 2
    assert len(res.clean_findings) == 2


# 19. Correct Final Status Assignment
def test_19_final_status_contract():
    agent = ScanIntakeAgent()

    # Empty
    assert agent.run(raw_payload=[]).status == ScanIntakeStatus.EMPTY_INPUT

    # Malformed
    assert agent.run(raw_payload="{bad_json").status == ScanIntakeStatus.INVALID_INPUT

    # All invalid
    assert agent.run(raw_payload=[{"bad": "val"}]).status == ScanIntakeStatus.FAILED

    # Full success
    good = {
        "finding_id": "F-OK",
        "cve_id": "CVE-2023-0001",
        "title": "T",
        "description": "D",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    assert agent.run(raw_payload=[good]).status == ScanIntakeStatus.SUCCESS


# 20. Trace Correctness and Auditability
def test_20_trace_correctness(agent: ScanIntakeAgent):
    record = {
        "finding_id": "F-TRACE",
        "cve_id": "CVE-2023-0001",
        "title": "Title",
        "description": "Desc",
        "cvss_score": 5.0,
        "severity": "MEDIUM",
        "affected_package": "pkg",
        "installed_version": "1.0",
        "asset_id": "ASSET-001",
    }
    res = agent.run(raw_payload=[record])

    assert len(res.step_traces) == 3
    # Step 1: parse_raw_scan
    assert res.step_traces[0].step_number == 1
    assert res.step_traces[0].action.action_type == AgentStepActionType.CALL_TOOL
    assert res.step_traces[0].action.tool_name == "parse_raw_scan"
    assert res.step_traces[0].status == ToolStatus.SUCCESS

    # Step 2: validate_finding_schema
    assert res.step_traces[1].step_number == 2
    assert res.step_traces[1].action.action_type == AgentStepActionType.CALL_TOOL
    assert res.step_traces[1].action.tool_name == "validate_finding_schema"
    assert res.step_traces[1].status == ToolStatus.SUCCESS

    # Step 3: deduplicate_findings
    assert res.step_traces[2].step_number == 3
    assert res.step_traces[2].action.action_type == AgentStepActionType.CALL_TOOL
    assert res.step_traces[2].action.tool_name == "deduplicate_findings"
    assert res.step_traces[2].status == ToolStatus.SUCCESS


# 21. Real Benchmark Findings Integration Test
def test_21_benchmark_findings_integration(agent: ScanIntakeAgent, benchmark_findings: Dict[str, VulnerabilityFinding]):
    # Ingest actual benchmark findings as raw dicts
    sample_findings = [benchmark_findings["FINDING-001"].model_dump(), benchmark_findings["FINDING-002"].model_dump()]
    res = agent.run(raw_payload=sample_findings, scanner_name="benchmark_importer")

    assert res.status == ScanIntakeStatus.SUCCESS
    assert res.raw_count == 2
    assert res.parsed_count == 2
    assert res.validated_count == 2
    assert res.unique_count == 2
    assert res.duplicate_count == 0
    assert len(res.clean_findings) == 2
    finding_ids = [f.finding_id for f in res.clean_findings]
    assert "FINDING-001" in finding_ids
    assert "FINDING-002" in finding_ids
