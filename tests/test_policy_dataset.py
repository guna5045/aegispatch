"""Automated tests validating the synthetic organizational policy corpus."""

from pathlib import Path
import pytest
from src.schemas import (
    BusinessTier,
    DataSensitivity,
    EnvironmentType,
    NetworkExposure,
    RemediationDecision,
)

POLICY_FILES = [
    "data/policies/POL-SEC-04-patching.md",
    "data/policies/POL-IT-09-criticality.md",
    "data/policies/POL-SEC-12-exceptions.md",
]


@pytest.fixture
def policy_corpus():
    """Load and return all three policy documents as text."""
    corpus = {}
    for rel_path in POLICY_FILES:
        path = Path(rel_path)
        assert path.exists(), f"Policy file missing: {rel_path}"
        content = path.read_text(encoding="utf-8")
        assert len(content.strip()) > 100, f"Policy file {rel_path} is unexpectedly small or empty"
        corpus[path.name] = content
    return corpus


def test_all_policy_files_exist_and_utf8():
    """Verify all 3 policy files exist and can be read as valid UTF-8."""
    for rel_path in POLICY_FILES:
        p = Path(rel_path)
        assert p.is_file()
        content = p.read_text(encoding="utf-8")
        assert len(content) > 0


def test_policy_identifiers_and_synthetic_label(policy_corpus):
    """Verify expected identifiers and explicit synthetic disclaimer."""
    expected_ids = {
        "POL-SEC-04-patching.md": "POL-SEC-04",
        "POL-IT-09-criticality.md": "POL-IT-09",
        "POL-SEC-12-exceptions.md": "POL-SEC-12",
    }
    for filename, expected_id in expected_ids.items():
        text = policy_corpus[filename]
        assert expected_id in text, f"Expected ID {expected_id} in {filename}"
        assert "Synthetic Organizational Policy — AegisPatch Benchmark" in text, (
            f"Missing synthetic benchmark disclaimer in {filename}"
        )


def test_numbered_clauses_present(policy_corpus):
    """Verify standard numbered clause format (§) is used for RAG citations."""
    for filename, text in policy_corpus.items():
        assert "§" in text, f"Missing section symbol (§) for structured clause numbering in {filename}"
        assert "1.0 Purpose" in text or "1.0 Purpose and Scope" in text, f"Missing Section 1 in {filename}"
        assert "2.0" in text, f"Missing Section 2 in {filename}"


def test_criticality_categories_in_pol_it_09(policy_corpus):
    """Verify POL-IT-09 contains all BusinessTier, NetworkExposure, and DataSensitivity enums."""
    text = policy_corpus["POL-IT-09-criticality.md"]

    for tier in BusinessTier:
        assert tier.value in text, f"BusinessTier {tier.value} missing from POL-IT-09"

    for exposure in NetworkExposure:
        assert exposure.value in text, f"NetworkExposure {exposure.value} missing from POL-IT-09"

    for sensitivity in DataSensitivity:
        assert sensitivity.value in text, f"DataSensitivity {sensitivity.value} missing from POL-IT-09"

    for env in EnvironmentType:
        assert env.value in text, f"EnvironmentType {env.value} missing from POL-IT-09"


def test_remediation_expectations_in_pol_sec_04(policy_corpus):
    """Verify POL-SEC-04 defines remediation timelines for critical, high, medium, and low."""
    text = policy_corpus["POL-SEC-04-patching.md"]
    assert "48 hours" in text
    assert "7 calendar days" in text
    assert "30 calendar days" in text
    assert "90 calendar days" in text
    assert "CISA Known Exploited Vulnerabilities" in text or "CISA KEV" in text
    assert "RollbackPlan" in text


def test_mitigate_vs_accept_risk_distinction_in_pol_sec_12(policy_corpus):
    """Verify POL-SEC-12 explicitly defines and distinguishes MITIGATE and ACCEPT_RISK."""
    text = policy_corpus["POL-SEC-12-exceptions.md"]
    assert RemediationDecision.MITIGATE.value in text
    assert RemediationDecision.ACCEPT_RISK.value in text

    # Verify specific controls represented in CMDB are defined
    assert "CTL-WAF-01" in text
    assert "CTL-EDR-01" in text
    assert "CTL-AIR-01" in text
    assert "CTL-NET-01" in text
    assert "CTL-SAND-01" in text


def test_zero_accidental_secrets(policy_corpus):
    """Verify policies contain no API keys, private keys, or passwords."""
    forbidden_tokens = [
        "BEGIN PRIVATE KEY",
        "BEGIN RSA",
        "aws_secret_access_key",
        "password =",
        "bearer ",
        "sk-ant-",
        "gsk_",
    ]
    for filename, text in policy_corpus.items():
        for token in forbidden_tokens:
            assert token.lower() not in text.lower(), f"Potential secret token '{token}' in {filename}"
