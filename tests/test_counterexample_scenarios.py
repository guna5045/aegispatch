"""Validation tests for AegisPatch Phase 3E: Counterexample Scenario Validation.

Evaluates the five benchmark scenarios defined in data/synthetic/benchmark_scenarios.json
against the actual Phase 2 datasets using the Phase 3 deterministic risk engine.
"""

from datetime import datetime, timezone
import json
from pathlib import Path
from typing import Dict
import pytest
from src.schemas import Asset, RiskAssessment, ThreatEvidence, VulnerabilityFinding
from src.tools import evaluate_risk

DATA_DIR = Path(__file__).resolve().parent.parent / "data" / "synthetic"
SCENARIOS_PATH = DATA_DIR / "benchmark_scenarios.json"
SCANS_PATH = DATA_DIR / "benchmark_60_scans.json"
CMDB_PATH = DATA_DIR / "enterprise_cmdb.json"


@pytest.fixture(scope="module")
def benchmark_scenarios() -> Dict[str, dict]:
    with open(SCENARIOS_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)
    return {item["scenario_id"]: item for item in items}


@pytest.fixture(scope="module")
def benchmark_findings() -> Dict[str, VulnerabilityFinding]:
    with open(SCANS_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)
    return {item["finding_id"]: VulnerabilityFinding(**item) for item in items}


@pytest.fixture(scope="module")
def benchmark_assets() -> Dict[str, Asset]:
    with open(CMDB_PATH, "r", encoding="utf-8") as f:
        items = json.load(f)
    return {item["asset_id"]: Asset(**item) for item in items}


# ==============================================================================
# 0. Benchmark Integrity & Reference Verification
# ==============================================================================


def test_scenario_metadata_integrity(benchmark_scenarios, benchmark_findings, benchmark_assets):
    """Verify that all scenarios A–E exist and their referenced findings and assets are valid."""
    expected_scenarios = {"SCENARIO-A", "SCENARIO-B", "SCENARIO-C", "SCENARIO-D", "SCENARIO-E"}
    assert set(benchmark_scenarios.keys()) == expected_scenarios

    for scenario_id, scenario in benchmark_scenarios.items():
        # Verify findings
        for fid in scenario["finding_ids"]:
            assert fid in benchmark_findings, f"Finding '{fid}' in {scenario_id} not in benchmark_60_scans.json"
            finding = benchmark_findings[fid]
            assert finding.asset_id in benchmark_assets, f"Asset '{finding.asset_id}' for finding '{fid}' not in CMDB"

        # Verify assets
        for aid in scenario["asset_ids"]:
            assert aid in benchmark_assets, f"Asset '{aid}' in {scenario_id} not in enterprise_cmdb.json"


# ==============================================================================
# SCENARIO A: Exposure and Criticality Inversion
# ==============================================================================


def test_scenario_a_exposure_and_criticality_inversion(benchmark_findings, benchmark_assets):
    """Scenario A: Contextual elevation of CVSS 7.5 finding over CVSS 10.0 finding.

    - FINDING-059 on ASSET-018: CVSS 10.0, AIR_GAPPED, TESTING, LOW criticality, PUBLIC data.
    - FINDING-006 on ASSET-002: CVSS 7.5, INTERNET_FACING, PRODUCTION, CRITICAL criticality, RESTRICTED data.
    """
    f_isolated = benchmark_findings["FINDING-059"]
    a_isolated = benchmark_assets["ASSET-018"]
    res_isolated = evaluate_risk(f_isolated, a_isolated)

    f_exposed = benchmark_findings["FINDING-006"]
    a_exposed = benchmark_assets["ASSET-002"]
    res_exposed = evaluate_risk(f_exposed, a_exposed)

    # 1. Base CVSS relationship
    assert f_isolated.cvss_score == 10.0
    assert f_exposed.cvss_score == 7.5
    assert f_isolated.cvss_score > f_exposed.cvss_score

    # 2. Environmental factor inversion
    assert float(res_exposed.calculation_metadata["environmental_score"]) == 100.0
    assert float(res_isolated.calculation_metadata["environmental_score"]) == 17.5
    assert float(res_exposed.calculation_metadata["environmental_score"]) > float(
        res_isolated.calculation_metadata["environmental_score"]
    )

    # 3. Final ERS inversion
    # Exposed mission-critical asset (ERS 43.00) > isolated air-gapped testbed (ERS 28.01)
    assert res_exposed.environmental_risk_score > res_isolated.environmental_risk_score, (
        f"Expected FINDING-006 ERS ({res_exposed.environmental_risk_score}) > "
        f"FINDING-059 ERS ({res_isolated.environmental_risk_score})"
    )

    # 4. Decision band divergence
    assert res_exposed.calculation_metadata["aegis_decision"] == "PLAN"
    assert res_isolated.calculation_metadata["aegis_decision"] == "TRACK"
    assert res_exposed.risk_tier == "MEDIUM"
    assert res_isolated.risk_tier == "LOW"


# ==============================================================================
# SCENARIO B: Threat Intelligence Exploitation Differential
# ==============================================================================


def test_scenario_b_threat_evidence_handling(benchmark_findings, benchmark_assets):
    """Scenario B: Real-world threat intelligence differential evaluation.

    - FINDING-018 (CVE-2023-36884, CVSS 8.8) on ASSET-004.
    - FINDING-007 (CVE-2023-4911, CVSS 7.8) on ASSET-002.

    Validates:
    1. Benchmark scan records do NOT contain fabricated threat intelligence.
    2. Without threat evidence, both default threat score T = 0.0.
    3. When supplied with valid threat signals, the risk engine adjusts ERS accordingly.
    """
    f_18 = benchmark_findings["FINDING-018"]
    a_04 = benchmark_assets["ASSET-004"]
    res_18_no_threat = evaluate_risk(f_18, a_04, threat=None)

    f_07 = benchmark_findings["FINDING-007"]
    a_02 = benchmark_assets["ASSET-002"]
    res_07_no_threat = evaluate_risk(f_07, a_02, threat=None)

    # Without threat feeds, threat scores default to 0.0
    assert float(res_18_no_threat.calculation_metadata["threat_score"]) == 0.0
    assert float(res_07_no_threat.calculation_metadata["threat_score"]) == 0.0
    assert res_18_no_threat.calculation_metadata["epss_available"] == "false"
    assert res_07_no_threat.calculation_metadata["epss_available"] == "false"

    # Base scan ERS without threat signals:
    # FINDING-018: Base 88.0, Env 82.0, M_ctrl 0.95 -> ERS 48.16
    # FINDING-007: Base 78.0, Env 100.0, M_ctrl 0.80 -> ERS 43.60
    assert res_18_no_threat.environmental_risk_score == 48.16
    assert res_07_no_threat.environmental_risk_score == 43.60

    # Test what occurs when threat intelligence IS provided:
    # Intended difference: FINDING-007 has active weaponized exploit PoC
    threat_07_with_poc = ThreatEvidence(
        evidence_id="THREAT-007-POC",
        cve_id=f_07.cve_id,
        is_cisa_kev=False,
        epss_score=0.45,
        public_poc_available=True,
        threat_source="FIRST_EPSS_AND_EXPLOITDB",
        retrieved_at=datetime.now(timezone.utc),
    )
    res_07_with_threat = evaluate_risk(f_07, a_02, threat=threat_07_with_poc)

    # Threat score elevates to: (0.45 * 80) + 20 = 36 + 20 = 56.0
    assert float(res_07_with_threat.calculation_metadata["threat_score"]) == 56.0
    # Final ERS elevates from 43.60 to 61.52
    assert res_07_with_threat.environmental_risk_score == 61.52
    assert res_07_with_threat.environmental_risk_score > res_18_no_threat.environmental_risk_score


# ==============================================================================
# SCENARIO C: Compensating Controls Risk Mitigation
# ==============================================================================


def test_scenario_c_compensating_controls_dampening(benchmark_findings, benchmark_assets):
    """Scenario C: Compensating control dampening on identical vulnerability.

    - FINDING-001 (CVE-2023-38545, CVSS 9.8) on ASSET-001 (Cloudflare Enterprise WAF).
    - FINDING-051 (CVE-2023-38545, CVSS 9.8) on ASSET-015 (No controls).
    """
    f_protected = benchmark_findings["FINDING-001"]
    a_protected = benchmark_assets["ASSET-001"]
    res_protected = evaluate_risk(f_protected, a_protected)

    f_unprotected = benchmark_findings["FINDING-051"]
    a_unprotected = benchmark_assets["ASSET-015"]
    res_unprotected = evaluate_risk(f_unprotected, a_unprotected)

    # 1. Identical underlying vulnerability
    assert f_protected.cve_id == f_unprotected.cve_id == "CVE-2023-38545"
    assert f_protected.cvss_score == f_unprotected.cvss_score == 9.8
    assert res_protected.cvss_score == res_unprotected.cvss_score == 9.8

    # 2. Control multiplier behavior
    assert float(res_protected.calculation_metadata["control_multiplier"]) == 0.85
    assert float(res_unprotected.calculation_metadata["control_multiplier"]) == 1.00
    assert len(res_protected.control_adjustments) == 1
    assert res_protected.control_adjustments[0].name == "Cloudflare Enterprise WAF"
    assert res_protected.control_adjustments[0].adjustment_factor == -0.15
    assert len(res_unprotected.control_adjustments) == 0

    # 3. Control multiplier within valid bounds
    assert 0.60 <= float(res_protected.calculation_metadata["control_multiplier"]) <= 1.00
    assert 0.60 <= float(res_unprotected.calculation_metadata["control_multiplier"]) <= 1.00

    # 4. Control dampening impact on ASSET-001 specifically:
    # Unmitigated risk R = 57.40 -> with WAF (M=0.85): ERS 48.79
    unmitigated_r = float(res_protected.calculation_metadata["unmitigated_risk"])
    assert unmitigated_r == 57.40
    assert res_protected.environmental_risk_score == 48.79
    # Control reduced score by 8.61 points without eliminating the vulnerability
    assert res_protected.environmental_risk_score < unmitigated_r
    assert res_protected.environmental_risk_score > 0.0


# ==============================================================================
# SCENARIO D: Intra-Asset Hotspot Prioritization
# ==============================================================================


def test_scenario_d_intra_asset_hotspot(benchmark_scenarios, benchmark_findings, benchmark_assets):
    """Scenario D: Multiple concurrent vulnerabilities on mission-critical ASSET-002."""
    scenario = benchmark_scenarios["SCENARIO-D"]
    asset = benchmark_assets["ASSET-002"]

    results = []
    for fid in scenario["finding_ids"]:
        finding = benchmark_findings[fid]
        res = evaluate_risk(finding, asset)
        results.append((fid, finding, res))

    assert len(results) == 5
    assert all(r.asset_id == "ASSET-002" for _, _, r in results)

    # Sort by ERS descending to demonstrate prioritization ranking within the single asset
    ranked = sorted(results, key=lambda x: x[2].environmental_risk_score, reverse=True)

    # Extract ranking breakdown
    summary = [
        {
            "finding_id": fid,
            "cve_id": f.cve_id,
            "cvss": f.cvss_score,
            "ers": r.environmental_risk_score,
            "decision": r.calculation_metadata["aegis_decision"],
            "tier": r.risk_tier.value,
        }
        for fid, f, r in ranked
    ]

    # Verify ranking order:
    # FINDING-008 (CVSS 9.8, ERS 47.60) > FINDING-007 (CVSS 7.8, ERS 43.60) >
    # FINDING-005/006 (CVSS 7.5, ERS 43.00) > FINDING-009 (CVSS 5.9, ERS 39.80)
    assert ranked[0][0] == "FINDING-008"
    assert ranked[1][0] == "FINDING-007"
    assert ranked[4][0] == "FINDING-009"

    # Verify decision band distribution (4 in PLAN, 1 in TRACK)
    decisions = [s["decision"] for s in summary]
    assert decisions.count("PLAN") == 4
    assert decisions.count("TRACK") == 1


# ==============================================================================
# SCENARIO E: Cross-Asset Prevalent Vulnerability Spread
# ==============================================================================


def test_scenario_e_cross_asset_prevalent_library(benchmark_scenarios, benchmark_findings, benchmark_assets):
    """Scenario E: Same CVE across 4 distinct infrastructure tiers produces distinct risk evaluations."""
    scenario = benchmark_scenarios["SCENARIO-E"]

    cve_id = "CVE-2023-38545"
    evaluations = []

    for fid in scenario["finding_ids"]:
        finding = benchmark_findings[fid]
        assert finding.cve_id == cve_id, f"Finding '{fid}' is not {cve_id}"
        asset = benchmark_assets[finding.asset_id]
        res = evaluate_risk(finding, asset)
        evaluations.append(
            {
                "finding_id": fid,
                "asset_id": asset.asset_id,
                "environment": asset.environment.value,
                "exposure": asset.network_exposure.value,
                "criticality": asset.criticality.value,
                "data_sensitivity": asset.data_sensitivity.value,
                "cvss_score": finding.cvss_score,
                "control_multiplier": float(res.calculation_metadata["control_multiplier"]),
                "ers": res.environmental_risk_score,
                "decision": res.calculation_metadata["aegis_decision"],
                "risk_tier": res.risk_tier.value,
            }
        )

    assert len(evaluations) == 4

    # Check distinct scores and tiers:
    # ASSET-001 (Prod Gateway): ERS 48.79 (PLAN)
    # ASSET-013 (Staging Gateway): ERS 46.55 (PLAN)
    # ASSET-017 (Air-gapped Backup): ERS 36.54 (TRACK)
    # ASSET-015 (Internal Dev): ERS 33.77 (TRACK)
    ers_values = [e["ers"] for e in evaluations]
    assert len(set(ers_values)) == 4, f"Expected 4 distinct ERS values, got: {ers_values}"

    # Verify spread across decision bands
    bands = {e["decision"] for e in evaluations}
    assert "PLAN" in bands
    assert "TRACK" in bands

    # Highest risk is Production Gateway (48.79), lowest is Internal Dev Sandbox (33.77)
    sorted_by_ers = sorted(evaluations, key=lambda x: x["ers"], reverse=True)
    assert sorted_by_ers[0]["asset_id"] == "ASSET-001"
    assert sorted_by_ers[-1]["asset_id"] == "ASSET-015"
