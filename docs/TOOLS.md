# Aegis Patch — Phase 7 Deterministic Tool Layer

## 1. Overview & Architectural Role

Phase 7 introduces the deterministic, typed security tool layer for **Aegis Patch**. 

```
                 SUPERVISOR / AGENTS (Phase 8+)
                               │
                               ▼
                         TOOL REGISTRY
                               │
       ┌───────────────┬───────┴───────┬───────────────┐
       ▼               ▼               ▼               ▼
   Scan Tools    Threat Tools     Asset Tools     Planning & Risk Tools
       │               │               │               │
       └───────────────┼───────────────┼───────────────┘
                               ▼
                      Deterministic Results
                               │
          ┌────────────────────┼────────────────────┐
          ▼                    ▼                    ▼
      Repositories        Risk Engine           Optimizer
          │                    │                    │
          └────────────────────┼────────────────────┘
                               ▼
                             SQLite
```

### Critical Distinction: Tools Are Not Agents
In the Aegis Patch architecture:
- **Agents (Phase 8+)** reason, formulate hypotheses, plan, verify conclusions, and orchestrate workflows.
- **Tools (Phase 7)** perform bounded, deterministic computation, retrieval, and validation.
- Tools **never** call LLMs, run autonomous feedback loops, invoke external APIs, execute arbitrary shell commands, or perform destructive mutations on infrastructure.

---

## 2. Tool Inventory (17 Tools)

| # | Tool Name | Category | Side-Effect Class | Input Schema | Output Schema | Reused Authority |
|---|-----------|----------|-------------------|--------------|---------------|------------------|
| 1 | `parse_raw_scan` | SCAN | `COMPUTE_ONLY` | `ParseRawScanInput` | `ParseRawScanOutput` | Pydantic contracts |
| 2 | `validate_finding_schema` | SCAN | `COMPUTE_ONLY` | `ValidateFindingSchemaInput` | `ValidateFindingSchemaOutput` | `VulnerabilityFinding` |
| 3 | `deduplicate_findings` | SCAN | `COMPUTE_ONLY` | `DeduplicateFindingsInput` | `DeduplicateFindingsOutput` | Identity tuple |
| 4 | `lookup_cisa_kev` | THREAT | `READ_ONLY` | `LookupCisaKevInput` | `LookupCisaKevOutput` | `ThreatIntelligenceRepository` |
| 5 | `query_epss` | THREAT | `READ_ONLY` | `QueryEpssInput` | `QueryEpssOutput` | `ThreatIntelligenceRepository` |
| 6 | `query_osv_database` | THREAT | `READ_ONLY` | `QueryOsvDatabaseInput` | `QueryOsvDatabaseOutput` | Offline Cache |
| 7 | `query_asset_cmdb` | ASSET | `READ_ONLY` | `QueryAssetCmdbInput` | `QueryAssetCmdbOutput` | `AssetRepository`, `ControlRepository` |
| 8 | `get_network_reachability` | ASSET | `READ_ONLY` | `GetNetworkReachabilityInput` | `GetNetworkReachabilityOutput` | CMDB Network Topology |
| 9 | `query_rag_policy` | ASSET | `READ_ONLY` | `QueryRagPolicyInput` | `QueryRagPolicyOutput` | Local policy files |
| 10 | `calculate_environmental_risk` | RISK | `COMPUTE_ONLY` | `CalculateEnvironmentalRiskInput` | `CalculateEnvironmentalRiskOutput` | `src.tools.risk_engine:evaluate_risk` |
| 11 | `map_ssvc_decision` | RISK | `COMPUTE_ONLY` | `MapSsvcDecisionInput` | `MapSsvcDecisionOutput` | `src.tools.decision_mapping:get_decision_details` |
| 12 | `optimize_patch_capacity` | PLANNING | `COMPUTE_ONLY` | `OptimizePatchCapacityInput` | `OptimizePatchCapacityOutput` | `src.services.scenario_service:optimize_patch_schedule` |
| 13 | `resolve_package_dependencies` | PLANNING | `READ_ONLY` | `ResolvePackageDependenciesInput` | `ResolvePackageDependenciesOutput` | Benchmark dependency catalog |
| 14 | `simulate_risk_reduction` | PLANNING | `SIMULATION` | `SimulateRiskReductionInput` | `SimulateRiskReductionOutput` | `src.tools.risk_engine:evaluate_risk` |
| 15 | `verify_score_derivation` | VERIFICATION | `COMPUTE_ONLY` | `VerifyScoreDerivationInput` | `VerifyScoreDerivationOutput` | `src.tools.risk_engine:evaluate_risk` |
| 16 | `detect_hallucinated_claims` | VERIFICATION | `COMPUTE_ONLY` | `DetectHallucinatedClaimsInput` | `DetectHallucinatedClaimsOutput` | Deterministic Evidence Checker |
| 17 | `validate_plan_constraints` | VERIFICATION | `COMPUTE_ONLY` | `ValidatePlanConstraintsInput` | `ValidatePlanConstraintsOutput` | Constraint Rules Engine |

---

## 3. Guarantees & Safety Policy

1. **Zero Live External API Dependencies**:
   - Threat intelligence queries (`lookup_cisa_kev`, `query_epss`, `query_osv_database`) query local database records or offline caches only.
   - If telemetry is absent, the tool returns `ToolStatus.NOT_AVAILABLE` or `ToolStatus.NOT_FOUND` with explicit provenance metadata. Telemetry is never fabricated.
2. **Zero Shell / Subprocess Execution**:
   - Tools never invoke `subprocess`, `os.system`, SSH, or package managers (e.g. `apt`, `pip`).
3. **Deterministic Reuse**:
   - `calculate_environmental_risk` delegates directly to Phase 3's authoritative `evaluate_risk`.
   - `optimize_patch_capacity` delegates directly to Phase 4's authoritative `optimize_patch_schedule`.
   - Mathematical formulas and knapsack DP algorithms are strictly non-duplicated.
4. **Audit Provenance**:
   - Every tool response includes standardized envelope metadata (`ToolProvenance`) declaring origin source, source type, and observation timestamps.

---

## 4. Usage Example

```python
from src.tools import default_tool_registry
from src.tools.schemas import MapSsvcDecisionInput

# Query or invoke via framework-neutral registry
result = default_tool_registry.invoke(
    "map_ssvc_decision",
    MapSsvcDecisionInput(ers_score=88.5, has_compensating_controls=False)
)
print(result.decision.value) # "ACT"
```
