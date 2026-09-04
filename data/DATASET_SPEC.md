# AegisPatch Synthetic Benchmark Dataset Specification

## 1. Purpose & Objectives

The AegisPatch Synthetic Benchmark is a deterministic evaluation testbed designed to demonstrate and empirically evaluate context-driven vulnerability prioritization and remediation planning.

Traditional vulnerability management relies almost exclusively on static Common Vulnerability Scoring System (CVSS) base scores. This dataset is engineered to demonstrate why CVSS alone is insufficient by modeling the real-world operational context of an enterprise environment, including:
1. **Asset Exposure:** How network reachability (Internet-facing vs. air-gapped) impacts actual exploit likelihood.
2. **Business Criticality & Tier:** How the operational role of an asset changes the business impact of a compromise.
3. **Data Sensitivity:** How resident data classification (Restricted/PII vs. Public) alters consequence severity.
4. **Threat Intelligence Signals:** How real-world exploitation evidence (CISA Known Exploited Vulnerabilities catalog, FIRST EPSS probabilities, public proof-of-concept exploits) elevates urgency over theoretical severity.
5. **Compensating Security Controls:** How active defenses (WAF virtual patching, network isolation, EDR) mitigate exposure and dampen immediate risk.
6. **Constrained Remediation Planning:** How limited operational capacity (maintenance windows, engineering hours) demands algorithmic prioritization rather than naïve top-to-bottom CVSS remediation.
7. **Verification & Auditability:** How verification agents can audit remediation recommendations against policies, constraints, and factual citations to detect discrepancies or unsupported decisions.

---

## 2. Record Counts & Scope

| Entity Type | Exact Count | Description |
|---|---|---|
| **Vulnerability Findings** | **60** | Normalized vulnerability occurrences across infrastructure assets. |
| **Enterprise Assets** | **18** | Distinct infrastructure systems spanning business tiers, environments, and exposure zones. |
| **Distinct CVEs** | **35–45** | Unique Common Vulnerabilities and Exposures represented across the 60 finding instances. |
| **Threat Evidence Records** | **1 per distinct CVE** | Authoritative threat intelligence records mapped 1-to-1 with unique CVE IDs. |
| **Organizational Policies** | **4–6** | Synthetic security policies defining compliance thresholds, remediation SLAs, and architectural rules. |

---

## 3. Entity Relationships & Cardinality

```
+--------------------------+           N:1           +----------------------+
|  VulnerabilityFinding    | ----------------------> |        Asset         |
|  (finding_id, asset_id)  |                         |      (asset_id)      |
+--------------------------+                         +----------------------+
             │
             │ N:1 (via cve_id)
             ▼
+--------------------------+
|      ThreatEvidence      |
|         (cve_id)         |
+--------------------------+
             │
             │ Combines with Asset & Finding
             ▼
+--------------------------+
|       AssetContext       |
|      (context_id)        |
+--------------------------+
             │
             ▼
+--------------------------+
|      RiskAssessment      |
|     (assessment_id)      |
+--------------------------+
             │
             ▼
+--------------------------+
|      PatchCandidate      |
|      (candidate_id)      |
+--------------------------+
             │
             ▼
+--------------------------+
|        PatchPlan         |
|        (plan_id)         |
+--------------------------+
```

### Cardinality Rules
1. **Finding $\rightarrow$ Asset ($N:1$):** Each `VulnerabilityFinding` belongs to exactly one `Asset`. A single asset can (and frequently does) host multiple vulnerability findings.
2. **Finding $\rightarrow$ ThreatEvidence ($N:1$):** Multiple findings on different assets may reference the same `cve_id`. Each unique `cve_id` corresponds to exactly one canonical `ThreatEvidence` record.
3. **Asset $\rightarrow$ Findings ($1:N$):** An asset may host between 1 and 8 findings. Hotspot assets will host multiple concurrent findings to test intra-asset prioritization.
4. **Cross-Asset CVE Distribution ($1:N$):** Prevalent vulnerabilities (e.g., common library vulnerabilities like OpenSSL or Log4j) appear across multiple distinct assets (e.g., appearing on a mission-critical Internet-facing server, a staging node, and an air-gapped test container) to test environmental divergence.

---

## 4. Deterministic Identifier Strategy

All benchmark records utilize deterministic, zero-padded identifier schemes:

| Entity | Identifier Format | Examples |
|---|---|---|
| Vulnerability Finding | `FINDING-{001..060}` | `FINDING-001`, `FINDING-042`, `FINDING-060` |
| Enterprise Asset | `ASSET-{001..018}` | `ASSET-001`, `ASSET-007`, `ASSET-018` |
| Threat Evidence | `THREAT-{001..NNN}` | `THREAT-001` (keyed to associated CVE) |
| Asset Context | `CTX-{001..060}` | `CTX-001` (keyed 1-to-1 with finding evaluation) |
| Risk Assessment | `RSK-{001..060}` | `RSK-001` (keyed 1-to-1 with finding evaluation) |
| Patch Candidate | `CAND-{001..060}` | `CAND-001` |
| Patch Action | `ACT-{001..NNN}` | `ACT-001`, `ACT-002` |
| Patch Plan | `PLAN-BENCHMARK-{ID}` | `PLAN-BENCHMARK-01` |
| Verification Record | `VRF-BENCHMARK-{ID}` | `VRF-BENCHMARK-01` |
| Policy Document | `POL-{NAME}-{01..NN}` | `POL-VULN-SLA-01`, `POL-DATA-PROT-02` |
| Compensating Control | `CTL-{TYPE}-{01..NN}` | `CTL-WAF-01`, `CTL-EDR-02`, `CTL-ACL-03` |

---

## 5. Field Population Rules & Schema Alignment

All records must strictly validate against the Phase 1 Pydantic contracts in `src/schemas/`:

### 5.1 Vulnerability Finding (`src/schemas/vulnerability.py`)
- `finding_id`: Required string matching `FINDING-\d{3}`.
- `cve_id`: Required string matching standard regex `^CVE-\d{4}-\d{4,7}$`.
- `title`: Concise descriptive summary.
- `description`: Technical explanation of root cause and vulnerability mechanism.
- `cvss_score`: Float between `0.0` and `10.0` (CVSS v3.1 base score standard).
- `severity`: Valid `VulnerabilitySeverity` enum (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- `affected_package`: Canonical package or software component name.
- `installed_version`: Specific version string currently present on asset.
- `fixed_version`: Patched version string, or `None` if zero-day / unpatched.
- `asset_id`: Corresponding `ASSET-\d{3}` identifier.
- `source`: Ingestion scanner name (`Trivy`, `Snyk`, `AWS-Inspector`, `Qualys`).
- `references`: List of `VulnerabilityReference` objects with valid URIs.
- `raw_evidence`: Untrusted raw scanner payload dictionary.

### 5.2 Enterprise Asset (`src/schemas/asset.py`)
- `asset_id`: Required string matching `ASSET-\d{3}`.
- `hostname`: Fully-qualified domain name or internal hostname format.
- `asset_type`: Valid `AssetType` enum (`SERVER`, `WORKSTATION`, `CONTAINER`, `CLOUD_INSTANCE`, `DATABASE`, `NETWORK_DEVICE`, `APPLICATION`).
- `business_tier`: Valid `BusinessTier` enum (`MISSION_CRITICAL`, `BUSINESS_CRITICAL`, `INTERNAL_OPERATIONAL`, `NON_CRITICAL`).
- `criticality`: Valid `AssetCriticality` enum (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`).
- `network_exposure`: Valid `NetworkExposure` enum (`INTERNET_FACING`, `DMZ`, `INTERNAL`, `AIR_GAPPED`).
- `data_sensitivity`: Valid `DataSensitivity` enum (`PUBLIC`, `INTERNAL`, `CONFIDENTIAL`, `RESTRICTED`).
- `environment`: Valid `EnvironmentType` enum (`PRODUCTION`, `STAGING`, `DEVELOPMENT`, `TESTING`).
- `owner_team`: Responsible organizational unit.
- `patch_window`: Structured `PatchWindow` object (e.g., Sunday 02:00 UTC, 4.0 hours), or `None` if unassigned.
- `compensating_controls`: List of active `CompensatingControl` items.
- `metadata`: String key-value tags (e.g., `cloud_provider`, `region`).

### 5.3 Threat Evidence (`src/schemas/threat.py`)
- `evidence_id`: Required string matching `THREAT-\d{3}`.
- `cve_id`: Matching `CVE-\d{4}-\d{4,7}`.
- `is_cisa_kev`: Boolean flag.
- `cisa_kev_date_added`: Timezone-aware datetime or `None`.
- `cisa_kev_due_date`: Timezone-aware datetime or `None`.
- `epss_score`: Float between `0.0` and `1.0`, or `None` if unindexed.
- `epss_percentile`: Float between `0.0` and `1.0`, or `None`.
- `public_poc_available`: Boolean flag.
- `threat_source`: Source attribution (e.g., `CISA KEV`, `FIRST EPSS`).
- `retrieved_at`: Timezone-aware datetime (UTC).
- `confidence`: Valid `ThreatConfidence` enum (`LOW`, `MEDIUM`, `HIGH`).

---

## 6. Unknown & Missing Data Rules

Real-world security operations constantly deal with incomplete intelligence. The benchmark explicitly encodes missing data states without fabricating synthetic filler:

1. **Unreleased Patches:** If a vulnerability has no official upstream patch, `fixed_version` must be `None`.
2. **Missing EPSS Intelligence:** For recent CVEs or vulnerabilities unindexed by FIRST, `epss_score` and `epss_percentile` must be `None`. They must **never** be fabricated as `0.0`.
3. **CISA KEV Status:** If a CVE is not in the CISA KEV catalog, `is_cisa_kev` is `False`, and `cisa_kev_date_added` / `cisa_kev_due_date` must be `None`.
4. **Maintenance Windows:** If an asset lacks an assigned maintenance schedule, `patch_window` must be `None`.
5. **Compensating Controls:** If an asset has no mitigating controls, `compensating_controls` must be an empty list `[]`.

---

## 7. Counterexample Scenario Matrix

The benchmark must include deliberate counterexample pairings where sorting findings purely by CVSS produces the **opposite** prioritization of context-aware risk.

### Scenario A: Environmental Exposure & Criticality Inversion
- **Finding A1 (The "Paper Tiger"):** CVSS **9.8** (Critical) in an isolated, air-gapped development container (`AIR_GAPPED`, `DEVELOPMENT`, `NON_CRITICAL`, `PUBLIC` data).
- **Finding A2 (The "Real Threat"):** CVSS **7.5** (High) in an Internet-facing production authentication database (`INTERNET_FACING`, `PRODUCTION`, `MISSION_CRITICAL`, `RESTRICTED` data).
- **Expected Behavior:** Naïve CVSS prioritizes A1 over A2. Context-aware AegisPatch prioritizes A2 over A1 due to immediate exposure, data sensitivity, and mission impact.

### Scenario B: Threat Intelligence & Active Exploitation Inversion
- **Finding B1 (High Severity, Dormant):** CVSS **8.8** (High), but zero public PoC, `epss_score` = `0.0012` (0.12% exploit probability), not in CISA KEV.
- **Finding B2 (Moderate Severity, Actively Exploited):** CVSS **7.1** (High), but listed in CISA KEV with an active federal remediation due date, public weaponized exploit available, and `epss_score` = `0.89` (89% exploit probability).
- **Expected Behavior:** Naïve CVSS prioritizes B1 over B2. AegisPatch prioritizes B2 due to confirmed active exploitation in the wild.

### Scenario C: Compensating Controls Dampening
- **Finding C1 (Shielded Critical):** CVSS **9.0** on an Internet-facing production service protected by an active, verified WAF virtual patch rule (`CTL-WAF-01`) that blocks the exploit vector.
- **Finding C2 (Exposed High):** CVSS **8.2** on an identical Internet-facing service with **no** compensating control or WAF coverage.
- **Expected Behavior:** AegisPatch applies control adjustment to C1, elevating C2 for immediate patch execution while scheduling C1 for standard maintenance.

### Scenario D: Intra-Asset Hotspot Prioritization
- **Asset ASSET-003 (Core Banking Gateway):** Hosts 5 distinct vulnerabilities ranging from CVSS 5.3 to CVSS 9.4.
- **Expected Behavior:** System evaluates which package upgrades resolve the greatest cumulative risk within the single asset's 3-hour maintenance window.

### Scenario E: Multi-Asset Shared Vulnerability Spread
- **Vulnerability CVE-2024-XXXX (Ubiquitous Library):** Present on 4 different assets:
  1. `ASSET-001` (Internet-facing Production API Gateway)
  2. `ASSET-006` (Internal Staging Service)
  3. `ASSET-012` (Internal Development Worker)
  4. `ASSET-017` (Air-gapped Backup Vault)
- **Expected Behavior:** Demonstrates identical CVE yielding 4 distinct environmental risk scores and disparate remediation urgency tiers.

---

## 8. Capacity Benchmark & Constrained Optimization

The benchmark includes an operational capacity constraint to evaluate the patch planning agent and deterministic schedule optimization:

| Metric | Benchmark Value | Description |
|---|---|---|
| **Default Total Maintenance Capacity** | **16.0 engineering hours** | Total labor budget allocated for a single remediation cycle. |
| **Total Evaluated Findings** | **60 findings** | Full pool of candidate vulnerabilities. |
| **Candidate Cost Range** | **0.5 to 6.0 hours** | Estimated testing, validation, and deployment effort per action. |
| **Risk Reduction Range** | **5.0 to 85.0 points** | Expected risk points eliminated upon successful deployment. |
| **Action Dependencies** | **4–6 dependency chains** | Prerequisite ordering rules (e.g., base runtime upgrade required before application patch; OS reboot required). |

### Desired Optimizer Properties
- The planner must select a subset of `PatchCandidate` items that maximizes total risk reduction without exceeding the `16.0` hour capacity limit.
- Dependency chains must be strictly respected (action $A$ must precede action $B$ in `sequence_order`).
- Actions exceeding capacity must be deferred to subsequent maintenance windows with explicit documentation.

---

## 9. Evaluation Fields & Benchmark Metrics

To enable quantitative evaluation of AegisPatch agents in later phases, the dataset defines the following audit dimensions:

| Evaluation Dimension | Input / Reference Fields | Expected Evaluation Check |
|---|---|---|
| **Ingestion Correctness** | `finding_id`, `raw_evidence` | Scanner payload correctly parsed into strongly-typed finding fields. |
| **Normalization Accuracy** | `cve_id`, `severity`, `cvss_score` | CVE format, score bounds, and severity enums strictly conform to standards. |
| **Asset Context Resolution** | `asset_id`, asset attributes | Finding correctly bound to asset environmental attributes and compensating controls. |
| **Threat Signal Grounding** | `cve_id`, `epss_score`, `is_cisa_kev` | Threat intelligence matches authoritative records without hallucinated status. |
| **Risk Inversion Rate** | `cvss_score` vs. `environmental_risk_score` | Inversion frequency matches designed counterexamples (Scenarios A–E). |
| **Plan Constraint Validity** | `total_estimated_cost_hours`, `capacity_limit_hours` | Total hours $\le$ capacity limit; all sequence dependencies satisfied. |
| **Rollback Completeness** | `rollback_plan.procedure_description` | Action contains actionable, non-empty recovery procedures and duration. |
| **Critic Audit Accuracy** | `VerificationResult` checks | Verification agent accurately detects policy breaches, constraint violations, and citation errors. |

---

## 10. Data Quality & Integrity Constraints

All records generated under this specification must adhere to these inviolable rules:
1. **Deterministic Identifiers:** Zero random UUIDs. All IDs must follow predictable sequences (`FINDING-001`, `ASSET-001`).
2. **Strict Schema Conformance:** Every record must instantiate its respective Pydantic model with zero validation errors.
3. **Realistic Versioning:** Package version strings must follow standard Semantic Versioning or standard Linux package schemes (e.g., `2.4.51-1+deb11u1`).
4. **No Fake URLs:** External advisory links must use official, authentic reference formats (e.g., `https://nvd.nist.gov/vuln/detail/CVE-YYYY-NNNN`, `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`).
5. **No Fabricated Intelligence:** Real CVE numbers used in the dataset must reflect authentic public vulnerability profiles or clearly designated synthetic CVE namespaces (e.g., `CVE-2024-99901` for synthetic demonstration cases).
6. **Zero Embedded Secrets:** No private keys, authentic credentials, internal IP ranges of proprietary systems, or confidential corporate data.

---

## 11. Reproducibility & Benchmark Seeding

- All synthetic dataset records will be stored in static JSON files under `data/synthetic/` in Phase 2B.
- The dataset must be 100% deterministic: loading the dataset at any time on any system must produce bit-for-bit identical Pydantic objects.
- Tests running against the benchmark must produce deterministic risk scores and patch plans.

---

## 12. Separation: Synthetic Environment Data vs. Public Threat Data

To maintain architectural cleanliness and real-world credibility:
- **Internal Assets & Findings (Synthetic):** Assets (`ASSET-001` through `ASSET-018`), internal hostnames, network topologies, and scanner findings are synthetic models representing a realistic enterprise environment.
- **External Threat Intelligence (Public / Cached):** Threat evidence (CVE CVSS vectors, EPSS probabilities, CISA KEV entries) will reflect verified public intelligence data cached locally in `data/cache/` to ensure offline reproducibility without external runtime dependencies.
