# Aegis Patch

**Context-Driven Vulnerability Prioritization and Remediation Orchestration**

Aegis Patch is an enterprise-grade security platform that evaluates vulnerabilities in the context of their real environment, determining which vulnerabilities deserve attention first rather than relying on generic CVSS severity alone.

---

## Overview

### The Problem
Traditional vulnerability management relies almost exclusively on CVSS base scores. This leads to critical alert fatigue: an isolated test server with a CVSS 10.0 vulnerability often gets prioritized over a CVSS 7.5 vulnerability actively exploited on an internet-facing production host with customer financial records.

### The Aegis Patch Solution
Aegis Patch evaluates vulnerability severity in conjunction with active threat intelligence, asset criticality, network exposure, data sensitivity, and compensating security controls. It computes a deterministic **Environmental Risk Score (ERS)** to partition findings into actionable decision bands: **ACT**, **ATTEND**, **PLAN**, and **TRACK**.

---

## Core Risk Methodology (Phase 3)

The deterministic Environmental Risk Score (ERS) is calculated on a 0–100 scale:

$$ERS = R \times M_{control}$$

Where:
- **Base Score ($B \in [0, 100]$)**: Derived from CVSS score ($CVSS \times 10$).
- **Threat Score ($T \in [0, 100]$)**: Derived from known exploitation in the wild (KEV), EPSS percentiles, and POC availability. Missing threat intelligence remains transparently unassessed rather than defaulted to zero.
- **Environmental Score ($E \in [0, 100]$)**: Derived from asset business criticality, network exposure (internet-facing vs. internal), data sensitivity classification, and deployment environment.
- **Unmitigated Risk ($R \in [0, 100]$)**: Weighted synthesis of Base ($w_B=0.40$), Threat ($w_T=0.30$), and Environmental ($w_E=0.30$) dimensions.
- **Control Multiplier ($M_{control} \in [0.40, 1.00]$)**: Reflects validated compensating controls (e.g., WAF, network segmentation, runtime agents). Compensating controls reduce residual environmental risk without removing the underlying vulnerability.

### Decision Bands
- **ACT ($ERS \ge 70.0$)**: Immediate emergency remediation within 24–48 hours.
- **ATTEND ($50.0 \le ERS < 70.0$)**: Next scheduled maintenance sprint (7–14 days).
- **PLAN ($30.0 \le ERS < 50.0$)**: Standard monthly maintenance patching.
- **TRACK ($ERS < 30.0$)**: Routine monitoring and regular release cycle.

---

## Web Application Features (Phase 4)

Built with Streamlit and styled using an enterprise light design system (`#f8fafc` background, crisp cards, restrained typography, and accessible indicators):

1. **Overview Dashboard**:
   - Executive KPIs: Findings Analyzed, Assets Affected, Critical Severity, Priority Findings (ACT + ATTEND), and Average ERS.
   - Dynamic multi-attribute filtering: Vulnerability Severity, Aegis Decision, Asset Environment, and Asset Criticality.
   - Side-by-side distribution charts: Aegis Patch Decisions vs. Vulnerability Severity.
   - Environmental Risk Overview: ERS score band distribution.
   - Core Differentiator Callout: Context Changes Priority.
   - Assets with Highest-Risk Findings: Ranked by peak ERS among hosted vulnerabilities.
   - Priority Preview: Top 5 prioritized findings.
   - Asset Context Deep Dive: Interactive asset inspection and compensating control review.

2. **Vulnerabilities Page**:
   - Multi-field search across Finding IDs, CVEs, package names, asset IDs, and hostnames.
   - Deterministic sorting by ERS descending, CVSS descending, and finding ID ascending.
   - Interactive deep-dive investigation view:
     - Clear narrative: "Why Aegis Patch Prioritized This".
     - Complete mathematical breakdown: $B$, $T$, $E$, $R$, $M_{control}$, and final $ERS$.
     - Threat intelligence provenance and verified exploit evidence.
     - Target asset context and compensating control status.
     - Recommended remediation guidance, verified policy references, and raw evidence isolation.

3. **Scenario Explorer & What-If Simulation**:
   - **Scenario A**: Exposure & Criticality Inversion (CVSS 10.0 internal test vs. CVSS 7.5 exposed production).
   - **Scenario B**: Threat Intelligence Differential (exploited vs. unexploited vulnerability prioritization).
   - **Scenario C**: Compensating Control Dampening (residual risk reduction from active WAF/segmentation).
   - **Scenario D**: Intra-Asset Hotspot Prioritization (evaluating multiple findings on a single host).
   - **Scenario E**: Cross-Asset Prevalent Vulnerability Spread (same CVE across diverse environments).
   - **What-If Patch Capacity Simulation**: Interactive engineering capacity slider with deterministic knapsack optimization under strict resource limits.

---

## Database Foundation, ORM Models, Repositories & Ingestion (Phase 5A–5D)

Aegis Patch utilizes SQLite with SQLAlchemy 2.x for local persistence:
- **Location & Configuration:** Configurable via `DATABASE_URL` (default: `sqlite:///data/runtime/aegispatch.db`).
- **Core Domain Models (`src/database/models/`):**
  - `Asset`: Enterprise CMDB infrastructure context and metadata.
  - `VulnerabilityFinding`: Scanner vulnerability findings with CVSS metrics and package info.
  - `ThreatIntelligenceObservation`: Verified exploit telemetry and EPSS probability observations.
  - `SecurityControl`: Compensating and mitigating security controls linked to assets.
  - `RiskAssessment`: Auditable mathematical risk evaluations ($B, T, E, R, M_{control}, ERS$) and decisions.
  - `PatchPlan` & `PatchPlanItem`: Remediation plans scheduling actions within capacity constraints.
  - `PolicyDocument`: Governance and patch management policy document metadata.
- **Repository / Data Access Layer (`src/database/repositories/`):**
  - `AssetRepository`, `VulnerabilityRepository`, `ThreatIntelligenceRepository`, `ControlRepository`, `RiskAssessmentRepository`, `PatchPlanRepository`, `PolicyRepository`.
  - Transaction boundary policy: repositories perform `add`, `flush`, and `refresh`; application boundaries govern atomic `commit` and `rollback`.
- **Benchmark Ingestion Pipeline (`src/database/ingestion/`):**
  - Populates SQLite deterministically and idempotently from local synthetic sources (`enterprise_cmdb.json` -> 18 assets, 18 controls; `benchmark_60_scans.json` -> 60 findings; `data/policies/*.md` -> 3 policies).
  - Preserves offline integrity (0 fabricated live threat observations; 0 uncalculated risk assessments).
  - CLI execution: `python scripts/ingest_benchmark.py`.
- **Persistence Service (`src/services/persistence_service.py`):**
  - Clean integration layer coordinating repositories, transactions, benchmark ingestion, Phase 3 risk result persistence, and patch plan item scheduling.
  - Supports historical risk evaluation accumulation and patch plan dependency ordering.
- **Initialization & Verification:** Schema creation via `init_db()`, connectivity check via `check_db_health()`.
- **Git Safety:** Generated runtime database files in `data/runtime/` and `*.db` are strictly ignored by Git.

---

## FastAPI Backend (Phase 6)

Aegis Patch provides a modern, RESTful FastAPI backend (`src/api/`) offering thin, validated endpoints decoupled from internal persistence queries and risk algorithms:

- **Application Entry Point:** `src.api.main:app` (via `create_app()` factory).
- **Base Versioned API Prefix:** `/api/v1`
- **Interactive Documentation:** Swagger UI at `http://localhost:8000/docs` and ReDoc at `http://localhost:8000/redoc`.
- **Core Endpoints:**
  - `GET /` — API gateway info and metadata links.
  - `GET /api/v1/health` — System and database connectivity status check.
  - `GET /api/v1/assets` — Paginated assets with environment, criticality, and network exposure filters.
  - `GET /api/v1/assets/{asset_id}` — Asset detail with active compensating controls and finding metrics.
  - `GET /api/v1/assets/{asset_id}/findings` — Scanner findings affecting the specified asset.
  - `GET /api/v1/vulnerabilities` — Paginated findings with free-text search (`search`), `severity`, and `status` filters.
  - `GET /api/v1/vulnerabilities/{finding_id}` — Detailed vulnerability description and advisory links.
  - `GET /api/v1/vulnerabilities/{finding_id}/risk` — Latest persisted contextual risk evaluation and ERS components.
  - `GET /api/v1/risk/highest` — Top risk assessments ordered by Environmental Risk Score (ERS) descending.
  - `GET /api/v1/risk/{finding_id}/history` — Chronological risk evaluation history (newest first) for mathematical auditability.
  - `GET /api/v1/patch-plans` — Persisted remediation plans and capacity limits.
  - `GET /api/v1/patch-plans/{plan_id}` — Remediation plan with ordered execution sequence items.
  - `POST /api/v1/patch-plans` — Create a new remediation plan (201 Created).
  - `POST /api/v1/patch-plans/{plan_id}/items` — Schedule a remediation item into a plan (validates foreign keys and uniqueness).
  - `PATCH /api/v1/patch-plans/{plan_id}` — Update plan capacity, status, or notes.
  - `GET /api/v1/policies` — Organizational security and patch remediation policy documents.
  - `GET /api/v1/policies/{policy_id}` — Policy detail with SHA-256 integrity hash and structured metadata.
  - `GET /api/v1/threat-intelligence/{cve_id}` — Locally stored offline threat telemetry (0 external network calls).
- **Local API Launch:**
  ```bash
  uvicorn src.api.main:app --reload
  ```

---

## Safety & Non-Destructive Operation

Aegis Patch is explicitly designed as an advisory and planning platform:
- **No destructive actions**: The system does not execute destructive infrastructure modifications or uncoordinated automated patching.
- **Safe artifacts**: All outputs consist of auditable plans, playbooks, verification reports, and patch schedules.
- **Benchmark integrity**: Demonstrations and evaluation harnesses utilize validated synthetic datasets (`benchmark_60_scans.json`, `enterprise_cmdb.json`).

---

## Getting Started

### Prerequisites
- Python 3.12+ (tested with Python 3.14)
- Git

### Setup
1. Clone the repository:
   ```bash
   git clone https://github.com/guna5045/aegispatch.git
   cd aegispatch
   ```

2. Activate virtual environment:
   ```bash
   # On Windows PowerShell:
   .\.venv\Scripts\Activate.ps1

   # On macOS/Linux:
   source .venv/bin/activate
   ```

3. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Run test suite:
   ```bash
   pytest
   ```

6. Launch the Aegis Patch web application:
   ```bash
   streamlit run app.py
   ```