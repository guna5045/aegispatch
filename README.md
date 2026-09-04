# AegisPatch

AegisPatch is a context-driven vulnerability prioritization and remediation planning system.

---

## Overview

### Problem
Security operations and engineering teams often face hundreds or thousands of vulnerability alerts, but have strictly limited patching capacity and maintenance windows. Traditional prioritization relies almost exclusively on generic CVSS severity scores, failing to capture organization-specific environmental context—such as network exposure, asset criticality, compensating controls, active exploit intelligence, and operational constraints.

### Intended Solution
AegisPatch implements a multi-agent AI system designed to intelligently evaluate vulnerability evidence, asset exposure, and organizational policies. The system prioritizes actual business risk, synthesizes optimal remediation and patch schedules, and rigorously verifies its own recommendations before submitting them for human approval.

---

## Planned Architecture

The planned system architecture includes:

- **Frontend:** Streamlit-based operational dashboard for reviewing vulnerability queues, agent audit trails, and remediation plans.
- **Backend:** FastAPI service orchestrating pipeline execution, data intake, and human-in-the-loop workflows.
- **Orchestration:** LangGraph state machine coordinating multi-agent workflows with deterministic state transitions.
- **Specialized Agents (7 planned):**
  1. Ingestion & Normalization Agent
  2. Asset & Context Enrichment Agent
  3. Threat Intelligence Agent
  4. Risk Prioritization Agent
  5. Remediation Planning Agent
  6. Verification & Critic Agent
  7. Reporting & Artifact Agent
- **Deterministic Tools:** Algorithmic scoring tools, formula-based risk calculators, and constraint-based schedule optimizers.
- **Data & Storage:** SQLite for relational state and history; local RAG / vector retrieval for organizational policies and security standards.
- **Threat Intelligence:** Cached and public intelligence feeds (e.g., CISA KEV, EPSS).
- **Human Approval:** Strict human-in-the-loop sign-off before any remediation artifact is finalized.

---

## Safety & Non-Destructive Operation

AegisPatch is explicitly designed as an advisory and planning system:
- **No destructive actions:** The system will never execute destructive real-world infrastructure modifications or unauthorized automated patching.
- **Safe artifacts:** Outputs consist of auditable plans, playbooks, verification reports, and patch schedules.
- **Local / Synthetic validation:** Demonstrations and test harnesses utilize synthetic and local data.

---

## Project Status

- **Current Status:** Foundation / Scaffolding Phase.
- Initial directory structure, configuration framework, environment templates, and test harness are established.
- Core agents, LangGraph orchestration, RAG pipelines, and UI components will be introduced in subsequent milestone phases.

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
   ```

3. Copy environment configuration:
   ```bash
   cp .env.example .env
   ```

4. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

5. Run foundation tests:
   ```bash
   pytest
   ```