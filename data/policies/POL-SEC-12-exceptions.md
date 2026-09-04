# POL-SEC-12: Compensating Controls, Risk Mitigations, and Exception Governance Policy

> **Document Type:** Synthetic Organizational Policy — AegisPatch Benchmark  
> **Policy Identifier:** `POL-SEC-12`  
> **Effective Date:** 2026-01-01  
> **Version:** 2.2  
> **Notice:** This document is a synthetic benchmark artifact created strictly for evaluating context-driven vulnerability prioritization in the AegisPatch project. It does not represent authoritative government or corporate standards.

---

## 1.0 Purpose and Scope

### §1.1 Purpose
This policy establishes governance requirements, evidentiary standards, and approval workflows when vulnerabilities cannot be remediated within mandatory SLAs defined in `POL-SEC-04`. It defines the rigorous operational criteria for deploying compensating controls (`MITIGATE`) versus formal risk acceptance (`ACCEPT_RISK`).

### §1.2 Scope
This policy applies to all systems, applications, and third-party software components cataloged in the enterprise CMDB for which an exception or remediation deferral is requested.

---

## 2.0 Core Governance Distinction: Mitigation vs. Risk Acceptance

A fundamental distinction exists between technical mitigation and risk acceptance. Agents, systems, and personnel must not conflate these decisions.

### §2.1 Technical Mitigation (`MITIGATE`)
- **§2.1.1 Definition:** `MITIGATE` denotes the active deployment of verified technical, operational, or architectural compensating controls that demonstrably intercept, block, or neutralize the attack vector of a vulnerability, without directly applying the vendor patch.
- **§2.1.2 Risk Impact:** Compensating controls reduce residual likelihood and/or impact, dampening the effective environmental risk score. However, **compensating controls do not eliminate underlying vulnerability flaws**, and a permanent patch plan must remain scheduled.
- **§2.1.3 Prerequisite:** A decision to `MITIGATE` is valid only if an approved compensating control is active (`ACTIVE`) and verified against the specific vulnerability payload or exploit vector.

### §2.2 Risk Acceptance (`ACCEPT_RISK`)
- **§2.2.1 Definition:** `ACCEPT_RISK` denotes formal executive authorization to operate an asset with known unpatched and unmitigated vulnerabilities without deploying an effective compensating control.
- **§2.2.2 Permitted Scenarios:** Risk acceptance is strictly limited to low-criticality assets, isolated testing sandboxes (`AIR_GAPPED`), or situations where patching is technically infeasible and compensating controls would cause severe business disruption.
- **§2.2.3 Prohibition on Internet-Facing Assets:** Risk acceptance is **strictly prohibited** for unmitigated Critical or High vulnerabilities residing on Internet-facing (`INTERNET_FACING`) production assets.

---

## 3.0 Approved Compensating Control Categories

To qualify for score adjustment and risk mitigation under §2.1, compensating controls must belong to one of the following recognized enterprise control categories:

### §3.1 Web Application Firewalls (WAF) & Virtual Patching
- **§3.1.1 Controls (`CTL-WAF-01`, `CTL-WAF-02`):** Layer 7 inspection engines enforcing custom or managed rulesets that detect and block known exploit payloads (e.g., SQLi, JNDI injection, path traversal) prior to reaching the vulnerable backend component.
- **§3.1.2 Validation Rule:** Virtual patches must be tested against sample exploit signatures to verify non-bypassability before mitigation credit is granted.

### §3.2 Endpoint Detection and Response (EDR)
- **§3.2.1 Control (`CTL-EDR-01`):** Kernel-level behavioral monitoring, memory protection, and automated execution containment (e.g., CrowdStrike Falcon).
- **§3.2.2 Mitigation Scope:** Dampens privilege escalation and post-exploitation execution but does not block remote network-level denial of service or memory corruption.

### §3.3 Network Segmentation and Access Control
- **§3.3.1 Controls (`CTL-NET-01`, `CTL-NET-02`, `CTL-ACL-01`):** Microsegmentation firewalls, isolated VLANs/VPCs, and mutual TLS (mTLS) client certificate enforcement that restrict communication strictly to authorized callers.
- **§3.3.2 Mitigation Scope:** Prevents unauthorized lateral movement and untrusted network access to vulnerable management endpoints.

### §3.4 Container Sandboxing and Ephemeral Isolation
- **§3.4.1 Control (`CTL-SAND-01`):** Unprivileged container runtimes, read-only root filesystems, and disposable build environments torn down after execution.
- **§3.4.2 Mitigation Scope:** Constrains breakout persistence and prevents persistent host compromise.

### §3.5 Air-Gap and Physical Disconnection
- **§3.5.1 Controls (`CTL-AIR-01`, `CTL-AIR-02`):** Physical network interface disconnection, hardware optical data diodes, and hypervisor-isolated lab detonation testbeds.
- **§3.5.2 Mitigation Scope:** Eliminates remote network exploitability entirely; restricts attack vectors strictly to local physical access.

---

## 4.0 Exception Governance and Evidentiary Requirements

### §4.1 Mandatory Technical Evidence
- **§4.1.1 Required Artifacts:** Every exception request must submit:
  1. Specific finding ID (`FINDING-NNN`) and asset ID (`ASSET-NNN`).
  2. Proof of active status (`ACTIVE`) for all referenced compensating controls.
  3. Demonstration of incompatible business operational dependencies that prevent immediate patching.
  4. Proposed target remediation date.

### §4.2 Temporal Expiration Limits
- **§4.2.1 Critical Vulnerability Limits:** Exceptions granted for Critical severity vulnerabilities expire automatically after **14 calendar days** and must be re-evaluated.
- **§4.2.2 High Vulnerability Limits:** Exceptions granted for High severity vulnerabilities expire after **30 calendar days**.
- **§4.2.3 Medium/Low Limits:** Maximum exception duration is **90 calendar days**.

---

## 5.0 Approval Authorities

- **§5.1 Critical / High Exceptions on Production:** Requires joint written authorization from the Chief Information Security Officer (CISO) and the affected Asset Owner.
- **§5.2 Staging / Non-Production Exceptions:** May be approved by the Security Operations Lead and Development Team Manager.
