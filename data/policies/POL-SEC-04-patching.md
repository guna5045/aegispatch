# POL-SEC-04: Enterprise Vulnerability Remediation and Patch Management Policy

> **Document Type:** Synthetic Organizational Policy — AegisPatch Benchmark  
> **Policy Identifier:** `POL-SEC-04`  
> **Effective Date:** 2026-01-01  
> **Version:** 2.4  
> **Notice:** This document is a synthetic benchmark artifact created strictly for evaluating context-driven vulnerability prioritization in the AegisPatch project. It does not represent authoritative government or corporate standards.

---

## 1.0 Purpose and Scope

### §1.1 Objective
This policy establishes mandatory operational timelines, architectural criteria, and governance procedures for remediating security vulnerabilities identified across enterprise infrastructure and software assets.

### §1.2 Scope
This policy applies to all systems, cloud workloads, on-premise hardware, network appliances, and software packages cataloged within the enterprise CMDB.

---

## 2.0 Vulnerability Remediation Service Level Agreements (SLAs)

Remediation timelines are determined by the composite environmental risk and deployment tier of the affected asset.

### §2.1 Critical Severity Vulnerabilities
- **§2.1.1 Internet-Facing / Mission-Critical Production:** Critical vulnerabilities (CVSS base score $\ge 9.0$) identified on Internet-facing or Mission-Critical assets must be remediated or mitigated within **48 hours** of identification.
- **§2.1.2 Internal Production Workloads:** Critical vulnerabilities on internal production assets must be remediated within **7 calendar days**.
- **§2.1.3 Non-Production Systems:** Critical vulnerabilities on staging, development, or testing assets must be remediated within **14 calendar days**.

### §2.2 High Severity Vulnerabilities
- **§2.2.1 Production Assets:** High severity vulnerabilities (CVSS base score $7.0 - 8.9$) affecting production infrastructure must be remediated within **7 calendar days** if Internet-facing, and within **14 calendar days** if internal.
- **§2.2.2 Non-Production Systems:** High severity vulnerabilities on staging and development systems must be remediated within **30 calendar days**.

### §2.3 Medium Severity Vulnerabilities
- **§2.3.1 All Environments:** Medium severity vulnerabilities (CVSS base score $4.0 - 6.9$) must be remediated within **30 calendar days** on production systems and within **60 calendar days** on non-production systems.

### §2.4 Low Severity Vulnerabilities
- **§2.4.1 All Environments:** Low severity vulnerabilities (CVSS base score $< 4.0$) should be addressed during routine maintenance cycles or within **90 calendar days**, unless compensating controls render remediation unnecessary.

---

## 3.0 Exploitation Escalators and Threat Accelerators

### §3.1 Active Exploitation Escalation
- **§3.1.1 CISA KEV or Weaponized Exploits:** Any vulnerability confirmed to have active exploitation in the wild (such as inclusion in the CISA Known Exploited Vulnerabilities catalog or verified public weaponized exploit kits with high EPSS probability) escalates immediately to **Emergency Out-of-Band Remediation** regardless of its original base score, requiring remediation within **24 hours** on Internet-facing assets.
- **§3.1.2 Theoretical vs. Active Exposure:** Vulnerabilities lacking public exploit tooling or proof-of-concept demonstrations may follow standard maintenance cycles if approved by the security lead.

### §3.2 Air-Gapped and Isolated Systems
- **§3.2.1 Air-Gap De-escalation:** Vulnerabilities on confirmed air-gapped systems (`AIR_GAPPED`) do not require out-of-band emergency patching unless a physical or multi-stage pivot vector is demonstrated. Remediation may occur during standard quarterly maintenance cycles.

---

## 4.0 Change Execution and Maintenance Windows

### §4.1 Emergency Out-of-Band Changes
- **§4.1.1 Authorization:** Emergency out-of-band patches may only be deployed outside an authorized maintenance window when approved by the Chief Information Security Officer (CISO) or designated incident commander.
- **§4.1.2 Notification:** Affected operational teams must receive at least 2 hours advance notice before emergency service restarts.

### §4.2 Standard Maintenance Window Adherence
- **§4.2.1 Window Alignment:** Standard patch deployments must strictly execute within the designated asset `PatchWindow` specified in the enterprise CMDB.
- **§4.2.2 Capacity Constraints:** The cumulative engineering effort for scheduled patch batches must not exceed the approved maintenance window capacity limit (default benchmark capacity: **16.0 engineering hours**).

---

## 5.0 Testing, Verification, and Rollback Requirements

### §5.1 Pre-Deployment Testing
- **§5.1.1 Staging Verification:** All patches must be verified in a representative staging (`STAGING`) or testing (`TESTING`) environment prior to production rollout, unless an active zero-day exploit requires immediate emergency deployment.

### §5.2 Mandatory Rollback Plan
- **§5.2.1 Rollback Documentation:** Every patch deployment plan must include an explicit, actionable `RollbackPlan` detailing recovery procedures, configuration backup validation, and estimated recovery duration in minutes.
- **§5.2.2 Rollback Threshold:** If a patch deployment causes unanticipated service degradation exceeding 15 minutes, automated or procedural rollback must be initiated immediately.

---

## 6.0 Policy Exceptions and Deferrals

### §6.1 Exception Mandate
- **§6.1.1 Formal Filing:** In the event that a patch cannot be deployed within the stipulated SLA due to software incompatibility, operational moratorium, or vendor patch unavailability, a formal exception must be filed under **`POL-SEC-12`** (Compensating Controls and Exception Governance Policy).
