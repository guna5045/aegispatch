# POL-IT-09: Enterprise Asset Classification and Operational Criticality Policy

> **Document Type:** Synthetic Organizational Policy — AegisPatch Benchmark  
> **Policy Identifier:** `POL-IT-09`  
> **Effective Date:** 2026-01-01  
> **Version:** 3.1  
> **Notice:** This document is a synthetic benchmark artifact created strictly for evaluating context-driven vulnerability prioritization in the AegisPatch project. It does not represent authoritative government or corporate standards.

---

## 1.0 Purpose and Scope

### §1.1 Purpose
This policy establishes standard definitions for categorizing computing assets across enterprise business tiers, network boundary exposures, and data sensitivity levels. These classifications provide the deterministic environmental weighting used in contextual risk assessments.

### §1.2 Scope
All physical servers, virtual machines, cloud instances, container hosts, database engines, and network appliances cataloged within the enterprise CMDB must be assigned explicit ratings adhering to this policy.

---

## 2.0 Business Tier and Operational Criticality Framework

The enterprise categorizes assets into four discrete business priority tiers reflecting service criticality and business impact.

### §2.1 Mission Critical (`MISSION_CRITICAL`)
- **§2.1.1 Definition:** Systems whose interruption causes immediate financial loss, severe regulatory penalties, compromise of core identity/authentication, or catastrophic reputational damage.
- **§2.1.2 Service Thresholds:** Maximum Tolerable Downtime (MTD) $< 1\text{ hour}$. Recovery Time Objective (RTO) $< 15\text{ minutes}$.
- **§2.1.3 Examples:** Payment processing engines, core customer OAuth2 identity providers, customer primary relational databases, immutable disaster recovery backup vaults.
- **§2.1.4 Inherent Criticality Rating:** Must be designated as `CRITICAL` or `HIGH`.

### §2.2 Business Critical (`BUSINESS_CRITICAL`)
- **§2.2.1 Definition:** Systems essential to primary business operations, order processing, customer self-service portals, supply chain pipelines, or corporate network ingress.
- **§2.2.2 Service Thresholds:** Maximum Tolerable Downtime (MTD) $< 8\text{ hours}$. RTO $< 2\text{ hours}$.
- **§2.2.3 Examples:** Enterprise Kafka event buses, order fulfillment orchestrators, customer web portals, centralized SIEM collectors, corporate remote access VPN gateways.
- **§2.2.4 Inherent Criticality Rating:** Typically designated as `HIGH`.

### §2.3 Internal Operational (`INTERNAL_OPERATIONAL`)
- **§2.3.1 Definition:** Supporting services, continuous integration build runners, business intelligence analytics clusters, and pre-production staging infrastructure.
- **§2.3.2 Service Thresholds:** Maximum Tolerable Downtime (MTD) $< 48\text{ hours}$. RTO $< 8\text{ hours}$.
- **§2.3.3 Examples:** Staging API gateways, staging payment sandboxes, OLAP analytical warehouses, CI/CD Kubernetes build agents.
- **§2.3.4 Inherent Criticality Rating:** Typically designated as `MEDIUM`.

### §2.4 Non-Critical (`NON_CRITICAL`)
- **§2.4.1 Definition:** Systems whose unavailability causes negligible disruption to enterprise business operations, including internal documentation tools, developer sandboxes, QA automated runners, and security detonation labs.
- **§2.4.2 Service Thresholds:** Maximum Tolerable Downtime (MTD) $> 7\text{ days}$. RTO best-effort.
- **§2.4.3 Examples:** Internal employee knowledge bases, ephemeral Docker developer sandboxes, Playwright QA regression nodes, isolated exploit research labs.
- **§2.4.4 Inherent Criticality Rating:** Designated as `LOW`.

---

## 3.0 Network Exposure Zones

Network accessibility directly dictates the reachability of a vulnerable component from untrusted threat actors.

### §3.1 Internet Facing (`INTERNET_FACING`)
- **§3.1.1 Boundary Definition:** Any system possessing a public IP address, direct Internet gateway ingress route, or reverse-proxy endpoint directly routable from the public Internet.
- **§3.1.2 Exposure Weight:** Maximum exposure factor; vulnerable services are subject to continuous automated scanning and unauthenticated probing.

### §3.2 Perimeter Demilitarized Zone (`DMZ`)
- **§3.2.1 Boundary Definition:** Screened subnets positioned between the external Internet boundary and internal corporate trust zones, hosting proxy services and ingress filters.
- **§3.2.2 Exposure Weight:** High exposure factor; shielded by boundary firewalls but exposed to external connection terminations.

### §3.3 Internal Network (`INTERNAL`)
- **§3.3.1 Boundary Definition:** Systems located strictly within private enterprise subnets (RFC 1918), reachable only from authenticated corporate network segments or VPN tunnels.
- **§3.3.2 Exposure Weight:** Moderate exposure factor; attack requires pre-existing perimeter breach or compromised internal workstation.

### §3.4 Air-Gapped Enclave (`AIR_GAPPED`)
- **§3.4.1 Boundary Definition:** Computing assets with zero routable physical or logical interfaces connecting to internal or external networks. Data transfer is restricted to optical data diodes or physical offline media.
- **§3.4.2 Exposure Weight:** Minimal exposure factor; unexploitable via remote network vectors.

---

## 4.0 Data Sensitivity Classifications

### §4.1 Restricted (`RESTRICTED`)
- **§4.1.1 Definition:** Highly sensitive regulated data including Payment Card Industry (PCI) primary account numbers, customer authentication credentials, session tokens, cryptographic private keys, and immutable financial records.
- **§4.1.2 Security Requirements:** Mandatory encryption at rest and in transit, strict access control, and zero unauthenticated network exposure.

### §4.2 Confidential (`CONFIDENTIAL`)
- **§4.2.1 Definition:** Proprietary corporate business information, customer account metadata, order fulfillment records, and business intelligence analytical models.
- **§4.2.2 Security Requirements:** Access restricted to authorized employees on a need-to-know basis.

### §4.3 Internal (`INTERNAL`)
- **§4.3.1 Definition:** Internal operational documentation, system logs, non-sensitive infrastructure telemetry, and developer source code without embedded credentials.
- **§4.3.2 Security Requirements:** Shielded from public disclosure; default access granted to authenticated enterprise staff.

### §4.4 Public (`PUBLIC`)
- **§4.4.1 Definition:** Information explicitly approved for public release, open-source packages, documentation wiki pages, and synthetic or scrubbed testing datasets.
- **§4.4.2 Security Requirements:** Integrity verification; confidentiality controls not required.

---

## 5.0 Environment Lifecycle Classifications

Every enterprise asset resides in exactly one deployment lifecycle environment:
- **§5.1 Production (`PRODUCTION`):** Live customer-serving and core corporate operational workloads.
- **§5.2 Staging (`STAGING`):** Production-mirror environments used for pre-release validation and integration testing.
- **§5.3 Development (`DEVELOPMENT`):** Workstation and sandbox environments for code authoring and feature prototyping.
- **§5.4 Testing (`TESTING`):** Automated regression environments, QA runners, and ephemeral security testing testbeds.
