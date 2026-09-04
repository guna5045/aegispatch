"""Deterministic, idempotent benchmark ingestion pipeline for Aegis Patch.

Loads synthetic benchmark data (assets, compensating controls, vulnerability findings,
and policy documents) into SQLite using the Phase 5C repository layer within an atomic
transaction boundary.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field
from sqlalchemy import Engine
from sqlalchemy.orm import Session

from src.database.config import PROJECT_ROOT
from src.database.init_db import init_db
from src.database.models.asset import Asset
from src.database.models.control import SecurityControl
from src.database.models.policy import PolicyDocument
from src.database.models.vulnerability import VulnerabilityFinding
from src.database.repositories.asset_repository import AssetRepository
from src.database.repositories.control_repository import ControlRepository
from src.database.repositories.policy_repository import PolicyRepository
from src.database.repositories.threat_repository import ThreatIntelligenceRepository
from src.database.repositories.vulnerability_repository import VulnerabilityRepository
from src.database.session import get_session

logger = logging.getLogger("aegis_patch.database.ingestion")

DEFAULT_CMDB_PATH = PROJECT_ROOT / "data" / "synthetic" / "enterprise_cmdb.json"
DEFAULT_SCANS_PATH = PROJECT_ROOT / "data" / "synthetic" / "benchmark_60_scans.json"
DEFAULT_POLICIES_DIR = PROJECT_ROOT / "data" / "policies"


class IngestionSummary(BaseModel):
    """Structured audit summary of benchmark data ingestion outcomes."""

    assets_created: int = 0
    assets_updated: int = 0
    controls_created: int = 0
    controls_updated: int = 0
    findings_created: int = 0
    findings_updated: int = 0
    threat_observations_created: int = 0
    policies_created: int = 0
    policies_updated: int = 0
    skipped_records: int = 0
    errors: List[str] = Field(default_factory=list)
    total_processed: int = 0

    @property
    def total_assets(self) -> int:
        return self.assets_created + self.assets_updated

    @property
    def total_findings(self) -> int:
        return self.findings_created + self.findings_updated

    @property
    def total_controls(self) -> int:
        return self.controls_created + self.controls_updated

    @property
    def total_policies(self) -> int:
        return self.policies_created + self.policies_updated


def _resolve_path(target_path: Optional[Union[str, Path]], default_path: Path) -> Path:
    """Resolve an input path against PROJECT_ROOT if relative."""
    if target_path is None:
        return default_path
    path = Path(target_path)
    return (PROJECT_ROOT / path).resolve() if not path.is_absolute() else path.resolve()


def _parse_policy_document(file_path: Path) -> Dict[str, Any]:
    """Extract structured metadata from a synthetic organizational policy markdown document."""
    content = file_path.read_text(encoding="utf-8")

    # Extract Policy ID and Title from primary header '# POL-XXX: Title'
    m_head = re.search(r"^#\s*([A-Z0-9-]+):\s*(.+)$", content, re.MULTILINE)
    policy_id = m_head.group(1).strip() if m_head else file_path.stem.split("-")[0]
    title = m_head.group(2).strip() if m_head else file_path.stem

    # Extract Version
    m_ver = re.search(r"\*\*Version:\*\*\s*([^\s\n\r]+)", content)
    version = m_ver.group(1).strip() if m_ver else "1.0"

    # Extract Effective Date
    m_date = re.search(r"\*\*Effective Date:\*\*\s*([0-9-]+)", content)
    effective_date = None
    if m_date:
        try:
            effective_date = datetime.strptime(m_date.group(1).strip(), "%Y-%m-%d").replace(
                tzinfo=timezone.utc
            )
        except ValueError:
            effective_date = None

    # Derive policy classification type
    if "patch" in file_path.name.lower():
        policy_type = "VULNERABILITY_MANAGEMENT"
    elif "criticality" in file_path.name.lower():
        policy_type = "ASSET_CLASSIFICATION"
    elif "exception" in file_path.name.lower():
        policy_type = "EXCEPTION_GOVERNANCE"
    else:
        policy_type = "SECURITY_POLICY"

    content_hash = f"sha256:{hashlib.sha256(content.encode('utf-8')).hexdigest()}"

    return {
        "policy_id": policy_id,
        "title": title,
        "policy_type": policy_type,
        "version": version,
        "status": "ACTIVE",
        "effective_date": effective_date,
        "source_path": str(file_path.relative_to(PROJECT_ROOT))
        if file_path.is_relative_to(PROJECT_ROOT)
        else str(file_path),
        "content_hash": content_hash,
        "policy_metadata": {
            "file_name": file_path.name,
            "word_count": len(content.split()),
            "character_count": len(content),
        },
    }


def ingest_benchmark(
    session: Session,
    cmdb_path: Optional[Union[str, Path]] = None,
    scans_path: Optional[Union[str, Path]] = None,
    policies_dir: Optional[Union[str, Path]] = None,
) -> IngestionSummary:
    """Ingest synthetic benchmark fixtures into the database using repository abstractions.

    This function performs all inserts and updates via flushed repository calls, leaving
    the outer transaction boundary to the caller. If any record fails validation or violates
    constraints, the caller's session context will roll back the entire batch.

    Args:
        session: Active SQLAlchemy Session.
        cmdb_path: Optional path to enterprise_cmdb.json. Defaults to data/synthetic.
        scans_path: Optional path to benchmark_60_scans.json. Defaults to data/synthetic.
        policies_dir: Optional path to data/policies directory. Defaults to data/policies.

    Returns:
        IngestionSummary containing structured audit metrics.
    """
    resolved_cmdb = _resolve_path(cmdb_path, DEFAULT_CMDB_PATH)
    resolved_scans = _resolve_path(scans_path, DEFAULT_SCANS_PATH)
    resolved_policies = _resolve_path(policies_dir, DEFAULT_POLICIES_DIR)

    summary = IngestionSummary()

    # Repositories
    asset_repo = AssetRepository(session)
    control_repo = ControlRepository(session)
    vuln_repo = VulnerabilityRepository(session)
    policy_repo = PolicyRepository(session)
    # ThreatIntelligenceRepository is initialized to adhere to architecture,
    # but zero threat records are fabricated since benchmark represents local baseline.
    _ = ThreatIntelligenceRepository(session)

    # --------------------------------------------------------------------------
    # 1. Ingest Assets and Compensating Controls (CMDB)
    # --------------------------------------------------------------------------
    if not resolved_cmdb.exists():
        raise FileNotFoundError(f"CMDB benchmark file not found at: {resolved_cmdb}")

    try:
        with open(resolved_cmdb, "r", encoding="utf-8") as f:
            cmdb_data = json.load(f)
    except Exception as exc:
        raise ValueError(f"Malformed CMDB JSON in {resolved_cmdb}: {exc}") from exc

    if not isinstance(cmdb_data, list):
        raise ValueError(f"CMDB dataset in {resolved_cmdb} must be a JSON list of asset objects.")

    for asset_raw in cmdb_data:
        asset_id = asset_raw.get("asset_id")
        if not asset_id:
            raise ValueError("Asset record missing mandatory 'asset_id'.")

        hostname = asset_raw.get("hostname")
        if not hostname:
            raise ValueError(f"Asset {asset_id} missing mandatory 'hostname'.")

        existing_asset = asset_repo.get_by_asset_id(asset_id)
        description = asset_raw.get("metadata", {}).get("service_role", asset_raw.get("description"))

        if existing_asset is None:
            new_asset = Asset(
                asset_id=asset_id,
                hostname=hostname,
                asset_type=asset_raw["asset_type"],
                business_tier=asset_raw["business_tier"],
                criticality=asset_raw["criticality"],
                network_exposure=asset_raw["network_exposure"],
                data_sensitivity=asset_raw["data_sensitivity"],
                environment=asset_raw["environment"],
                description=description,
                owner_team=asset_raw.get("owner_team"),
                patch_window=asset_raw.get("patch_window"),
                asset_metadata=asset_raw.get("metadata"),
            )
            asset_repo.create(new_asset)
            summary.assets_created += 1
        else:
            existing_asset.hostname = hostname
            existing_asset.asset_type = asset_raw["asset_type"]
            existing_asset.business_tier = asset_raw["business_tier"]
            existing_asset.criticality = asset_raw["criticality"]
            existing_asset.network_exposure = asset_raw["network_exposure"]
            existing_asset.data_sensitivity = asset_raw["data_sensitivity"]
            existing_asset.environment = asset_raw["environment"]
            existing_asset.description = description
            existing_asset.owner_team = asset_raw.get("owner_team", existing_asset.owner_team)
            existing_asset.patch_window = asset_raw.get("patch_window", existing_asset.patch_window)
            existing_asset.asset_metadata = asset_raw.get("metadata", existing_asset.asset_metadata)
            asset_repo.update(existing_asset)
            summary.assets_updated += 1

        summary.total_processed += 1

        # Ingest Compensating Security Controls for this asset
        raw_controls = asset_raw.get("compensating_controls", [])
        existing_controls = {c.control_id: c for c in control_repo.list_by_asset(asset_id)}

        for c_data in raw_controls:
            ctrl_id = c_data.get("control_id")
            if not ctrl_id:
                continue

            ctrl_status = c_data.get("status", "ACTIVE")
            is_active = ctrl_status.upper() == "ACTIVE"

            if ctrl_id not in existing_controls:
                new_ctrl = SecurityControl(
                    control_id=ctrl_id,
                    asset_id=asset_id,
                    name=c_data.get("name", ctrl_id),
                    description=c_data.get("description", ""),
                    status=ctrl_status,
                    active=is_active,
                )
                control_repo.create(new_ctrl)
                summary.controls_created += 1
            else:
                existing_ctrl = existing_controls[ctrl_id]
                existing_ctrl.name = c_data.get("name", existing_ctrl.name)
                existing_ctrl.description = c_data.get("description", existing_ctrl.description)
                existing_ctrl.status = ctrl_status
                existing_ctrl.active = is_active
                control_repo.update(existing_ctrl)
                summary.controls_updated += 1

    # --------------------------------------------------------------------------
    # 2. Ingest Vulnerability Findings (Scans)
    # --------------------------------------------------------------------------
    if not resolved_scans.exists():
        raise FileNotFoundError(f"Scans benchmark file not found at: {resolved_scans}")

    try:
        with open(resolved_scans, "r", encoding="utf-8") as f:
            scans_data = json.load(f)
    except Exception as exc:
        raise ValueError(f"Malformed Scans JSON in {resolved_scans}: {exc}") from exc

    if not isinstance(scans_data, list):
        raise ValueError(f"Scans dataset in {resolved_scans} must be a JSON list of finding objects.")

    for finding_raw in scans_data:
        finding_id = finding_raw.get("finding_id")
        if not finding_id:
            raise ValueError("Finding record missing mandatory 'finding_id'.")

        target_asset_id = finding_raw.get("asset_id")
        if not target_asset_id:
            raise ValueError(f"Finding {finding_id} missing mandatory 'asset_id'.")

        # Validate that the referenced asset exists
        parent_asset = asset_repo.get_by_asset_id(target_asset_id)
        if parent_asset is None:
            raise ValueError(
                f"Foreign key constraint violation: Finding '{finding_id}' references unknown asset '{target_asset_id}'."
            )

        existing_finding = vuln_repo.get_by_finding_id(finding_id)
        cvss_val = float(finding_raw["cvss_score"])

        if existing_finding is None:
            new_finding = VulnerabilityFinding(
                finding_id=finding_id,
                cve_id=finding_raw["cve_id"],
                title=finding_raw["title"],
                description=finding_raw["description"],
                cvss_score=cvss_val,
                severity=finding_raw["severity"],
                affected_package=finding_raw["affected_package"],
                installed_version=finding_raw["installed_version"],
                fixed_version=finding_raw.get("fixed_version"),
                asset_id=target_asset_id,
                source=finding_raw.get("source", "synthetic_benchmark"),
                status="OPEN",
                references_data=finding_raw.get("references"),
                raw_evidence=finding_raw.get("raw_evidence"),
            )
            vuln_repo.create(new_finding)
            summary.findings_created += 1
        else:
            existing_finding.cve_id = finding_raw["cve_id"]
            existing_finding.title = finding_raw["title"]
            existing_finding.description = finding_raw["description"]
            existing_finding.cvss_score = cvss_val
            existing_finding.severity = finding_raw["severity"]
            existing_finding.affected_package = finding_raw["affected_package"]
            existing_finding.installed_version = finding_raw["installed_version"]
            existing_finding.fixed_version = finding_raw.get("fixed_version", existing_finding.fixed_version)
            existing_finding.asset_id = target_asset_id
            existing_finding.source = finding_raw.get("source", existing_finding.source)
            existing_finding.references_data = finding_raw.get("references", existing_finding.references_data)
            existing_finding.raw_evidence = finding_raw.get("raw_evidence", existing_finding.raw_evidence)
            vuln_repo.update(existing_finding)
            summary.findings_updated += 1

        summary.total_processed += 1

    # --------------------------------------------------------------------------
    # 3. Ingest Policy Documents
    # --------------------------------------------------------------------------
    if resolved_policies.exists() and resolved_policies.is_dir():
        policy_files = sorted(
            [p for p in resolved_policies.glob("*.md") if p.is_file() and not p.name.startswith(".")]
        )
        for p_file in policy_files:
            p_data = _parse_policy_document(p_file)
            pol_id = p_data["policy_id"]
            existing_pol = policy_repo.get_by_policy_id(pol_id)

            if existing_pol is None:
                new_pol = PolicyDocument(
                    policy_id=pol_id,
                    title=p_data["title"],
                    policy_type=p_data["policy_type"],
                    version=p_data["version"],
                    status=p_data["status"],
                    effective_date=p_data["effective_date"],
                    source_path=p_data["source_path"],
                    content_hash=p_data["content_hash"],
                    policy_metadata=p_data["policy_metadata"],
                )
                policy_repo.create(new_pol)
                summary.policies_created += 1
            else:
                existing_pol.title = p_data["title"]
                existing_pol.policy_type = p_data["policy_type"]
                existing_pol.version = p_data["version"]
                existing_pol.status = p_data["status"]
                existing_pol.effective_date = p_data["effective_date"]
                existing_pol.source_path = p_data["source_path"]
                existing_pol.content_hash = p_data["content_hash"]
                existing_pol.policy_metadata = p_data["policy_metadata"]
                policy_repo.update(existing_pol)
                summary.policies_updated += 1

            summary.total_processed += 1

    # Note on Threat Intelligence / Risk Assessments / Patch Plans:
    # Intentionally ZERO threat observations fabricated (benchmark represents local data).
    # Intentionally ZERO risk assessments or patch plans created (calculated in later phases).
    summary.threat_observations_created = 0

    logger.info(
        f"Benchmark ingestion complete: {summary.total_assets} assets ({summary.assets_created} new), "
        f"{summary.total_findings} findings ({summary.findings_created} new), "
        f"{summary.total_controls} controls ({summary.controls_created} new), "
        f"{summary.total_policies} policies ({summary.policies_created} new)."
    )

    return summary


def run_benchmark_ingestion(
    engine: Optional[Engine] = None,
    cmdb_path: Optional[Union[str, Path]] = None,
    scans_path: Optional[Union[str, Path]] = None,
    policies_dir: Optional[Union[str, Path]] = None,
) -> IngestionSummary:
    """Initialize schema and execute benchmark ingestion within an atomic transaction.

    Automatically commits on successful completion, and rolls back all changes
    if any exception occurs.
    """
    # Ensure database tables exist
    init_db(engine=engine)

    # Execute inside transaction scope
    with get_session(engine=engine) as session:
        return ingest_benchmark(
            session=session,
            cmdb_path=cmdb_path,
            scans_path=scans_path,
            policies_dir=policies_dir,
        )
