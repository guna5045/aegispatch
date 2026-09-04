"""Persistence service providing a clean integration layer for database operations.

Bridges the Phase 5 SQLAlchemy repositories and ingestion pipeline with
application workflows (FastAPI in Phase 6, risk engine results persistence,
and patch plan persistence).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Union

from sqlalchemy import Engine
from sqlalchemy.orm import Session

from src.database.engine import get_engine
from src.database.init_db import check_db_health, init_db
from src.database.ingestion.benchmark_ingestion import (
    IngestionSummary,
    ingest_benchmark,
)
from src.database.models.asset import Asset
from src.database.models.control import SecurityControl
from src.database.models.patch_plan import PatchPlan, PatchPlanItem
from src.database.models.policy import PolicyDocument
from src.database.models.risk import RiskAssessment
from src.database.models.threat import ThreatIntelligenceObservation
from src.database.models.vulnerability import VulnerabilityFinding
from src.database.repositories.asset_repository import AssetRepository
from src.database.repositories.control_repository import ControlRepository
from src.database.repositories.patch_plan_repository import PatchPlanRepository
from src.database.repositories.policy_repository import PolicyRepository
from src.database.repositories.risk_repository import RiskAssessmentRepository
from src.database.repositories.threat_repository import ThreatIntelligenceRepository
from src.database.repositories.vulnerability_repository import VulnerabilityRepository
from src.schemas.risk import RiskAssessment as PydanticRiskAssessment

logger = logging.getLogger("aegis_patch.services.persistence")


class PersistenceService:
    """Service layer coordinating database operations through repositories."""

    @staticmethod
    def initialize_database(
        engine: Optional[Engine] = None, database_url: Optional[str] = None
    ) -> None:
        """Initialize database schema idempotently."""
        init_db(engine=engine, database_url=database_url)

    @staticmethod
    def check_health(engine: Optional[Engine] = None) -> bool:
        """Perform database connectivity check."""
        return check_db_health(engine=engine)

    @staticmethod
    def ingest_benchmark_dataset(
        session: Session,
        cmdb_path: Optional[Any] = None,
        scans_path: Optional[Any] = None,
        policies_dir: Optional[Any] = None,
    ) -> IngestionSummary:
        """Execute deterministic benchmark ingestion pipeline within caller's session."""
        return ingest_benchmark(
            session=session,
            cmdb_path=cmdb_path,
            scans_path=scans_path,
            policies_dir=policies_dir,
        )

    # ------------------------------------------------------------------
    # Assets & Controls
    # ------------------------------------------------------------------

    @staticmethod
    def list_assets(session: Session) -> List[Asset]:
        """Retrieve all enterprise assets ordered by asset_id."""
        return AssetRepository(session).list_all()

    @staticmethod
    def get_asset(session: Session, asset_id: str) -> Optional[Asset]:
        """Retrieve an asset by its unique domain identifier."""
        return AssetRepository(session).get_by_asset_id(asset_id)

    @staticmethod
    def filter_assets(
        session: Session,
        environment: Optional[str] = None,
        criticality: Optional[str] = None,
        network_exposure: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[List[Asset], int]:
        """Query and paginate enterprise assets with optional filtering."""
        offset = (page - 1) * page_size
        return AssetRepository(session).filter_and_paginate(
            environment=environment,
            criticality=criticality,
            network_exposure=network_exposure,
            offset=offset,
            limit=page_size,
        )

    @staticmethod
    def list_controls_for_asset(session: Session, asset_id: str) -> List[SecurityControl]:
        """List active compensating security controls protecting an asset."""
        return ControlRepository(session).list_by_asset(asset_id)

    # ------------------------------------------------------------------
    # Vulnerabilities
    # ------------------------------------------------------------------

    @staticmethod
    def list_findings(session: Session) -> List[VulnerabilityFinding]:
        """Retrieve all vulnerability scan findings ordered by finding_id."""
        return VulnerabilityRepository(session).list_all()

    @staticmethod
    def get_finding(session: Session, finding_id: str) -> Optional[VulnerabilityFinding]:
        """Retrieve a vulnerability finding by its unique domain identifier."""
        return VulnerabilityRepository(session).get_by_finding_id(finding_id)

    @staticmethod
    def list_findings_for_asset(session: Session, asset_id: str) -> List[VulnerabilityFinding]:
        """Retrieve all vulnerability findings affecting a specific asset."""
        return VulnerabilityRepository(session).list_by_asset(asset_id)

    @staticmethod
    def filter_findings(
        session: Session,
        query: Optional[str] = None,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        asset_id: Optional[str] = None,
        cve_id: Optional[str] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> tuple[List[VulnerabilityFinding], int]:
        """Search and paginate vulnerability scan findings."""
        offset = (page - 1) * page_size
        return VulnerabilityRepository(session).search_and_paginate(
            query=query,
            severity=severity,
            status=status,
            asset_id=asset_id,
            cve_id=cve_id,
            offset=offset,
            limit=page_size,
        )

    # ------------------------------------------------------------------
    # Policies
    # ------------------------------------------------------------------

    @staticmethod
    def list_policies(session: Session) -> List[PolicyDocument]:
        """Retrieve all ingested organizational security policy documents."""
        return PolicyRepository(session).list_all()

    @staticmethod
    def get_policy(session: Session, policy_id: str) -> Optional[PolicyDocument]:
        """Retrieve a policy document by its domain policy_id."""
        return PolicyRepository(session).get_by_policy_id(policy_id)

    @staticmethod
    def filter_policies(
        session: Session,
        status: Optional[str] = None,
        policy_type: Optional[str] = None,
    ) -> List[PolicyDocument]:
        """Filter policy documents by lifecycle status or category."""
        return PolicyRepository(session).filter_policies(status=status, policy_type=policy_type)

    # ------------------------------------------------------------------
    # Threat Intelligence (Offline / Stored Only)
    # ------------------------------------------------------------------

    @staticmethod
    def get_threat_observations_for_cve(
        session: Session, cve_id: str
    ) -> List[ThreatIntelligenceObservation]:
        """List stored offline threat intelligence observations for a CVE."""
        return ThreatIntelligenceRepository(session).list_by_cve(cve_id)

    # ------------------------------------------------------------------
    # Risk Assessments (Reusing Phase 3 Deterministic Engine Results)
    # ------------------------------------------------------------------

    @staticmethod
    def save_risk_assessment(
        session: Session,
        assessment: Union[RiskAssessment, PydanticRiskAssessment, Dict[str, Any]],
    ) -> RiskAssessment:
        """Persist a computed contextual risk assessment through RiskAssessmentRepository.

        Accepts either an ORM RiskAssessment instance, a Phase 1/3 Pydantic
        RiskAssessment schema object, or a structured dictionary.
        Does NOT recalculate risk; strictly persists the evaluation results.
        """
        repo = RiskAssessmentRepository(session)

        if isinstance(assessment, RiskAssessment):
            return repo.create(assessment)

        if isinstance(assessment, PydanticRiskAssessment):
            meta = assessment.calculation_metadata or {}
            base_score = float(meta.get("base_score", assessment.cvss_score))
            threat_score = float(meta.get("threat_score", 0.0))
            env_score = float(meta.get("environmental_score", 0.0))
            raw_risk = float(meta.get("weighted_risk", assessment.environmental_risk_score))
            ctrl_mult = float(meta.get("control_multiplier", 1.0))
            remediation_dec = meta.get("remediation_decision") or (
                assessment.decision.value if hasattr(assessment.decision, "value") else str(assessment.decision)
            )

            orm_entity = RiskAssessment(
                assessment_id=assessment.assessment_id,
                finding_id=assessment.finding_id,
                cve_id=assessment.cve_id,
                asset_id=assessment.asset_id,
                base_score=base_score,
                threat_score=threat_score,
                environmental_score=env_score,
                raw_risk_score=raw_risk,
                control_multiplier=ctrl_mult,
                environmental_risk_score=assessment.environmental_risk_score,
                risk_tier=assessment.risk_tier.value if hasattr(assessment.risk_tier, "value") else str(assessment.risk_tier),
                decision=assessment.decision.value if hasattr(assessment.decision, "value") else str(assessment.decision),
                remediation_decision=remediation_dec,
                explanation=assessment.explanation,
                supporting_evidence=assessment.supporting_evidence,
                calculation_metadata=meta,
                engine_version=meta.get("engine", "aegis_ers_deterministic_v1"),
                assessed_at=assessment.assessed_at,
            )
            return repo.create(orm_entity)

        if isinstance(assessment, dict):
            orm_entity = RiskAssessment(
                assessment_id=assessment["assessment_id"],
                finding_id=assessment["finding_id"],
                cve_id=assessment["cve_id"],
                asset_id=assessment["asset_id"],
                base_score=float(assessment.get("base_score", 0.0)),
                threat_score=float(assessment.get("threat_score", 0.0)),
                environmental_score=float(assessment.get("environmental_score", 0.0)),
                raw_risk_score=float(assessment.get("raw_risk_score", 0.0)),
                control_multiplier=float(assessment.get("control_multiplier", 1.0)),
                environmental_risk_score=float(assessment["environmental_risk_score"]),
                risk_tier=str(assessment["risk_tier"]),
                decision=str(assessment["decision"]),
                remediation_decision=assessment.get("remediation_decision"),
                explanation=assessment.get("explanation", ""),
                supporting_evidence=assessment.get("supporting_evidence"),
                calculation_metadata=assessment.get("calculation_metadata"),
                engine_version=assessment.get("engine_version", "1.0.0"),
                assessed_at=assessment.get("assessed_at"),
            )
            return repo.create(orm_entity)

        raise TypeError(f"Unsupported assessment type: {type(assessment)}")

    @staticmethod
    def list_risk_assessments_for_finding(
        session: Session, finding_id: str
    ) -> List[RiskAssessment]:
        """List historical risk assessments for a vulnerability finding (newest first)."""
        return RiskAssessmentRepository(session).list_by_finding(finding_id)

    @staticmethod
    def get_latest_risk_assessment(
        session: Session, finding_id: str
    ) -> Optional[RiskAssessment]:
        """Retrieve the most recent computed risk assessment for a finding."""
        return RiskAssessmentRepository(session).get_latest_for_finding(finding_id)

    @staticmethod
    def filter_highest_risks(
        session: Session,
        decision: Optional[str] = None,
        risk_tier: Optional[str] = None,
        limit: int = 10,
    ) -> List[RiskAssessment]:
        """List highest risk assessments ordered by ERS descending."""
        return RiskAssessmentRepository(session).filter_highest_risk(
            decision=decision,
            risk_tier=risk_tier,
            limit=limit,
        )

    # ------------------------------------------------------------------
    # Patch Remediation Plans
    # ------------------------------------------------------------------

    @staticmethod
    def save_patch_plan(
        session: Session,
        plan: PatchPlan,
        items: Optional[List[PatchPlanItem]] = None,
    ) -> PatchPlan:
        """Persist a patch remediation plan and its scheduled items through PatchPlanRepository."""
        repo = PatchPlanRepository(session)
        created_plan = repo.create(plan)
        if items:
            for item in items:
                item.patch_plan_id = created_plan.plan_id
                repo.add_item(item)
        return repo.get_plan_with_items(created_plan.plan_id) or created_plan

    @staticmethod
    def create_patch_plan(
        session: Session,
        plan: PatchPlan,
    ) -> PatchPlan:
        """Create a patch plan and commit the transaction boundary."""
        repo = PatchPlanRepository(session)
        created = repo.create(plan)
        session.commit()
        session.refresh(created)
        return created

    @staticmethod
    def add_item_to_patch_plan(
        session: Session,
        item: PatchPlanItem,
    ) -> PatchPlanItem:
        """Add a scheduled item to an existing patch plan and commit the transaction boundary."""
        repo = PatchPlanRepository(session)
        created = repo.add_item(item)
        session.commit()
        session.refresh(created)
        return created

    @staticmethod
    def update_patch_plan(
        session: Session,
        plan: PatchPlan,
    ) -> PatchPlan:
        """Update an existing plan and commit the transaction boundary."""
        repo = PatchPlanRepository(session)
        updated = repo.update(plan)
        session.commit()
        session.refresh(updated)
        return updated

    @staticmethod
    def get_patch_plan(session: Session, plan_id: str) -> Optional[PatchPlan]:
        """Retrieve a patch remediation plan with items eagerly loaded."""
        return PatchPlanRepository(session).get_plan_with_items(plan_id)

    @staticmethod
    def list_patch_plans(session: Session) -> List[PatchPlan]:
        """List all remediation plans."""
        return PatchPlanRepository(session).list_all()
