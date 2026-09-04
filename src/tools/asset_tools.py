"""Deterministic asset and environment context tools for Aegis Patch.

All tools in this module query enterprise CMDB, network exposure metadata,
and organizational security policies deterministically.
No live network scanners, ping, port scan, or shell commands are executed.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from src.database.engine import get_engine
from src.database.repositories.asset_repository import AssetRepository
from src.database.repositories.control_repository import ControlRepository
from src.database.repositories.policy_repository import PolicyRepository
from src.database.session import get_session
from src.schemas.asset import (
    Asset as PydanticAsset,
    AssetCriticality,
    BusinessTier,
    EnvironmentType,
    NetworkExposure,
)
from src.tools.schemas import (
    GetNetworkReachabilityInput,
    GetNetworkReachabilityOutput,
    PolicyClause,
    ProvenanceSourceType,
    QueryAssetCmdbInput,
    QueryAssetCmdbOutput,
    QueryRagPolicyInput,
    QueryRagPolicyOutput,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
)

DEFAULT_POLICIES_DIR = Path(__file__).resolve().parent.parent.parent / "data" / "policies"


def query_asset_cmdb(
    input_data: QueryAssetCmdbInput,
    session: Optional[Session] = None,
) -> QueryAssetCmdbOutput:
    """Retrieve enterprise asset context and active compensating controls.

    Uses the persisted database / repository layer to retrieve authoritative
    CMDB information for the requested asset_id.
    """
    def _execute(sess: Session) -> QueryAssetCmdbOutput:
        asset_repo = AssetRepository(sess)
        control_repo = ControlRepository(sess)

        db_asset = asset_repo.get_by_asset_id(input_data.asset_id)
        if not db_asset:
            return QueryAssetCmdbOutput(
                tool_name="query_asset_cmdb",
                status=ToolStatus.NOT_FOUND,
                message=f"Asset {input_data.asset_id} not found in enterprise CMDB.",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(
                    source="enterprise_cmdb",
                    source_type=ProvenanceSourceType.PERSISTED_DATABASE,
                ),
                asset=None,
                compensating_controls=[],
                patch_window=None,
            )

        # Retrieve active compensating controls
        active_controls = control_repo.list_active_by_asset(input_data.asset_id)
        control_codes = [c.name for c in active_controls]

        # Map to Pydantic Asset schema
        from src.schemas.asset import AssetType, CompensatingControl, ControlStatus, DataSensitivity
        asset_type_val = getattr(db_asset, "asset_type", "SERVER") or "SERVER"
        try:
            a_type = AssetType(asset_type_val)
        except Exception:
            a_type = AssetType.SERVER

        try:
            d_sens = DataSensitivity(db_asset.data_sensitivity)
        except Exception:
            d_sens = DataSensitivity.INTERNAL

        controls_list = [
            CompensatingControl(
                control_id=c.control_id,
                name=c.name,
                description=c.description or f"Active control: {c.name}",
                status=ControlStatus.ACTIVE,
            )
            for c in active_controls
        ]

        patch_win_str = None
        if db_asset.patch_window:
            if isinstance(db_asset.patch_window, dict):
                patch_win_str = f"{db_asset.patch_window.get('day_of_week')}_{db_asset.patch_window.get('start_time_utc')}"
            else:
                patch_win_str = str(db_asset.patch_window)

        pydantic_asset = PydanticAsset(
            asset_id=db_asset.asset_id,
            hostname=db_asset.hostname,
            asset_type=a_type,
            business_tier=BusinessTier(db_asset.business_tier),
            criticality=AssetCriticality(db_asset.criticality),
            network_exposure=NetworkExposure(db_asset.network_exposure),
            data_sensitivity=d_sens,
            environment=EnvironmentType(db_asset.environment),
            owner_team=db_asset.owner_team or "SecOps",
            compensating_controls=controls_list,
        )

        return QueryAssetCmdbOutput(
            tool_name="query_asset_cmdb",
            status=ToolStatus.SUCCESS,
            message=f"Retrieved CMDB record for {input_data.asset_id}.",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="enterprise_cmdb",
                source_type=ProvenanceSourceType.PERSISTED_DATABASE,
            ),
            asset=pydantic_asset,
            compensating_controls=control_codes,
            patch_window=patch_win_str,
        )

    if session is not None:
        return _execute(session)
    with get_session() as sess:
        return _execute(sess)


def get_network_reachability(
    input_data: GetNetworkReachabilityInput,
    session: Optional[Session] = None,
) -> GetNetworkReachabilityOutput:
    """Determine network reachability and ingress exposure based on CMDB topology.

    Deterministic environment metadata evaluation only.
    No live ping, port scan, or network discovery commands are run.
    """
    cmdb_result = query_asset_cmdb(QueryAssetCmdbInput(asset_id=input_data.asset_id), session=session)
    if cmdb_result.status != ToolStatus.SUCCESS or not cmdb_result.asset:
        return GetNetworkReachabilityOutput(
            tool_name="get_network_reachability",
            status=ToolStatus.NOT_FOUND,
            message=f"Cannot determine reachability: Asset {input_data.asset_id} not found.",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="cmdb_network_topology",
                source_type=ProvenanceSourceType.PERSISTED_DATABASE,
            ),
            asset_id=input_data.asset_id,
            network_exposure=NetworkExposure.INTERNAL,
            reachable_from_internet=False,
            rationale="Asset record not found in CMDB.",
        )

    asset = cmdb_result.asset
    is_external = (asset.network_exposure == NetworkExposure.INTERNET_FACING)

    rationale = (
        f"Asset {asset.asset_id} ({asset.hostname}) is classified as {asset.network_exposure.value} "
        f"in environment {asset.environment.value}. "
    )
    if is_external:
        rationale += "Direct internet ingress reachability is enabled."
    elif asset.network_exposure == NetworkExposure.DMZ:
        rationale += "Positioned in DMZ perimeter; internet ingress requires gateway proxy."
    elif asset.network_exposure == NetworkExposure.INTERNAL:
        rationale += "Internal network zone only; unreachable from internet without perimeter compromise."
    else:
        rationale += "Air-gapped isolated zone; completely decoupled from external network paths."

    return GetNetworkReachabilityOutput(
        tool_name="get_network_reachability",
        status=ToolStatus.SUCCESS,
        message=f"Determined network boundary reachability for {input_data.asset_id}.",
        side_effect=SideEffectClass.READ_ONLY,
        provenance=ToolProvenance(
            source="cmdb_network_topology",
            source_type=ProvenanceSourceType.PERSISTED_DATABASE,
            reference="data/synthetic/enterprise_cmdb.json",
        ),
        asset_id=asset.asset_id,
        network_exposure=asset.network_exposure,
        reachable_from_internet=is_external,
        rationale=rationale,
    )


def query_rag_policy(
    input_data: QueryRagPolicyInput,
    session: Optional[Session] = None,
) -> QueryRagPolicyOutput:
    """Deterministic policy lookup tool.

    Placeholder for future Phase 11 RAG.
    Does NOT use ChromaDB, embeddings, or semantic retrieval.
    Operates strictly via deterministic keyword, section, and policy ID matching
    against local policy documents.
    """
    matched: List[PolicyClause] = []
    search_term = input_data.query.strip().lower()
    policy_id_term = input_data.policy_id.strip().upper() if input_data.policy_id else None

    # Deterministic file-based search across data/policies/*.md
    if DEFAULT_POLICIES_DIR.is_dir():
        for doc_file in sorted(DEFAULT_POLICIES_DIR.glob("*.md")):
            if doc_file.name.startswith("."):
                continue
            try:
                content = doc_file.read_text(encoding="utf-8")
                # Parse policy header (ID, Title)
                lines = content.splitlines()
                pid = doc_file.stem
                title = lines[0].replace("#", "").strip() if lines else doc_file.stem

                # Check if policy matches ID directly
                id_matches = (policy_id_term and policy_id_term in pid.upper()) or (search_term in pid.lower())
                term_matches = search_term in content.lower()

                if id_matches or term_matches:
                    # Extract matched sections
                    sections = content.split("## ")
                    for sec in sections:
                        if not sec.strip():
                            continue
                        sec_lines = sec.splitlines()
                        sec_title = sec_lines[0].strip()
                        sec_body = "\n".join(sec_lines[1:]).strip()

                        if id_matches or (search_term in sec.lower()):
                            matched.append(
                                PolicyClause(
                                    policy_id=pid,
                                    title=title,
                                    section=sec_title,
                                    content=sec_body[:600],
                                    relevance_rationale=f"Deterministic match for '{input_data.query}' in section '{sec_title}'",
                                )
                            )
            except Exception:
                continue

    status = ToolStatus.SUCCESS if matched else ToolStatus.NOT_FOUND
    msg = f"Retrieved {len(matched)} policy clauses via deterministic search." if matched else f"No policy clauses matched '{input_data.query}'."

    return QueryRagPolicyOutput(
        tool_name="query_rag_policy",
        status=status,
        message=msg,
        side_effect=SideEffectClass.READ_ONLY,
        provenance=ToolProvenance(
            source="local_policy_corpus",
            source_type=ProvenanceSourceType.LOCAL_DATASET,
            reference="data/policies/",
        ),
        retrieval_mode="LOCAL_DETERMINISTIC",
        matched_policies=matched,
    )
