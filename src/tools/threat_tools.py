"""Deterministic Threat Intelligence tools for Aegis Patch.

All queries are executed against local datasets and SQLite caches only.
Phase 7 guarantees:
- Zero live external network calls (no CISA API, no EPSS API, no OSV API).
- Zero fabricated telemetry: if not present locally, returns NOT_AVAILABLE or NOT_FOUND with explicit provenance.
- Deterministic behavior and typed outputs.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from sqlalchemy.orm import Session

from src.database.engine import get_engine
from src.database.repositories.threat_repository import ThreatIntelligenceRepository
from src.database.session import get_session
from src.tools.schemas import (
    LookupCisaKevInput,
    LookupCisaKevOutput,
    ProvenanceSourceType,
    QueryEpssInput,
    QueryEpssOutput,
    QueryOsvDatabaseInput,
    QueryOsvDatabaseOutput,
    SideEffectClass,
    ToolProvenance,
    ToolStatus,
)


def lookup_cisa_kev(
    input_data: LookupCisaKevInput,
    session: Optional[Session] = None,
) -> LookupCisaKevOutput:
    """Look up whether a CVE is present in the local CISA KEV dataset/cache.

    Does NOT call live CISA API. Uses local repository.
    Distinguishes:
    - FOUND: CVE is present and verified in local dataset
    - NOT_FOUND: Local dataset was queried and CVE is not present
    - NOT_AVAILABLE: Local dataset or cache is unavailable
    """
    def _execute(sess: Session) -> LookupCisaKevOutput:
        repo = ThreatIntelligenceRepository(sess)
        obs_list = repo.list_by_cve(input_data.cve_id)
        if not obs_list:
            # Check if any threat intelligence exists in the database at all
            all_obs = repo.list_by_source("CISA KEV")
            if not all_obs:
                # Also check benchmark observations
                bench_obs = repo.list_by_source("synthetic_benchmark")
                if not bench_obs:
                    return LookupCisaKevOutput(
                        tool_name="lookup_cisa_kev",
                        status=ToolStatus.NOT_AVAILABLE,
                        message="Local CISA KEV dataset/cache is not available.",
                        side_effect=SideEffectClass.READ_ONLY,
                        provenance=ToolProvenance(
                            source="cisa_kev_local_mirror",
                            source_type=ProvenanceSourceType.LOCAL_DATASET,
                            reference="data/synthetic/benchmark_60_scans.json",
                        ),
                        cve_id=input_data.cve_id,
                        is_known_exploited=False,
                    )

            return LookupCisaKevOutput(
                tool_name="lookup_cisa_kev",
                status=ToolStatus.NOT_FOUND,
                message=f"CVE {input_data.cve_id} was not found in local CISA KEV catalog.",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(
                    source="cisa_kev_local_mirror",
                    source_type=ProvenanceSourceType.LOCAL_DATASET,
                ),
                cve_id=input_data.cve_id,
                is_known_exploited=False,
            )

        # Check if any observation marks KEV
        for obs in obs_list:
            if obs.is_cisa_kev:
                date_added_str = obs.cisa_kev_date_added.isoformat() if obs.cisa_kev_date_added else None
                due_date_str = obs.cisa_kev_due_date.isoformat() if obs.cisa_kev_due_date else None
                return LookupCisaKevOutput(
                    tool_name="lookup_cisa_kev",
                    status=ToolStatus.SUCCESS,
                    message=f"CVE {input_data.cve_id} is confirmed in local CISA KEV catalog.",
                    side_effect=SideEffectClass.READ_ONLY,
                    provenance=ToolProvenance(
                        source=obs.source or "cisa_kev_local_mirror",
                        source_type=ProvenanceSourceType.LOCAL_DATASET,
                        observed_at=obs.observed_at,
                    ),
                    cve_id=input_data.cve_id,
                    is_known_exploited=True,
                    date_added=date_added_str,
                    due_date=due_date_str,
                    notes=obs.notes,
                )

        return LookupCisaKevOutput(
            tool_name="lookup_cisa_kev",
            status=ToolStatus.SUCCESS,
            message=f"CVE {input_data.cve_id} is present in local threat intelligence but NOT listed in CISA KEV.",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="cisa_kev_local_mirror",
                source_type=ProvenanceSourceType.LOCAL_DATASET,
            ),
            cve_id=input_data.cve_id,
            is_known_exploited=False,
        )

    if session is not None:
        return _execute(session)
    try:
        with get_session() as sess:
            return _execute(sess)
    except Exception as err:
        return LookupCisaKevOutput(
            tool_name="lookup_cisa_kev",
            status=ToolStatus.NOT_AVAILABLE,
            message=f"Local CISA KEV dataset unavailable: {err}",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="cisa_kev_local_mirror",
                source_type=ProvenanceSourceType.LOCAL_DATASET,
            ),
            cve_id=input_data.cve_id,
            is_known_exploited=False,
        )


def query_epss(
    input_data: QueryEpssInput,
    session: Optional[Session] = None,
) -> QueryEpssOutput:
    """Retrieve EPSS telemetry from local database/cache.

    Does NOT call live FIRST EPSS API.
    Validates 0.0 <= epss_score <= 1.0. Returns NOT_AVAILABLE if absent.
    """
    def _execute(sess: Session) -> QueryEpssOutput:
        repo = ThreatIntelligenceRepository(sess)
        obs = repo.get_latest_for_cve(input_data.cve_id)
        if not obs or obs.epss_score is None:
            return QueryEpssOutput(
                tool_name="query_epss",
                status=ToolStatus.NOT_AVAILABLE,
                message=f"No local EPSS telemetry available for {input_data.cve_id}.",
                side_effect=SideEffectClass.READ_ONLY,
                provenance=ToolProvenance(
                    source="first_epss_local_cache",
                    source_type=ProvenanceSourceType.LOCAL_CACHE,
                ),
                cve_id=input_data.cve_id,
                epss_score=None,
                percentile=None,
                observed_at=None,
            )

        return QueryEpssOutput(
            tool_name="query_epss",
            status=ToolStatus.SUCCESS,
            message=f"Retrieved local EPSS telemetry for {input_data.cve_id}.",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source=obs.source or "first_epss_local_cache",
                source_type=ProvenanceSourceType.LOCAL_CACHE,
                observed_at=obs.observed_at,
            ),
            cve_id=input_data.cve_id,
            epss_score=obs.epss_score,
            percentile=obs.epss_percentile,
            observed_at=obs.observed_at,
        )

    if session is not None:
        return _execute(session)
    try:
        with get_session() as sess:
            return _execute(sess)
    except Exception as err:
        return QueryEpssOutput(
            tool_name="query_epss",
            status=ToolStatus.NOT_AVAILABLE,
            message=f"Local EPSS database unavailable: {err}",
            side_effect=SideEffectClass.READ_ONLY,
            provenance=ToolProvenance(
                source="first_epss_local_cache",
                source_type=ProvenanceSourceType.LOCAL_CACHE,
            ),
            cve_id=input_data.cve_id,
            epss_score=None,
            percentile=None,
            observed_at=None,
        )


def query_osv_database(
    input_data: QueryOsvDatabaseInput,
    session: Optional[Session] = None,
) -> QueryOsvDatabaseOutput:
    """Retrieve package advisory information from a local OSV dataset/cache.

    Does NOT connect to live OSV API.
    If no local OSV database is provisioned, returns NOT_AVAILABLE.
    """
    # Aegis Patch Phase 7 maintains an offline architecture without an external OSV mirror.
    # Returns structured NOT_AVAILABLE rather than fabricating package advisories.
    return QueryOsvDatabaseOutput(
        tool_name="query_osv_database",
        status=ToolStatus.NOT_AVAILABLE,
        message="Local OSV database cache is not provisioned in offline environment.",
        side_effect=SideEffectClass.READ_ONLY,
        provenance=ToolProvenance(
            source="osv_offline_cache",
            source_type=ProvenanceSourceType.LOCAL_CACHE,
        ),
        package_name=input_data.package_name,
        version=input_data.version,
        advisories=[],
        fixed_versions=[],
    )
