"""Tests for Phase 7 threat intelligence tools: lookup_cisa_kev, query_epss, query_osv_database."""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from src.database.base import Base
from src.database.models.threat import ThreatIntelligenceObservation
from src.tools.schemas import (
    LookupCisaKevInput,
    QueryEpssInput,
    QueryOsvDatabaseInput,
    SideEffectClass,
    ToolStatus,
)
from src.tools.threat_tools import (
    lookup_cisa_kev,
    query_epss,
    query_osv_database,
)


@pytest.fixture
def in_memory_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sm = sessionmaker(bind=engine)
    session = sm()
    try:
        yield session
    finally:
        session.close()


def test_lookup_cisa_kev_found(in_memory_session):
    obs = ThreatIntelligenceObservation(
        cve_id="CVE-2023-38545",
        source="CISA KEV",
        is_cisa_kev=True,
        cisa_kev_date_added=datetime(2023, 10, 18, tzinfo=timezone.utc),
        cisa_kev_due_date=datetime(2023, 11, 8, tzinfo=timezone.utc),
        epss_score=0.92,
        notes="Known actively exploited in wild.",
    )
    in_memory_session.add(obs)
    in_memory_session.commit()

    inp = LookupCisaKevInput(cve_id="CVE-2023-38545")
    out = lookup_cisa_kev(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.side_effect == SideEffectClass.READ_ONLY
    assert out.is_known_exploited is True
    assert out.date_added is not None
    assert "2023-10-18" in out.date_added


def test_lookup_cisa_kev_not_kev(in_memory_session):
    obs = ThreatIntelligenceObservation(
        cve_id="CVE-2023-44487",
        source="CISA KEV",
        is_cisa_kev=False,
        epss_score=0.15,
    )
    in_memory_session.add(obs)
    in_memory_session.commit()

    inp = LookupCisaKevInput(cve_id="CVE-2023-44487")
    out = lookup_cisa_kev(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.is_known_exploited is False


def test_lookup_cisa_kev_not_found(in_memory_session):
    obs = ThreatIntelligenceObservation(
        cve_id="CVE-2023-44487",
        source="CISA KEV",
        is_cisa_kev=False,
    )
    in_memory_session.add(obs)
    in_memory_session.commit()

    inp = LookupCisaKevInput(cve_id="CVE-2024-9999")
    out = lookup_cisa_kev(inp, session=in_memory_session)

    assert out.status == ToolStatus.NOT_FOUND
    assert out.is_known_exploited is False


def test_lookup_cisa_kev_not_available_when_db_empty(in_memory_session):
    inp = LookupCisaKevInput(cve_id="CVE-2024-9999")
    out = lookup_cisa_kev(inp, session=in_memory_session)

    assert out.status == ToolStatus.NOT_AVAILABLE
    assert out.is_known_exploited is False


def test_query_epss_found(in_memory_session):
    obs = ThreatIntelligenceObservation(
        cve_id="CVE-2023-38545",
        source="FIRST EPSS",
        epss_score=0.885,
        epss_percentile=0.97,
    )
    in_memory_session.add(obs)
    in_memory_session.commit()

    inp = QueryEpssInput(cve_id="CVE-2023-38545")
    out = query_epss(inp, session=in_memory_session)

    assert out.status == ToolStatus.SUCCESS
    assert out.epss_score == 0.885
    assert out.percentile == 0.97
    assert 0.0 <= out.epss_score <= 1.0


def test_query_epss_not_available(in_memory_session):
    inp = QueryEpssInput(cve_id="CVE-2024-9999")
    out = query_epss(inp, session=in_memory_session)

    assert out.status == ToolStatus.NOT_AVAILABLE
    assert out.epss_score is None


def test_query_osv_database_offline():
    inp = QueryOsvDatabaseInput(package_name="libcurl4", version="7.88.1")
    out = query_osv_database(inp)

    assert out.status == ToolStatus.NOT_AVAILABLE
    assert out.package_name == "libcurl4"
    assert out.side_effect == SideEffectClass.READ_ONLY
    assert len(out.advisories) == 0
