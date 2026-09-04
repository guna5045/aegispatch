"""Declarative Base for Aegis Patch SQLAlchemy ORM models."""

from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Shared declarative base class for all Aegis Patch database models.

    All ORM models in subsequent phases (Asset, Vulnerability, RiskAssessment, etc.)
    will inherit from this shared declarative base.
    """

    pass
