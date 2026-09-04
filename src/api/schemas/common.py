"""Common API schemas and pagination models for Aegis Patch."""

from __future__ import annotations

from typing import Any, Generic, List, Optional, TypeVar
from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class ErrorDetail(BaseModel):
    """Structured error payload details."""

    model_config = ConfigDict(extra="forbid")

    code: str = Field(..., description="Machine-readable error classification code")
    message: str = Field(..., description="Human-readable explanation of the error")
    details: Optional[Any] = Field(None, description="Optional supporting contextual details or field errors")


class ErrorResponse(BaseModel):
    """Standardized envelope for error responses."""

    model_config = ConfigDict(extra="forbid")

    error: ErrorDetail


class PaginationMeta(BaseModel):
    """Pagination metadata describing a window over a dataset."""

    model_config = ConfigDict(extra="forbid")

    page: int = Field(..., ge=1, description="Current 1-indexed page number")
    page_size: int = Field(..., ge=1, le=100, description="Maximum items per page")
    total_items: int = Field(..., ge=0, description="Total count of items matching the query")
    total_pages: int = Field(..., ge=0, description="Total number of available pages")


class PaginatedResponse(BaseModel, Generic[T]):
    """Generic wrapper for paginated collections."""

    model_config = ConfigDict(extra="forbid")

    items: List[T] = Field(default_factory=list, description="List of items for the requested page")
    pagination: PaginationMeta


class HealthResponse(BaseModel):
    """System and database connectivity status summary."""

    model_config = ConfigDict(extra="forbid")

    status: str = Field(..., description="Overall API operational state ('healthy' or 'degraded')")
    app_name: str = Field(..., description="Application name")
    app_version: str = Field(..., description="Application semantic version")
    database: str = Field(..., description="Database connectivity status ('healthy' or 'unavailable')")


class RootInfoResponse(BaseModel):
    """API gateway metadata and exploration links."""

    model_config = ConfigDict(extra="forbid")

    app_name: str
    app_version: str
    description: str
    docs_url: str
    api_prefix: str
