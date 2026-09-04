"""Aegis Patch — FastAPI HTTP Backend Application.

Provides a clean, versioned, RESTful API layer for context-driven vulnerability
prioritization, enterprise asset exploration, risk evaluations, and patch remediation planning.
"""

from __future__ import annotations

import logging
from typing import Any, Dict
from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from config.constants import APP_DESCRIPTION, APP_NAME, APP_VERSION
from config.settings import settings
from src.api.routers import (
    assets_router,
    health_router,
    patch_plans_router,
    policies_router,
    risk_router,
    threat_router,
    vulnerabilities_router,
)
from src.api.schemas.common import ErrorDetail, ErrorResponse, RootInfoResponse

logger = logging.getLogger("aegis_patch.api")


def create_app() -> FastAPI:
    """Construct and configure the Aegis Patch FastAPI application instance.

    Returns:
        Configured FastAPI application with registered routers and error handlers.
    """
    app = FastAPI(
        title=APP_NAME,
        version=APP_VERSION,
        description=APP_DESCRIPTION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # CORS configuration with explicit origins (No wildcard credentials)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:8501",
            "http://127.0.0.1:8501",
            "http://localhost:8000",
            "http://127.0.0.1:8000",
        ],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PATCH", "OPTIONS"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # Exception Handlers
    # ------------------------------------------------------------------

    @app.exception_handler(HTTPException)
    async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
        """Handle standard HTTP exceptions with structured error envelope."""
        code_map = {
            400: "BAD_REQUEST",
            404: "NOT_FOUND",
            409: "CONFLICT",
            422: "UNPROCESSABLE_ENTITY",
            500: "INTERNAL_SERVER_ERROR",
            503: "SERVICE_UNAVAILABLE",
        }
        error_code = code_map.get(exc.status_code, "ERROR")
        error_response = ErrorResponse(
            error=ErrorDetail(
                code=error_code,
                message=str(exc.detail),
                details=None,
            )
        )
        return JSONResponse(
            status_code=exc.status_code,
            content=error_response.model_dump(),
        )

    @app.exception_handler(RequestValidationError)
    async def validation_exception_handler(
        request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        """Handle schema validation errors cleanly without leaking internals."""
        clean_errors = []
        for err in exc.errors():
            clean_errors.append(
                {
                    "location": [str(loc) for loc in err.get("loc", [])],
                    "message": err.get("msg", ""),
                    "type": err.get("type", ""),
                }
            )

        error_response = ErrorResponse(
            error=ErrorDetail(
                code="VALIDATION_ERROR",
                message="Request validation failed. Check parameters and payload.",
                details=clean_errors,
            )
        )
        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_CONTENT
            if hasattr(status, "HTTP_422_UNPROCESSABLE_CONTENT")
            else 422,
            content=error_response.model_dump(),
        )

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Catch-all for internal unexpected errors without leaking tracebacks or filesystem paths."""
        logger.error(f"Unhandled server error on {request.method} {request.url.path}: {exc}", exc_info=True)
        error_response = ErrorResponse(
            error=ErrorDetail(
                code="INTERNAL_ERROR",
                message="An unexpected internal server error occurred.",
                details=None,
            )
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=error_response.model_dump(),
        )

    # ------------------------------------------------------------------
    # Root Gateway Endpoint
    # ------------------------------------------------------------------

    @app.get(
        "/",
        response_model=RootInfoResponse,
        summary="Aegis Patch API Information",
        description="Returns basic gateway metadata, application version, and documentation links.",
        tags=["System"],
    )
    def get_api_root() -> RootInfoResponse:
        """Root API info."""
        return RootInfoResponse(
            app_name=APP_NAME,
            app_version=APP_VERSION,
            description=APP_DESCRIPTION,
            docs_url="/docs",
            api_prefix=settings.api_prefix,
        )

    # ------------------------------------------------------------------
    # Versioned Router Mounting
    # ------------------------------------------------------------------

    prefix = settings.api_prefix  # Defaults to /api/v1
    app.include_router(health_router, prefix=prefix)
    app.include_router(assets_router, prefix=prefix)
    app.include_router(vulnerabilities_router, prefix=prefix)
    app.include_router(risk_router, prefix=prefix)
    app.include_router(patch_plans_router, prefix=prefix)
    app.include_router(policies_router, prefix=prefix)
    app.include_router(threat_router, prefix=prefix)

    return app


# Module-level default application instance for ASGI servers
app = create_app()
