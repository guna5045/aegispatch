"""API routers for Aegis Patch backend."""

from src.api.routers.assets import router as assets_router
from src.api.routers.health import router as health_router
from src.api.routers.patch_plans import router as patch_plans_router
from src.api.routers.policies import router as policies_router
from src.api.routers.risk import router as risk_router
from src.api.routers.threat import router as threat_router
from src.api.routers.vulnerabilities import router as vulnerabilities_router

__all__ = [
    "assets_router",
    "health_router",
    "patch_plans_router",
    "policies_router",
    "risk_router",
    "threat_router",
    "vulnerabilities_router",
]
