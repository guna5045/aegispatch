"""Foundational constants for AegisPatch."""

APP_NAME: str = "AegisPatch"
APP_VERSION: str = "0.1.0"
APP_DESCRIPTION: str = "Context-driven vulnerability prioritization and remediation planning system"

# Default configuration values
DEFAULT_LOG_LEVEL: str = "INFO"
DEFAULT_DATABASE_URL: str = "sqlite:///data/runtime/aegispatch.db"
DEFAULT_DATABASE_ECHO: bool = False
DEFAULT_API_HOST: str = "127.0.0.1"
DEFAULT_API_PORT: int = 8000
DEFAULT_API_PREFIX: str = "/api/v1"
