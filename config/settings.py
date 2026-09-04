"""Foundational environment and application settings for AegisPatch."""

import os
from dataclasses import dataclass
from typing import Optional
from config.constants import (
    APP_NAME,
    APP_VERSION,
    DEFAULT_DATABASE_ECHO,
    DEFAULT_DATABASE_URL,
    DEFAULT_LOG_LEVEL,
)


@dataclass
class Settings:
    """Foundational configuration loaded from environment variables."""

    app_name: str = APP_NAME
    app_version: str = APP_VERSION
    log_level: str = os.getenv("LOG_LEVEL", DEFAULT_LOG_LEVEL)
    database_url: str = os.getenv("DATABASE_URL", DEFAULT_DATABASE_URL)
    database_echo: bool = os.getenv("DATABASE_ECHO", str(DEFAULT_DATABASE_ECHO)).lower() in (
        "true",
        "1",
        "yes",
    )
    
    # Model provider configuration placeholders
    model_provider: Optional[str] = os.getenv("MODEL_PROVIDER")
    model_name: Optional[str] = os.getenv("MODEL_NAME")
    groq_api_key: Optional[str] = os.getenv("GROQ_API_KEY")
    openrouter_api_key: Optional[str] = os.getenv("OPENROUTER_API_KEY")


settings = Settings()
