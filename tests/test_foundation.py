"""Basic foundation tests for AegisPatch."""

from config.constants import APP_NAME, APP_VERSION
from config.settings import settings


def test_app_constants():
    """Verify application constants are defined as expected."""
    assert APP_NAME == "AegisPatch"
    assert APP_VERSION == "0.1.0"


def test_settings_initialization():
    """Verify settings initialize cleanly with default values."""
    assert settings.app_name == "AegisPatch"
    assert settings.app_version == "0.1.0"
    assert settings.log_level in ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
    assert settings.database_url.startswith("sqlite")


def test_packages_importable():
    """Verify foundational project packages can be imported."""
    import src
    import src.agents
    import src.api
    import src.database
    import src.gateway
    import src.orchestration
    import src.rag
    import src.schemas
    import src.tools
    import src.ui

    assert src is not None
