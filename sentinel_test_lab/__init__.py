"""Sentinel Test Lab - authorized website load, resilience and security testing."""

from pathlib import Path

__version__ = "1.0.0"
APP_NAME = "Sentinel Test Lab"
USER_AGENT = f"SentinelTestLab/{__version__} (authorized-testing)"

PACKAGE_DIR = Path(__file__).resolve().parent


def resource_path(*parts: str) -> Path:
    """Path to a bundled data file (works from source and from a PyInstaller build)."""
    return PACKAGE_DIR.joinpath(*parts)
