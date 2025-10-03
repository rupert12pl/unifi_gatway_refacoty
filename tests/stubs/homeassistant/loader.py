"""Minimal loader stubs for tests."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

DATA_INTEGRATIONS = "integrations"
DATA_COMPONENTS = "components"
DATA_CUSTOM_COMPONENTS = "custom_components"
DATA_PRELOAD_PLATFORMS = "preload_platforms"
DATA_MISSING_PLATFORMS = "missing_platforms"


@dataclass
class Integration:
    """Integration metadata container used by tests."""

    hass: Any
    domain: str
    file_path: str
    manifest: dict[str, Any]


__all__ = [
    "DATA_COMPONENTS",
    "DATA_CUSTOM_COMPONENTS",
    "DATA_INTEGRATIONS",
    "DATA_MISSING_PLATFORMS",
    "DATA_PRELOAD_PLATFORMS",
    "Integration",
]
