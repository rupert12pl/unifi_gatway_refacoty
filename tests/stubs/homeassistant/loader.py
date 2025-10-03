"""Minimal loader stubs for Home Assistant tests."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict

DATA_INTEGRATIONS = "integrations"
DATA_COMPONENTS = "components"
DATA_CUSTOM_COMPONENTS = "custom_components"
DATA_PRELOAD_PLATFORMS = "preload_platforms"
DATA_MISSING_PLATFORMS = "missing_platforms"


@dataclass
class Integration:
    """Basic representation of an integration manifest."""

    hass: Any
    domain: str
    file_path: str
    manifest: Dict[str, Any]


__all__ = [
    "Integration",
    "DATA_INTEGRATIONS",
    "DATA_COMPONENTS",
    "DATA_CUSTOM_COMPONENTS",
    "DATA_PRELOAD_PLATFORMS",
    "DATA_MISSING_PLATFORMS",
]
