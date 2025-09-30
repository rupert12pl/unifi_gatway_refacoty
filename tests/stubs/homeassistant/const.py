"""Home Assistant constant stubs used in tests."""
from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    """Platforms referenced by the integration."""

    SENSOR = "sensor"
    BINARY_SENSOR = "binary_sensor"


__all__ = ["Platform"]
