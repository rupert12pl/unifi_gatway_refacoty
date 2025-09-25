"""Home Assistant constants used in tests."""
from __future__ import annotations

from enum import Enum


class Platform(str, Enum):
    """Subset of Home Assistant platforms referenced by the integration."""

    BINARY_SENSOR = "binary_sensor"
    BUTTON = "button"
    SENSOR = "sensor"


__all__ = ["Platform"]
