"""Home Assistant constants used in tests."""
from __future__ import annotations

from enum import Enum


class UnitOfTime(Enum):
    """Minimal UnitOfTime enum stub."""

    MILLISECONDS = "milliseconds"


TIME_MILLISECONDS = UnitOfTime.MILLISECONDS
STATE_UNKNOWN = "unknown"


class Platform(str, Enum):
    """Subset of Home Assistant platforms referenced by the integration."""

    BINARY_SENSOR = "binary_sensor"
    BUTTON = "button"
    SENSOR = "sensor"


__all__ = ["Platform", "UnitOfTime", "TIME_MILLISECONDS", "STATE_UNKNOWN"]
