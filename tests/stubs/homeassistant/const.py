"""Home Assistant constants used in tests."""
from __future__ import annotations

from enum import Enum


CONF_HOST = "host"
CONF_PASSWORD = "password"
CONF_USERNAME = "username"


class UnitOfTime(Enum):
    """Minimal UnitOfTime enum stub."""

    MILLISECONDS = "milliseconds"


TIME_MILLISECONDS = UnitOfTime.MILLISECONDS


class Platform(str, Enum):
    """Subset of Home Assistant platforms referenced by the integration."""

    BINARY_SENSOR = "binary_sensor"
    BUTTON = "button"
    SENSOR = "sensor"


__all__ = [
    "CONF_HOST",
    "CONF_PASSWORD",
    "CONF_USERNAME",
    "Platform",
    "UnitOfTime",
    "TIME_MILLISECONDS",
]
