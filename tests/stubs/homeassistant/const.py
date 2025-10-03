"""Home Assistant constants used in tests."""
from __future__ import annotations

from enum import Enum


class UnitOfTime(Enum):
    """Minimal UnitOfTime enum stub."""

    MILLISECONDS = "milliseconds"


TIME_MILLISECONDS = UnitOfTime.MILLISECONDS


class Platform(str, Enum):
    """Subset of Home Assistant platforms referenced by the integration."""

    BINARY_SENSOR = "binary_sensor"
    BUTTON = "button"
    SENSOR = "sensor"


CONF_HOST = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"

__all__ = [
    "Platform",
    "UnitOfTime",
    "TIME_MILLISECONDS",
    "CONF_HOST",
    "CONF_USERNAME",
    "CONF_PASSWORD",
]
