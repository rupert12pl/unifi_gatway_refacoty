"""Constants required by the integration tests."""
from __future__ import annotations

from enum import Enum

CONF_HOST = "host"
CONF_USERNAME = "username"
CONF_PASSWORD = "password"  # noqa: S105
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"


class Platform(str, Enum):
    """Platforms supported by Home Assistant."""

    SENSOR = "sensor"
    BINARY_SENSOR = "binary_sensor"


class UnitOfDataRate:
    """Minimal representation of data rate units."""

    MEGABITS_PER_SECOND = "Mbit/s"


class UnitOfTime:
    """Minimal representation of time units."""

    SECONDS = "s"
