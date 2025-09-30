"""Constants and helpers for the UniFi Gateway Refactory integration."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactory"
PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]

CONF_SITE = "site"
DEFAULT_SITE = "default"

CONF_SCAN_INTERVAL = "scan_interval"
DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 30
MAX_SCAN_INTERVAL = 60

CONF_VERIFY_SSL = "verify_ssl"
DEFAULT_VERIFY_SSL = True

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
DEFAULT_PORT = 443

CONF_RATE_LIMIT = "rate_limit"
DEFAULT_RATE_LIMIT = 2

DATA_COORDINATOR = "coordinator"
DATA_VERIFY_WARNING = "verify_warning_emitted"

ISSUE_LEGACY_DOMAIN = "legacy_conflict"
LEGACY_DOMAIN = "unifigateway"

API_REQUEST_TIMEOUT = 15
API_MAX_ATTEMPTS = 4
API_BACKOFF_FACTOR = 1.5
API_MAX_BACKOFF = 30

WAN_STATUS_SUBSYSTEM = "wan"
VPN_STATUS_SUBSYSTEM = "vpn"

@dataclass
class GatewaySensorDescription:
    """Description for a UniFi Gateway sensor."""

    key: str
    name: str
    icon: str
    native_unit_of_measurement: str | None
    device_class: str | None
    state_class: str | None
    value_fn: Callable[[dict[str, Any]], Any]
    attributes_fn: Callable[[dict[str, Any]], dict[str, Any]] = lambda _: {}


def as_float(value: Any) -> float | None:
    """Parse a raw value into a float without raising errors.

    Returns ``None`` when conversion fails.
    """

    if value is None:
        return None
    if isinstance(value, bool):
        return float(value)
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        stripped = value.strip()
        if not stripped:
            return None
        try:
            return float(stripped)
        except ValueError:
            return None
    try:
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return None


__all__ = [
    "API_BACKOFF_FACTOR",
    "API_MAX_ATTEMPTS",
    "API_MAX_BACKOFF",
    "API_REQUEST_TIMEOUT",
    "CONF_HOST",
    "CONF_PASSWORD",
    "CONF_PORT",
    "CONF_RATE_LIMIT",
    "CONF_SCAN_INTERVAL",
    "CONF_SITE",
    "CONF_USERNAME",
    "CONF_VERIFY_SSL",
    "DATA_COORDINATOR",
    "DATA_VERIFY_WARNING",
    "DEFAULT_PORT",
    "DEFAULT_RATE_LIMIT",
    "DEFAULT_SCAN_INTERVAL",
    "DEFAULT_SITE",
    "DEFAULT_VERIFY_SSL",
    "DOMAIN",
    "GatewaySensorDescription",
    "ISSUE_LEGACY_DOMAIN",
    "LEGACY_DOMAIN",
    "MAX_SCAN_INTERVAL",
    "MIN_SCAN_INTERVAL",
    "PLATFORMS",
    "VPN_STATUS_SUBSYSTEM",
    "WAN_STATUS_SUBSYSTEM",
    "as_float",
]
