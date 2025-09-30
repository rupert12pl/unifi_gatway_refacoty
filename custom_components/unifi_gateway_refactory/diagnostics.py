"""Diagnostics support for UniFi Gateway Refactory."""
from __future__ import annotations

from typing import Any, cast

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from . import IntegrationRuntime
from .const import DOMAIN
from .coordinator import UniFiGatewayCoordinator


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> dict[str, Any]:
    """Return diagnostics for a config entry."""
    runtime = cast(IntegrationRuntime, hass.data[DOMAIN][entry.entry_id])
    coordinator: UniFiGatewayCoordinator = runtime.coordinator
    data = coordinator.data

    if not data:
        return {"detail": "no_data"}

    return {
        "entry": {
            "title": entry.title,
            "site": entry.data.get("site"),
        },
        "last_fetch": data.last_fetch.isoformat(),
        "health": [_sanitize_health(item) for item in data.health],
        "wlans": [_sanitize_wlan(item) for item in data.wlans],
    }


def _sanitize_health(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    sanitized = dict(item)
    if "name" in sanitized:
        sanitized["name"] = "redacted"
    if "ip" in sanitized:
        sanitized["ip"] = "redacted"
    return sanitized


def _sanitize_wlan(item: Any) -> Any:
    if not isinstance(item, dict):
        return item
    sanitized = dict(item)
    if "name" in sanitized:
        sanitized["name"] = "redacted"
    if "x_password" in sanitized:
        sanitized["x_password"] = "redacted"  # noqa: S105 - sanitized placeholder
    return sanitized
