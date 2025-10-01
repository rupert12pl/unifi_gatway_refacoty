"""Diagnostics support for the UniFi Gateway Dashboard Analyzer."""

from __future__ import annotations

import json
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_ERRORS,
    DIAGNOSTICS_MAX_PAYLOAD_BYTES,
    DOMAIN,
    SENSITIVE_DIAGNOSTIC_KEYS,
)
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiApiClient


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            if key.lower() in SENSITIVE_DIAGNOSTIC_KEYS:
                redacted[key] = "***"
            else:
                redacted[key] = _redact(item)
        return redacted
    if isinstance(value, list):
        return [_redact(item) for item in value]
    return value


def _truncate_payload(value: Any) -> Any:
    encoded = json.dumps(value, ensure_ascii=False, default=str).encode("utf-8")
    if len(encoded) <= DIAGNOSTICS_MAX_PAYLOAD_BYTES:
        return value
    preview = encoded[:DIAGNOSTICS_MAX_PAYLOAD_BYTES].decode("utf-8", "ignore")
    return {"truncated": True, "preview": preview}


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    store = hass.data.get(DOMAIN, {}).get(entry.entry_id, {})
    coordinator: UniFiGatewayDataUpdateCoordinator | None = store.get(DATA_COORDINATOR)
    client: UniFiApiClient | None = store.get(DATA_CLIENT)
    errors = list(store.get(DATA_ERRORS, []))

    config = {
        CONF_HOST: entry.data.get(CONF_HOST),
        CONF_PORT: entry.data.get(CONF_PORT),
        CONF_SITE_ID: entry.data.get(CONF_SITE_ID),
        CONF_TIMEOUT: entry.data.get(CONF_TIMEOUT),
        CONF_VERIFY_SSL: entry.data.get(CONF_VERIFY_SSL),
        CONF_USERNAME: "***" if entry.data.get(CONF_USERNAME) else None,
        CONF_PASSWORD: "***" if entry.data.get(CONF_PASSWORD) else None,
    }

    diagnostics: dict[str, Any] = {
        "config": _redact(config),
        "errors": errors[-10:],
    }

    if client is not None:
        diagnostics["client"] = {
            "controller": client.get_controller_url(),
            "api": client.get_controller_api_url(),
            "site": client.get_site(),
        }

    if coordinator and coordinator.data:
        data = coordinator.data
        diagnostics["coordinator"] = {
            "trace_id": data.trace_id,
            "available": data.available,
            "status": data.status,
            "last_updated": data.last_updated.isoformat(),
        }
        diagnostics["data"] = {
            "health": _truncate_payload(_redact(data.health)),
            "alerts": _truncate_payload(_redact(data.alerts)),
            "devices": _truncate_payload(_redact(data.devices)),
        }

    return diagnostics
