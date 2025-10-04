
from __future__ import annotations

from typing import Any

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import (
    CONF_API_KEY,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_UI_API_KEY,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient


REDACT_KEYS: set[str] = {
    CONF_PASSWORD,
    CONF_USERNAME,
    CONF_API_KEY,
    CONF_UI_API_KEY,
}


def _summarize_error(err: Exception) -> dict[str, Any]:
    """Return a compact, sanitized representation of ``err``."""

    summary: dict[str, Any] = {"type": err.__class__.__name__}
    if isinstance(err, APIError):
        if err.status_code is not None:
            summary["status"] = err.status_code
        if err.expected:
            summary["expected"] = True
        if err.status_code == 404:
            summary["reason"] = "not_found"
        elif err.status_code == 400:
            summary["reason"] = "bad_request"
    return summary


def _collect_health(client: UniFiOSClient) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    """Fetch controller health data, tolerating expected API failures."""

    try:
        health = client.get_healthinfo()
    except APIError as err:
        if err.status_code in (400, 404) or err.expected:
            return [], {
                "health": _summarize_error(err),
            }
        raise
    except ConnectivityError as err:
        return [], {"health": _summarize_error(err)}
    return health, None


def _build_controller_payload(client: UniFiOSClient) -> dict[str, Any]:
    """Collect controller diagnostics from ``client``."""

    health, health_error = _collect_health(client)

    payload: dict[str, Any] = {
        "controller_ui": client.get_controller_url(),
        "controller_api": client.get_controller_api_url(),
        "site": client.get_site(),
        "health": health,
    }

    if health_error:
        payload["errors"] = health_error

    return payload


def _base_payload(entry: ConfigEntry) -> dict[str, Any]:
    """Return diagnostics payload skeleton with redaction metadata."""

    return {
        "config": {
            "data": dict(entry.data),
            "options": dict(entry.options),
        }
    }


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)

    if stored and isinstance(stored.get("client"), UniFiOSClient):
        client: UniFiOSClient = stored["client"]

        def _collect_existing() -> dict[str, Any]:
            payload = _base_payload(entry)
            payload["controller"] = _build_controller_payload(client)
            payload["source"] = "runtime"
            return payload

        result = await hass.async_add_executor_job(_collect_existing)
        return async_redact_data(result, REDACT_KEYS)

    def _collect_fresh() -> dict[str, Any]:
        payload = _base_payload(entry)
        errors: dict[str, Any] | None = None
        client: UniFiOSClient | None = None

        try:
            client = UniFiOSClient(
                host=entry.data[CONF_HOST],
                username=entry.data.get(CONF_USERNAME),
                password=entry.data.get(CONF_PASSWORD),
                port=entry.data.get(CONF_PORT, DEFAULT_PORT),
                site_id=entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
                ssl_verify=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                use_proxy_prefix=entry.data.get(
                    CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
                ),
                timeout=entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
            )
            payload["controller"] = _build_controller_payload(client)
        except (APIError, AuthError, ConnectivityError) as err:
            errors = {"connect": _summarize_error(err)}
        finally:
            if client is not None:
                client.close()

        if errors:
            payload["errors"] = errors

        payload["source"] = "direct"
        return payload

    result = await hass.async_add_executor_job(_collect_fresh)
    return async_redact_data(result, REDACT_KEYS)
