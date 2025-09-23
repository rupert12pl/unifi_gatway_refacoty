
from __future__ import annotations

from typing import Any, Dict

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.components.diagnostics import async_redact_data

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from .unifi_client import UniFiOSClient


TO_REDACT: set[str] = {
    CONF_HOST,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_SITE_ID,
    "controller_ui",
    "controller_api",
    "site",
    "mac",
    "mac_address",
    "macs",
    "serial",
    "device_id",
    "ip",
    "ip_address",
    "ipv4",
    "ipv6",
    "wan_ip",
    "lan_ip",
    "gateway",
    "gateway_ip",
    "ssid",
    "essid",
    "bssid",
    "token",
    "cookie",
    "secret",
    "passphrase",
    "password",
    "username",
    "private_key",
    "key",
    "session_id",
}


def _build_diagnostics_payload(client: UniFiOSClient) -> Dict[str, Any]:
    """Collect controller diagnostics payload from the UniFi client."""

    health = client.get_healthinfo()
    sites = client.list_sites()
    return {
        "controller_ui": client.get_controller_url(),
        "controller_api": client.get_controller_api_url(),
        "site": client.get_site(),
        "health": health,
        "sites": sites,
    }


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> Dict[str, Any]:
    stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)

    if stored and isinstance(stored.get("client"), UniFiOSClient):
        client: UniFiOSClient = stored["client"]

        def _collect_existing() -> Dict[str, Any]:
            return _build_diagnostics_payload(client)

        payload = await hass.async_add_executor_job(_collect_existing)
        return async_redact_data(payload, TO_REDACT)

    def _collect_fresh() -> Dict[str, Any]:
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
        return _build_diagnostics_payload(client)

    payload = await hass.async_add_executor_job(_collect_fresh)
    return async_redact_data(payload, TO_REDACT)
