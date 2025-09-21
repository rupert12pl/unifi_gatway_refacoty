
from __future__ import annotations

from typing import Any, Dict

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

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


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> Dict[str, Any]:
    stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)

    if stored and isinstance(stored.get("client"), UniFiOSClient):
        client: UniFiOSClient = stored["client"]

        def _collect_existing() -> Dict[str, Any]:
            health = client.get_healthinfo()
            sites = client.list_sites()
            return {
                "controller_ui": client.get_controller_url(),
                "controller_api": client.get_controller_api_url(),
                "site": client.get_site(),
                "health": health,
                "sites": sites,
            }

        return await hass.async_add_executor_job(_collect_existing)

    def _collect_fresh() -> Dict[str, Any]:
        client = UniFiOSClient(
            host=entry.data[CONF_HOST],
            username=entry.data[CONF_USERNAME],
            password=entry.data[CONF_PASSWORD],
            port=entry.data.get(CONF_PORT, DEFAULT_PORT),
            site_id=entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
            ssl_verify=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            use_proxy_prefix=entry.data.get(
                CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
            ),
            timeout=entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        )
        health = client.get_healthinfo()
        sites = client.list_sites()
        return {
            "controller_ui": client.get_controller_url(),
            "controller_api": client.get_controller_api_url(),
            "site": client.get_site(),
            "health": health,
            "sites": sites,
        }

    return await hass.async_add_executor_job(_collect_fresh)
