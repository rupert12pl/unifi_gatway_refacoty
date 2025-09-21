
from __future__ import annotations
from typing import Any, Dict
from homeassistant.core import HomeAssistant
from homeassistant.config_entries import ConfigEntry
from .const import (
    CONF_USERNAME, CONF_PASSWORD, CONF_HOST, CONF_PORT, CONF_SITE_ID,
    CONF_VERIFY_SSL, CONF_USE_PROXY_PREFIX, CONF_TIMEOUT
)
from .unifi_client import UniFiOSClient, APIError, AuthError, ConnectivityError

async def async_get_config_entry_diagnostics(hass: HomeAssistant, entry: ConfigEntry) -> Dict[str, Any]:
    data = entry.data
    def _sync():
        client = UniFiOSClient(
            host=data[CONF_HOST],
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            port=data.get(CONF_PORT, 443),
            site_id=data.get(CONF_SITE_ID, "default"),
            ssl_verify=data.get(CONF_VERIFY_SSL, False),
            use_proxy_prefix=data.get(CONF_USE_PROXY_PREFIX, True),
            timeout=data.get(CONF_TIMEOUT, 10),
        )
        health = client.get_healthinfo()
        sites = client.list_sites()
        return {
            "controller_ui": client.get_controller_url(),
            "site": client.get_site(),
            "health": health,
            "sites": sites,
        }
    return await hass.async_add_executor_job(_sync)
