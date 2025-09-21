
from __future__ import annotations

import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

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
    PLATFORMS,
)
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})

    client_kwargs: dict[str, Any] = {
        "host": entry.data[CONF_HOST],
        "username": entry.data[CONF_USERNAME],
        "password": entry.data[CONF_PASSWORD],
        "port": entry.data.get(CONF_PORT, DEFAULT_PORT),
        "site_id": entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
        "ssl_verify": entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        "use_proxy_prefix": entry.data.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
        "timeout": entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        "instance_hint": "sensor",
    }

    try:
        client: UniFiOSClient = await hass.async_add_executor_job(
            UniFiOSClient, **client_kwargs
        )
    except AuthError as err:
        raise ConfigEntryAuthFailed("Authentication with UniFi controller failed") from err
    except ConnectivityError as err:
        raise ConfigEntryNotReady(f"Cannot connect to UniFi controller: {err}") from err
    except APIError as err:
        raise ConfigEntryNotReady(f"UniFi controller error: {err}") from err

    coordinator = UniFiGatewayDataUpdateCoordinator(hass, client)
    await coordinator.async_config_entry_first_refresh()

    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        stored = hass.data.get(DOMAIN)
        if stored and entry.entry_id in stored:
            stored.pop(entry.entry_id)
    return unload_ok
