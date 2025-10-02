"""Factory functions for UniFi Gateway Dashboard Analyzer client creation."""
from __future__ import annotations

from functools import partial
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady

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
)
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient

async def async_get_client(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> UniFiOSClient:
    """Create and initialize UniFi client for config entry."""
    client_kwargs: dict[str, Any] = {
        "host": entry.data[CONF_HOST],
        "port": entry.data.get(CONF_PORT, DEFAULT_PORT),
        "site_id": entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
        "ssl_verify": entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        "use_proxy_prefix": entry.data.get(
            CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
        ),
        "timeout": entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
    }

    username = entry.data.get(CONF_USERNAME)
    password = entry.data.get(CONF_PASSWORD)
    if username:
        client_kwargs["username"] = username
    if password:
        client_kwargs["password"] = password

    # Ensures stable unique_id across restarts
    client_kwargs["instance_hint"] = entry.entry_id

    try:
        client = await hass.async_add_executor_job(partial(UniFiOSClient, **client_kwargs))
    except AuthError as err:
        raise ConfigEntryAuthFailed(
            f"Authentication failed for entry {entry.entry_id}: {err}"
        ) from err
    except ConnectivityError as err:
        raise ConfigEntryNotReady(
            f"Cannot connect to UniFi controller: {err}"
        ) from err
    except APIError as err:
        raise ConfigEntryNotReady(
            f"UniFi controller error: {err}"
        ) from err

    return client