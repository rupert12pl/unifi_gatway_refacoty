"""Setup for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

import logging
from typing import Any

from aiohttp import ClientSession, ClientTimeout
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.typing import ConfigType

from .const import (
    CLIENT_CONNECT_TIMEOUT,
    CLIENT_SOCK_READ_TIMEOUT,
    CLIENT_TOTAL_TIMEOUT,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_ERRORS,
    DATA_SESSION,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    PLATFORMS,
)
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .unifi_client import (
    UniFiApiClient,
    UniFiAuthError,
    UniFiClientError,
    UniFiRequestError,
)

LOGGER = logging.getLogger(__package__)


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Set up the integration namespace."""

    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Gateway Dashboard Analyzer from a config entry."""

    hass.data.setdefault(DOMAIN, {})

    timeout = ClientTimeout(
        total=CLIENT_TOTAL_TIMEOUT,
        connect=CLIENT_CONNECT_TIMEOUT,
        sock_read=CLIENT_SOCK_READ_TIMEOUT,
    )
    session = ClientSession(timeout=timeout)

    client = UniFiApiClient(
        session=session,
        host=entry.data[CONF_HOST],
        username=entry.data.get(CONF_USERNAME, ""),
        password=entry.data.get(CONF_PASSWORD, ""),
        port=entry.data.get(CONF_PORT, DEFAULT_PORT),
        site_id=entry.data.get(CONF_SITE_ID, DEFAULT_SITE),
        verify_ssl=entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        use_proxy_prefix=entry.data.get(
            CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
        ),
        request_timeout=entry.data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        instance_hint=entry.entry_id,
    )

    try:
        await client.async_login()
        await client.async_probe()
    except UniFiAuthError as err:
        await session.close()
        raise ConfigEntryAuthFailed(str(err)) from err
    except UniFiClientError as err:
        await session.close()
        raise ConfigEntryNotReady(str(err)) from err

    errors: list[dict[str, Any]] = []
    coordinator = UniFiGatewayDataUpdateCoordinator(
        hass=hass, client=client, error_buffer=errors
    )

    try:
        await coordinator.async_config_entry_first_refresh()
    except UniFiAuthError as err:
        await session.close()
        raise ConfigEntryAuthFailed(str(err)) from err
    except UniFiRequestError as err:
        await session.close()
        raise ConfigEntryNotReady(str(err)) from err

    hass.data[DOMAIN][entry.entry_id] = {
        DATA_CLIENT: client,
        DATA_COORDINATOR: coordinator,
        DATA_SESSION: session,
        DATA_ERRORS: errors,
    }

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    LOGGER.info(
        "UniFi Gateway Dashboard Analyzer configured",
        extra={"event": "setup", "status": "ok", "trace_id": entry.entry_id},
    )
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a UniFi Gateway Dashboard Analyzer config entry."""

    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)

    stored = hass.data.get(DOMAIN, {}).pop(entry.entry_id, None)
    if stored:
        session: ClientSession | None = stored.get(DATA_SESSION)
        if session and not session.closed:
            await session.close()

    if unload_ok:
        LOGGER.info(
            "UniFi Gateway Dashboard Analyzer unloaded",
            extra={"event": "setup", "status": "unloaded", "trace_id": entry.entry_id},
        )
    return unload_ok
