"""Home Assistant setup for the UniFi Gateway Refactory integration."""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, cast

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_HOST, CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers import issue_registry as ir
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.typing import ConfigType
from homeassistant.helpers.update_coordinator import UpdateFailed

from .const import (
    CONF_SCAN_INTERVAL,
    CONF_SITE,
    CONF_VERIFY_SSL,
    DATA_SSL_WARNING_EMITTED,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    LEGACY_DOMAIN,
    PLATFORMS,
)
from .coordinator import UniFiGatewayApi, UniFiGatewayCoordinator

_LOGGER = logging.getLogger(__name__)


async def async_setup(hass: HomeAssistant, _config: ConfigType) -> bool:
    """Set up the integration from YAML (not supported)."""
    hass.data.setdefault(DOMAIN, {})
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Gateway Refactory from a config entry."""
    hass.data.setdefault(DOMAIN, {})

    options = {
        CONF_SCAN_INTERVAL: entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        CONF_VERIFY_SSL: entry.options.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    }

    verify_ssl = options[CONF_VERIFY_SSL]
    if not verify_ssl:
        _log_ssl_warning_once(hass)

    session = async_get_clientsession(hass, verify_ssl=verify_ssl)

    api = UniFiGatewayApi(
        session=session,
        host=entry.data[CONF_HOST],
        username=entry.data[CONF_USERNAME],
        password=entry.data[CONF_PASSWORD],
        site=entry.data.get(CONF_SITE, DEFAULT_SITE),
        verify_ssl=verify_ssl,
    )

    coordinator = UniFiGatewayCoordinator(
        hass=hass,
        api=api,
        update_interval_seconds=options[CONF_SCAN_INTERVAL],
    )

    try:
        await coordinator.async_config_entry_first_refresh()
    except ConfigEntryAuthFailed:
        raise
    except UpdateFailed as err:
        raise ConfigEntryNotReady(str(err)) from err

    hass.data[DOMAIN][entry.entry_id] = IntegrationRuntime(
        coordinator=coordinator,
        api=api,
        options=options,
    )

    await _async_check_legacy_conflict(hass)

    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)

    entry.async_on_unload(entry.add_update_listener(_sync_update_listener))

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a config entry."""
    unload_ok = cast(bool, await hass.config_entries.async_unload_platforms(entry, PLATFORMS))
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        await _async_check_legacy_conflict(hass)
    return unload_ok


async def async_update_options(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Handle options update."""
    runtime = hass.data[DOMAIN].get(entry.entry_id)
    if not runtime:
        return

    options = {
        CONF_SCAN_INTERVAL: entry.options.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
        CONF_VERIFY_SSL: entry.options.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
    }
    runtime.options = options

    runtime.coordinator.update_interval_seconds = options[CONF_SCAN_INTERVAL]

    verify_ssl = options[CONF_VERIFY_SSL]
    if runtime.api.verify_ssl != verify_ssl:
        session = async_get_clientsession(hass, verify_ssl=verify_ssl)
        runtime.api.update_client_session(session, verify_ssl=verify_ssl)
        if not verify_ssl:
            _log_ssl_warning_once(hass)


async def _async_check_legacy_conflict(hass: HomeAssistant) -> None:
    """Detect conflicting legacy integrations and create a repair issue."""
    has_legacy = bool(hass.config_entries.async_entries(LEGACY_DOMAIN))
    issue_id = "legacy_conflict"
    if has_legacy:
        ir.async_create_issue(
            hass,
            DOMAIN,
            issue_id,
            is_fixable=False,
            severity=ir.IssueSeverity.WARNING,
            translation_key="legacy_conflict",
        )
    else:
        ir.async_delete_issue(hass, DOMAIN, issue_id)


def _log_ssl_warning_once(hass: HomeAssistant) -> None:
    """Log a warning exactly once when SSL verification is disabled."""
    domain_data = hass.data.setdefault(DOMAIN, {})
    if domain_data.get(DATA_SSL_WARNING_EMITTED):
        return
    domain_data[DATA_SSL_WARNING_EMITTED] = True
    _LOGGER.warning(
        "SSL verification for UniFi Gateway Refactory has been disabled. This "
        "reduces connection security."
    )


@dataclass
class IntegrationRuntime:
    """Runtime container for an active config entry."""

    coordinator: UniFiGatewayCoordinator
    api: UniFiGatewayApi
    options: dict[str, Any]


def _sync_update_listener(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """Schedule async option handling when entry options change."""
    hass.async_create_task(async_update_options(hass, entry))
