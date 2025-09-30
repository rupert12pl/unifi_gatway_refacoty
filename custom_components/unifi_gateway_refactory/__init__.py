"""Setup for the UniFi Gateway Refactory integration."""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed, ConfigEntryNotReady
from homeassistant.helpers.issue_registry import (  # type: ignore[attr-defined]
    IssueSeverity,
    async_create_issue,
)

from .const import (
    CONF_SCAN_INTERVAL,
    DATA_COORDINATOR,
    DATA_VERIFY_WARNING,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    ISSUE_LEGACY_DOMAIN,
    LEGACY_DOMAIN,
    PLATFORMS,
)
from .const import (
    CONF_VERIFY_SSL as CONST_VERIFY_SSL,
)
from .coordinator import AuthFailedError, GatewayApiError, UniFiGatewayDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)


def _resolve_option(entry: ConfigEntry, key: str, default: int | bool | str) -> int | bool | str:
    """Return the option or fallback to entry data/default."""

    if key in entry.options:
        return entry.options[key]
    if key in entry.data:
        return entry.data[key]
    return default


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Set up UniFi Gateway from a config entry."""

    hass.data.setdefault(DOMAIN, {})

    verify_ssl = bool(_resolve_option(entry, CONST_VERIFY_SSL, True))
    if not verify_ssl:
        warned_entries: set[str] = hass.data.setdefault(DATA_VERIFY_WARNING, set())
        if entry.entry_id not in warned_entries:
            _LOGGER.warning("SSL certificate verification is disabled for UniFi Gateway")
            warned_entries.add(entry.entry_id)

    scan_interval = int(_resolve_option(entry, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
    coordinator = UniFiGatewayDataUpdateCoordinator(
        hass,
        entry,
        update_interval=timedelta(seconds=max(scan_interval, DEFAULT_SCAN_INTERVAL)),
    )

    try:
        await coordinator.async_config_entry_first_refresh()
    except AuthFailedError as exc:  # pragma: no cover - defensive logging path
        _LOGGER.error("Authentication failed while setting up UniFi Gateway: %s", exc)
        raise ConfigEntryAuthFailed from exc
    except GatewayApiError as exc:  # pragma: no cover - defensive logging path
        _LOGGER.error("Error communicating with UniFi Gateway: %s", exc)
        raise ConfigEntryNotReady from exc

    hass.data[DOMAIN][entry.entry_id] = {DATA_COORDINATOR: coordinator}

    legacy_entries: list[Any] = getattr(
        hass.config_entries, "async_entries", lambda *_: []
    )(LEGACY_DOMAIN)
    if legacy_entries:
        async_create_issue(
            hass,
            DOMAIN,
            ISSUE_LEGACY_DOMAIN,
            breaks_in_ha_version=None,
            is_fixable=False,
            issue_domain=DOMAIN,
            translation_key="legacy_conflict",
            severity=IssueSeverity.WARNING,
            translation_placeholders={
                "domain": LEGACY_DOMAIN,
            },
        )

    forwarder = getattr(hass.config_entries, "async_forward_entry_setups", None)
    if forwarder is not None:
        await forwarder(entry, PLATFORMS)

    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Unload a UniFi Gateway config entry."""

    unload = getattr(hass.config_entries, "async_unload_platforms", None)
    if unload is not None:
        await unload(entry, PLATFORMS)

    if entry.entry_id in hass.data.get(DOMAIN, {}):
        hass.data[DOMAIN].pop(entry.entry_id)
    return True
