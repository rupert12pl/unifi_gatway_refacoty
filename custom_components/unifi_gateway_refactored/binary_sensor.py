from __future__ import annotations

import logging

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:
    """Set up UniFi Gateway binary sensors (none required)."""

    _LOGGER.debug(
        "No binary sensors to set up for UniFi Gateway entry %s", entry.entry_id
    )
    # This integration currently exposes only sensor entities.
    return
