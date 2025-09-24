from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_RUNNER, DOMAIN

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    async_add_entities([SpeedtestRunButton(hass, entry)], True)


class SpeedtestRunButton(ButtonEntity):
    _attr_name = "Run Speedtest"
    _attr_unique_id = "unifi_gateway_refactored_run_speedtest"
    _attr_icon = "mdi:speedometer"

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        self.hass = hass
        self._entry = entry

    async def async_press(self) -> None:
        store = self.hass.data.get(DOMAIN, {})
        entry_data = store.get(self._entry.entry_id)
        if not entry_data:
            _LOGGER.error("Button pressed but entry data missing for %s", self._entry.entry_id)
            return
        runner = entry_data.get(DATA_RUNNER)
        if runner is None:
            _LOGGER.error("Button pressed but speedtest runner missing for %s", self._entry.entry_id)
            return
        _LOGGER.info("Button pressed -> triggering Speedtest (runner handles trace).")
        await runner.async_trigger(reason="button")
