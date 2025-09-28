from __future__ import annotations

import logging

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_RUNNER, DOMAIN
from .unifi_client import UniFiOSClient
from .utils import build_speedtest_button_unique_id

_LOGGER = logging.getLogger(__name__)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    entry_data = hass.data[DOMAIN].get(entry.entry_id, {})
    client = entry_data.get("client")
    device_name = entry_data.get("device_name") or entry.title or "UniFi Gateway"
    if client is None:
        raise RuntimeError(
            "UniFi Gateway Dashboard Analyzer client missing during button setup"
        )
    async_add_entities(
        [SpeedtestRunButton(hass, entry, client, device_name)], True
    )

class SpeedtestRunButton(ButtonEntity):
    _attr_name = "Run Speedtest"
    _attr_icon = "mdi:speedometer"

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: UniFiOSClient,
        device_name: str,
    ) -> None:
        self.hass = hass
        self._entry = entry
        self._entry_id = entry.entry_id
        self._client = client
        self._device_name = device_name
        self._attr_unique_id = build_speedtest_button_unique_id(self._entry_id)

    async def async_press(self) -> None:
        store = self.hass.data.get(DOMAIN, {})
        entry_data = store.get(self._entry_id)
        if not entry_data:
            _LOGGER.error("Button pressed but entry data missing for %s", self._entry_id)
            return
        runner = entry_data.get(DATA_RUNNER)
        if runner is None:
            _LOGGER.error(
                "Button pressed but speedtest runner missing for %s", self._entry_id
            )
            return
        _LOGGER.info("Button pressed -> triggering Speedtest (runner handles trace).")
        await runner.async_trigger(reason="button")

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
            "configuration_url": self._client.get_controller_url(),
        }
