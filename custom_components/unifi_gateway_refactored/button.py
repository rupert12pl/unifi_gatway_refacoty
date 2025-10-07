from __future__ import annotations

import asyncio
import inspect
import logging
from collections.abc import Awaitable, Callable

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import EntityCategory
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from .const import DATA_MANUAL_REFRESHERS, DATA_RUNNER, DOMAIN
from .unifi_client import UniFiOSClient
from .utils import (
    build_reset_button_unique_id,
    build_speedtest_button_unique_id,
    build_status_refresh_button_unique_id,
)

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
    coordinator = entry_data.get("coordinator")
    async_add_entities(
        [
            SpeedtestRunButton(hass, entry, client, device_name),
            GatewayResetButton(hass, entry, client, device_name),
            NetworkStatusRefreshButton(
                hass, entry, client, coordinator, device_name
            ),
        ],
        True,
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


class GatewayResetButton(ButtonEntity):
    _attr_name = "Reset Gateway"
    _attr_icon = "mdi:restart"
    _attr_entity_category = EntityCategory.CONFIG

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
        self._attr_unique_id = build_reset_button_unique_id(self._entry_id)

    async def async_press(self) -> None:
        try:
            await self.hass.async_add_executor_job(self._client.restart_gateway)
        except Exception:  # pragma: no cover - defensive logging
            _LOGGER.exception(
                "Failed to trigger gateway reset for entry %s", self._entry_id
            )

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
            "configuration_url": self._client.get_controller_url(),
        }


ManualRefreshCallback = Callable[[], Awaitable[object] | None]


class NetworkStatusRefreshButton(ButtonEntity):
    _attr_name = "Refresh Network Status"
    _attr_icon = "mdi:refresh"
    _attr_entity_category = EntityCategory.DIAGNOSTIC

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        client: UniFiOSClient,
        coordinator,
        device_name: str,
    ) -> None:
        self.hass = hass
        self._entry = entry
        self._entry_id = entry.entry_id
        self._client = client
        self._coordinator = coordinator
        self._device_name = device_name
        self._attr_unique_id = build_status_refresh_button_unique_id(self._entry_id)

    async def async_press(self) -> None:
        store = self.hass.data.get(DOMAIN, {})
        entry_data = store.get(self._entry_id)
        callbacks: set[ManualRefreshCallback] = set()
        if not entry_data:
            _LOGGER.error(
                "Status refresh requested but entry data missing for %s", self._entry_id
            )
        else:
            registered = entry_data.get(DATA_MANUAL_REFRESHERS)
            if isinstance(registered, set):
                callbacks = set(registered)

        tasks: list[Awaitable[object]] = []
        if self._coordinator is not None:
            tasks.append(self._coordinator.async_request_refresh())
        else:
            _LOGGER.error(
                "Status refresh requested but coordinator missing for %s",
                self._entry_id,
            )

        for callback in callbacks:
            try:
                result = callback()
            except Exception:  # pragma: no cover - guard manual callbacks
                _LOGGER.exception(
                    "Manual refresh callback failed for entry %s", self._entry_id
                )
                continue
            if result is None:
                continue
            if inspect.isawaitable(result):
                tasks.append(result)  # type: ignore[arg-type]

        if not tasks:
            return

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for outcome in results:
            if isinstance(outcome, Exception):
                _LOGGER.error(
                    "Error during manual status refresh for entry %s: %s",
                    self._entry_id,
                    outcome,
                )

    @property
    def device_info(self):
        return {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
            "configuration_url": self._client.get_controller_url(),
        }
