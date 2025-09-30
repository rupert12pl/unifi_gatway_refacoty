"""Binary sensors for UniFi Gateway Refactory."""
from __future__ import annotations

from typing import Any, cast

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import IntegrationRuntime
from .const import DOMAIN
from .coordinator import UniFiGatewayCoordinator, UniFiGatewayData


def _get_subsystem(data: UniFiGatewayData, subsystem: str) -> dict[str, Any]:
    for item in data.health:
        if isinstance(item, dict) and item.get("subsystem") == subsystem:
            return item
    return {}


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Set up UniFi Gateway binary sensors."""
    runtime = cast(IntegrationRuntime, hass.data[DOMAIN][entry.entry_id])
    coordinator: UniFiGatewayCoordinator = runtime.coordinator
    async_add_entities([UniFiGatewayWanOnlineBinarySensor(coordinator, entry.entry_id)])


class UniFiGatewayWanOnlineBinarySensor(
    CoordinatorEntity[UniFiGatewayCoordinator], BinarySensorEntity
):
    """Binary sensor indicating WAN availability."""

    _attr_has_entity_name = True
    _attr_translation_key = "wan_online"

    def __init__(self, coordinator: UniFiGatewayCoordinator, entry_id: str) -> None:
        super().__init__(coordinator)
        self._attr_unique_id = f"{entry_id}_wan_online"

    @property
    def available(self) -> bool:
        return bool(self.coordinator.last_update_success)

    @property
    def is_on(self) -> bool | None:
        data = self.coordinator.data
        if not data:
            return None
        subsystem = _get_subsystem(data, "wan")
        status = str(subsystem.get("status") or "")
        return status.lower() in {"ok", "connected", "online"}

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        data = self.coordinator.data
        if not data:
            return None
        subsystem = _get_subsystem(data, "wan")
        return {
            "status": subsystem.get("status"),
            "status_translated": subsystem.get("status_translated"),
        }
