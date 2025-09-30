"""Binary sensor entities for UniFi Gateway Refactory."""
from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import UniFiGatewayDataUpdateCoordinator, UniFiGatewayMetrics


class UniFiGatewayWanOnlineSensor(
    CoordinatorEntity[UniFiGatewayMetrics], BinarySensorEntity
):
    """Binary sensor reporting WAN connectivity."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        entry: ConfigEntry,
    ) -> None:
        super().__init__(coordinator)
        self._attr_name = "UniFi WAN Online"
        self._attr_unique_id = f"{entry.entry_id}_wan_online"
        self._attr_icon = "mdi:wan"

    @property
    def is_on(self) -> bool | None:
        metrics = self.coordinator.data
        if not metrics:
            return None
        status = metrics.wan.get("status")
        if isinstance(status, str):
            return status.lower() in {"ok", "online", "connected"}
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        metrics = self.coordinator.data
        if not metrics:
            return {}
        return {
            "latency_ms": metrics.wan.get("latency_ms"),
            "packet_loss_pct": metrics.wan.get("packet_loss_pct"),
        }


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities
) -> None:  # type: ignore[override]
    """Set up binary sensors from a config entry."""

    data = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    if not data:
        return
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]
    async_add_entities([UniFiGatewayWanOnlineSensor(coordinator, entry)])
