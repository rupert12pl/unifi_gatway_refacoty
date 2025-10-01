"""Sensor platform for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import CONF_HOST, DATA_CLIENT, DATA_COORDINATOR, DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiApiClient


@dataclass
class _EntityDescription:
    key: str
    name: str
    icon: str | None = None
    state_class: SensorStateClass | None = None


STATUS_SENSOR = _EntityDescription(
    key="status", name="Gateway Status", icon="mdi:lan-connect"
)
ALERT_SENSOR = _EntityDescription(
    key="alerts",
    name="Active Alerts",
    icon="mdi:alert",
    state_class=SensorStateClass.MEASUREMENT,
)
DEVICE_SENSOR = _EntityDescription(
    key="devices",
    name="Known Devices",
    icon="mdi:access-point",
    state_class=SensorStateClass.MEASUREMENT,
)


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    entry_store = hass.data[DOMAIN][entry.entry_id]
    coordinator: UniFiGatewayDataUpdateCoordinator = entry_store[DATA_COORDINATOR]
    client: UniFiApiClient = entry_store[DATA_CLIENT]
    instance_key = client.instance_key()

    device_name = entry.title or entry.data.get(CONF_HOST, "UniFi Gateway")
    device_info = DeviceInfo(
        identifiers={(DOMAIN, instance_key)},
        manufacturer="Ubiquiti",
        model="UniFi Gateway",
        name=device_name,
        configuration_url=client.get_controller_url(),
    )

    entities: list[SensorEntity] = [
        UniFiGatewayStatusSensor(coordinator, device_info, instance_key),
        UniFiGatewayAlertCountSensor(coordinator, device_info, instance_key),
        UniFiGatewayDeviceCountSensor(coordinator, device_info, instance_key),
    ]
    async_add_entities(entities)


class BaseUniFiSensor(CoordinatorEntity[UniFiGatewayData], SensorEntity):
    """Base class for UniFi Gateway sensors."""

    entity_description: _EntityDescription

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        description: _EntityDescription,
        device_info: DeviceInfo,
        instance_key: str,
    ) -> None:
        super().__init__(coordinator)
        self.entity_description = description
        self._attr_name = f"{device_info.name} {description.name}"
        self._attr_icon = description.icon
        self._attr_state_class = description.state_class
        self._attr_device_info = device_info
        self._instance_key = instance_key

    @property
    def available(self) -> bool:
        data = self.coordinator.data
        return bool(data and data.available)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data
        if not data:
            return {}
        return {
            "trace_id": data.trace_id,
            "controller_site": data.controller.get("site"),
        }


class UniFiGatewayStatusSensor(BaseUniFiSensor):
    """Reports the overall gateway health state."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        device_info: DeviceInfo,
        instance_key: str,
    ) -> None:
        super().__init__(coordinator, STATUS_SENSOR, device_info, instance_key)
        self._attr_unique_id = f"{instance_key}-status"

    @property
    def native_value(self) -> str | None:
        data = self.coordinator.data
        if not data:
            return None
        return data.status


class UniFiGatewayAlertCountSensor(BaseUniFiSensor):
    """Reports number of active alerts."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        device_info: DeviceInfo,
        instance_key: str,
    ) -> None:
        super().__init__(coordinator, ALERT_SENSOR, device_info, instance_key)
        self._attr_unique_id = f"{instance_key}-alerts"

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        if not data:
            return None
        return len(data.alerts)


class UniFiGatewayDeviceCountSensor(BaseUniFiSensor):
    """Reports number of known devices."""

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        device_info: DeviceInfo,
        instance_key: str,
    ) -> None:
        super().__init__(coordinator, DEVICE_SENSOR, device_info, instance_key)
        self._attr_unique_id = f"{instance_key}-devices"

    @property
    def native_value(self) -> int | None:
        data = self.coordinator.data
        if not data:
            return None
        return len(data.devices)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        data = self.coordinator.data
        if not data:
            return {}
        return {
            "trace_id": data.trace_id,
            "controller_site": data.controller.get("site"),
            "alert_count": len(data.alerts),
        }
