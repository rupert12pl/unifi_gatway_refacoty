from __future__ import annotations

from datetime import datetime
from typing import cast

from homeassistant.helpers.entity import DeviceInfo

from custom_components.unifi_gateway_refactored.const import DOMAIN
from custom_components.unifi_gateway_refactored.coordinator import (
    UniFiGatewayData,
    UniFiGatewayDataUpdateCoordinator,
)
from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewayAlertCountSensor,
    UniFiGatewayDeviceCountSensor,
    UniFiGatewayStatusSensor,
)


class DummyCoordinator:
    def __init__(self, data: UniFiGatewayData) -> None:
        self.data = data
        self.last_update_success = True
        self._listeners: list = []

    @property
    def available(self) -> bool:
        return self.data.available

    def async_add_listener(self, update_callback):
        self._listeners.append(update_callback)

    def async_remove_listener(self, update_callback):
        self._listeners.remove(update_callback)


def _sample_data(available: bool = True) -> UniFiGatewayData:
    return UniFiGatewayData(
        trace_id="abc",
        status="ok",
        controller={"site": "default"},
        health=[{"status": "ok"}],
        alerts=[{"id": 1}],
        devices=[{"id": "a"}, {"id": "b"}],
        errors=[],
        last_updated=datetime.utcnow(),
        available=available,
    )


def test_status_sensor_value() -> None:
    coordinator = DummyCoordinator(_sample_data())
    device_info = DeviceInfo(identifiers={(DOMAIN, "instance")})
    sensor = UniFiGatewayStatusSensor(
        cast(UniFiGatewayDataUpdateCoordinator, coordinator),
        device_info,
        "instance",
    )
    assert sensor.native_value == "ok"
    assert sensor.available is True


def test_alert_sensor_counts_active_alerts() -> None:
    coordinator = DummyCoordinator(_sample_data())
    device_info = DeviceInfo(identifiers={(DOMAIN, "instance")})
    sensor = UniFiGatewayAlertCountSensor(
        cast(UniFiGatewayDataUpdateCoordinator, coordinator),
        device_info,
        "instance",
    )
    assert sensor.native_value == 1


def test_device_sensor_unavailable_when_coordinator_down() -> None:
    coordinator = DummyCoordinator(_sample_data(available=False))
    device_info = DeviceInfo(identifiers={(DOMAIN, "instance")})
    sensor = UniFiGatewayDeviceCountSensor(
        cast(UniFiGatewayDataUpdateCoordinator, coordinator),
        device_info,
        "instance",
    )
    assert sensor.available is False
