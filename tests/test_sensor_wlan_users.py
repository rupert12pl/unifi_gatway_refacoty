from __future__ import annotations

from dataclasses import replace

from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData
from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewaySubsystemSensor,
)


class DummyCoordinator:
    def __init__(self, hass, data: UniFiGatewayData) -> None:
        self.hass = hass
        self.data = data

    def async_add_listener(self, _callback):  # pragma: no cover - not used in tests
        return lambda: None


class DummyClient:
    def instance_key(self) -> str:
        return "test"

    def get_controller_url(self) -> str:
        return "https://unifi.local"

    def get_site(self) -> str:
        return "default"


def _build_wlan_data() -> UniFiGatewayData:
    return UniFiGatewayData(
        controller={"url": "https://unifi.local", "api_url": "https://unifi.local/api", "site": "default"},
        health=[],
        health_by_subsystem={
            "wlan": {
                "subsystem": "wlan",
                "num_user": 1,
                "num_guest": 9,
                "num_iot": 9,
            }
        },
        wlans=[
            {"name": "Home WiFi"},
            {"name": "Home WiFi Guest"},
            {"name": "Home WiFi IoT"},
        ],
        clients=[
            {"essid": "Home WiFi"},
            {"wifi_network": "Home WiFi"},
            {"essid": "Home WiFi"},
            {"essid": "Home WiFi Guest"},
            {"ap_essid": "Home WiFi IoT"},
            {"essid": "Home WiFi IoT"},
        ],
    )


def test_wlan_subsystem_overrides_counts(hass) -> None:
    data = _build_wlan_data()
    coordinator = DummyCoordinator(hass, data)
    client = DummyClient()

    sensor = UniFiGatewaySubsystemSensor(
        coordinator,
        client,
        "wlan",
        "WLAN",
        "mdi:wifi",
        device_name="Gateway",
        wifi_overrides={"guest": "Home WiFi Guest", "iot": "Home WiFi IoT"},
    )

    attrs = sensor.extra_state_attributes

    assert attrs["num_user"] == 3
    assert attrs["user"] == 3
    assert attrs["num_guest"] == 1
    assert attrs["user_guest"] == 1
    assert attrs["num_iot"] == 2
    assert attrs["user_iot"] == 2
    assert attrs["num_user_total"] == 6
    assert attrs["user_total"] == 6


def test_wlan_subsystem_preserves_counts_without_overrides(hass) -> None:
    data = replace(
        _build_wlan_data(),
        health_by_subsystem={
            "wlan": {
                "subsystem": "wlan",
                "num_user": 4,
                "num_guest": 2,
                "num_iot": 1,
            }
        },
    )
    coordinator = DummyCoordinator(hass, data)
    client = DummyClient()

    sensor = UniFiGatewaySubsystemSensor(
        coordinator,
        client,
        "wlan",
        "WLAN",
        "mdi:wifi",
        device_name="Gateway",
        wifi_overrides=None,
    )

    attrs = sensor.extra_state_attributes

    assert attrs["num_user"] == 4
    assert attrs["user_guest"] == 2
    assert attrs["user_iot"] == 1
    assert attrs["num_user_total"] == 7
    assert attrs["user_total"] == 7
