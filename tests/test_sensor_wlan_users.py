"""Test WLAN user functionality in sensors."""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, cast

from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData
from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewaySubsystemSensor,
)

if TYPE_CHECKING:
    from custom_components.unifi_gateway_refactored.coordinator import (
        UniFiGatewayDataUpdateCoordinator,
    )
    from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


class DummyCoordinator:
    """Test double for DataUpdateCoordinator."""

    def __init__(self, hass, data: UniFiGatewayData) -> None:
        """Initialize coordinator with test data."""
        self.hass = hass
        self.data = data

    def async_add_listener(self, _callback):  # pragma: no cover - not used in tests
        """Add listener for update notifications."""
        return lambda: None


class DummyClient:
    """Test double for UniFi client."""

    def instance_key(self) -> str:
        """Get unique instance key."""
        return "test"

    def get_controller_url(self) -> str:
        """Get controller URL for UniFi device."""
        return "https://unifi.local"

    def get_site(self) -> str:
        """Get site name for UniFi device."""
        return "default"


def _build_wlan_data() -> UniFiGatewayData:
    """Build test data for WLAN functionality tests.

    Returns:
        UniFiGatewayData: Test data object with WLAN configuration.

    """
    return UniFiGatewayData(
        controller={
            "url": "https://unifi.local",
            "api_url": "https://unifi.local/api",
            "site": "default"
        },
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
    """Test that WLAN subsystem correctly overrides user counts."""
    data = _build_wlan_data()
    coordinator = DummyCoordinator(hass, data)
    client = DummyClient()

    sensor = UniFiGatewaySubsystemSensor(
        cast("UniFiGatewayDataUpdateCoordinator", coordinator),
        cast("UniFiOSClient", client),
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
    """Test that WLAN subsystem preserves user counts when no overrides exist."""
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
        cast("UniFiGatewayDataUpdateCoordinator", coordinator),
        cast("UniFiOSClient", client),
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
