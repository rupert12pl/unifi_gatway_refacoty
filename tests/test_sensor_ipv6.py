"""Test IPv6 functionality in sensors."""

from types import SimpleNamespace

from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewayLanClientsSensor,
    UniFiGatewaySubsystemSensor,
    UniFiGatewayWanIpv6Sensor,
    UniFiGatewayWanStatusSensor,
    UniFiGatewayWlanClientsSensor,
    _extract_ip_from_value,
)


class _StubClient:
    """Stub client implementation for testing."""

    def instance_key(self) -> str:
        """Return a stub instance key."""
        return "stub"

    def get_site(self) -> str:
        """Return a stub site name."""
        return "Site"

    def get_controller_url(self):
        """Return a stub controller URL."""
        return None


def _make_data(**overrides):
    """Create a test data object with default values and optional overrides.

    Args:
        **overrides: Dictionary of values to override default test data.

    Returns:
        SimpleNamespace: A namespace object containing the test data.

    """
    base = {
        "controller": {"url": None, "api_url": None, "site": None},
        "clients": [],
        "lan_networks": [],
        "wan_links": [],
        "wan_health": [],
        "health_by_subsystem": {},
        "network_map": {},
        "wlans": [],
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def test_extract_ip_from_value_filters_by_version():
    """Test IP extraction with version filtering."""
    assert _extract_ip_from_value(["192.0.2.1", "2001:db8::1"], version=4) == "192.0.2.1"
    assert _extract_ip_from_value(["192.0.2.1", "2001:db8::1"], version=6) == "2001:db8::1"
    assert _extract_ip_from_value("2001:db8::5/64", version=6) == "2001:db8::5"
    assert _extract_ip_from_value("192.0.2.5/24", version=4) == "192.0.2.5"
    assert _extract_ip_from_value("192.0.2.5", version=6) is None


def test_lan_sensor_reports_ipv6_attribute():
    """Test that LAN sensor correctly reports IPv6 attributes."""
    network = {
        "_id": "lan-1",
        "name": "LAN",
        "subnet": "192.168.1.1/24",
        "cidr": "2001:db8::1/64",
    }
    data = _make_data(
        lan_networks=[network],
        clients=[{"network_id": "lan-1", "ip": "192.168.1.50"}],
    )
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayLanClientsSensor(
        coordinator, _StubClient(), "entry-id", dict(network)
    )

    attrs = sensor.extra_state_attributes

    assert attrs["ip_address"] == "192.168.1.1"
    assert attrs["ipv6_address"] == "2001:db8::1"


def test_wlan_sensor_uses_network_ipv6_information():
    """Test WLAN sensor's use of network IPv6 information."""
    network = {"name": "Corporate", "vlan": 10, "cidr": "2001:db8:5::1/64"}
    wlan = {"name": "WiFi", "networkconf_id": "net-1", "ipv6_address": "2001:db8:5::5"}
    data = _make_data(network_map={"net-1": network}, wlans=[wlan])
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayWlanClientsSensor(
        coordinator, _StubClient(), "entry-id", dict(wlan)
    )

    attrs = sensor.extra_state_attributes

    assert attrs["ipv6_address"] == "2001:db8:5::1"


def test_wan_ipv6_sensor_reports_details():
    """Test that WAN IPv6 sensor reports correct details."""
    link = {"id": "wan1", "name": "WAN", "wan_ipv6": "2001:db8::1"}
    health = {
        "id": "wan1",
        "wan_ipv6": "2001:db8::2",
        "gateway_ipv6": "fe80::1",
        "wan_ipv6_prefix": "2001:db8::/64",
    }
    data = _make_data(wan_links=[link], wan_health=[health])
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayWanIpv6Sensor(
        coordinator, _StubClient(), "entry-id", dict(link)
    )

    value = sensor.native_value

    assert value == "2001:db8::1"
    attrs = sensor.extra_state_attributes
    assert attrs["last_ipv6"] == "2001:db8::1"
    assert attrs["source"] == "link"
    assert attrs["gateway_ipv6"] == "fe80::1"
    assert attrs["prefix"] == "2001:db8::/64"


def test_wan_ipv6_sensor_ignores_placeholder_values():
    """Test that WAN IPv6 sensor correctly handles placeholder values."""
    link = {"id": "wan1", "name": "WAN", "wan_ipv6": "Unknown"}
    health = {
        "id": "wan1",
        "wan_ipv6": "2001:db8::2",
        "gateway_ipv6": "fe80::2",
        "wan_ipv6_prefix": "2001:db8::/60",
    }
    data = _make_data(wan_links=[link], wan_health=[health])
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayWanIpv6Sensor(
        coordinator, _StubClient(), "entry-id", dict(link)
    )

    value = sensor.native_value

    assert value == "2001:db8::2"
    attrs = sensor.extra_state_attributes
    assert attrs["last_ipv6"] == "2001:db8::2"
    assert attrs["source"] == "health"
    assert attrs["gateway_ipv6"] == "fe80::2"
    assert attrs["prefix"] == "2001:db8::/60"


def test_wan_subsystem_sensor_includes_ipv6_attribute():
    """Test that WAN subsystem sensor includes IPv6 attribute."""
    data = _make_data(
        health_by_subsystem={"wan": {"status": "ok", "ipv6": "2001:db8::10"}},
        wan_links=[{"id": "wan1", "name": "WAN"}],
    )
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewaySubsystemSensor(
        coordinator, _StubClient(), "wan", "WAN", "mdi:shield-outline"
    )

    attrs = sensor.extra_state_attributes

    assert attrs["ipv6"] == "2001:db8::10"


def test_wan_status_sensor_reports_ip_sources():
    """Test that WAN status sensor reports correct IP sources."""
    link = {
        "id": "wan1",
        "name": "WAN",
        "status": "up",
        "wan_ip": "198.51.100.2",
    }
    health = {
        "id": "wan1",
        "wan_ipv6": "2001:db8::10",
        "wan_ip": "198.51.100.10",
    }
    data = _make_data(wan_links=[link], wan_health=[health])
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayWanStatusSensor(
        coordinator, _StubClient(), "entry-id", dict(link)
    )

    assert sensor.native_value == "UP"
    attrs = sensor.extra_state_attributes

    assert attrs["ip"] == "198.51.100.2"
    assert attrs["ip_source"] == "wan_link"
    assert attrs["ipv6"] == "2001:db8::10"
    assert attrs["ipv6_source"] == "wan_health"
