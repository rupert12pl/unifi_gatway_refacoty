from types import SimpleNamespace

from custom_components.unifi_gateway_refactored.sensor import (
    _extract_ip_from_value,
    UniFiGatewayLanClientsSensor,
    UniFiGatewaySubsystemSensor,
    UniFiGatewayWanStatusSensor,
    UniFiGatewayWanIpv6Sensor,
    UniFiGatewayWlanClientsSensor,
)


class _StubClient:
    def instance_key(self) -> str:
        return "stub"

    def get_site(self) -> str:
        return "Site"

    def get_controller_url(self):
        return None


def _make_data(**overrides):
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
    assert _extract_ip_from_value(["192.0.2.1", "2001:db8::1"], version=4) == "192.0.2.1"
    assert _extract_ip_from_value(["192.0.2.1", "2001:db8::1"], version=6) == "2001:db8::1"
    assert _extract_ip_from_value("2001:db8::5/64", version=6) == "2001:db8::5"
    assert _extract_ip_from_value("192.0.2.5/24", version=4) == "192.0.2.5"
    assert _extract_ip_from_value("192.0.2.5", version=6) is None


def test_extract_ip_from_value_prefers_non_link_local_ipv6():
    assert (
        _extract_ip_from_value(
            ["fe80::1/64", "2001:db8::1/64", "fe80::2"], version=6
        )
        == "2001:db8::1"
    )
    assert (
        _extract_ip_from_value(
            [
                {"address": "fe80::1/64"},
                {"address": "2001:db8::2/64"},
                {"address": "fe80::2"},
            ],
            version=6,
        )
        == "2001:db8::2"
    )
    assert (
        _extract_ip_from_value(
            ["fe80::3", {"ip": "fe80::4"}, "2001:db8::5"], version=6
        )
        == "2001:db8::5"
    )


def test_extract_ip_from_value_handles_scope_id_suffixes():
    assert _extract_ip_from_value("fe80::1%wan", version=6) == "fe80::1"
    assert (
        _extract_ip_from_value(["fe80::2%wan", "2001:db8::2%wan"], version=6)
        == "2001:db8::2"
    )
    assert (
        _extract_ip_from_value(["fe80::3%eth0"], version=6)
        == "fe80::3"
    )
    assert _extract_ip_from_value("fe80::4%eth0/64", version=6) == "fe80::4"
    assert _extract_ip_from_value("2001:db8::5%eth0/64", version=6) == "2001:db8::5"


def test_lan_sensor_reports_ipv6_attribute():
    network = {
        "_id": "lan-1",
        "name": "LAN",
        "subnet": "192.168.1.1/24",
        "cidr": "2001:db8::1/64",
        "inet6": ["fe80::1/64", "2001:db8::1/64"],
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
    network = {
        "name": "Corporate",
        "vlan": 10,
        "cidr": "2001:db8:5::1/64",
        "inet6": ["fe80::10/64", "2001:db8:5::1/64"],
    }
    wlan = {
        "name": "WiFi",
        "networkconf_id": "net-1",
        "ipv6_address": "fe80::5",
        "ip6": ["fe80::5", "2001:db8:5::5"],
    }
    data = _make_data(network_map={"net-1": network}, wlans=[wlan])
    coordinator = SimpleNamespace(data=data)
    sensor = UniFiGatewayWlanClientsSensor(
        coordinator, _StubClient(), "entry-id", dict(wlan)
    )

    attrs = sensor.extra_state_attributes

    assert attrs["ipv6_address"] == "2001:db8:5::1"


def test_wan_ipv6_sensor_reports_details():
    link = {
        "id": "wan1",
        "name": "WAN",
        "wan_ipv6": ["fe80::1", "2001:db8::1"],
    }
    health = {
        "id": "wan1",
        "wan_ipv6": ["fe80::2", "2001:db8::2"],
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
