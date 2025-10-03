"""Test VPN client functionality in sensors."""

from types import SimpleNamespace
from unittest.mock import patch

from custom_components.unifi_gateway_refactored.sensor import (
    UniFiGatewayVpnUsageSensor,
    _collect_vpn_connected_clients_details,
    _format_vpn_connected_clients,
    _prepare_connected_clients_output,
)


def test_format_vpn_connected_clients_extracts_values():
    """Test that VPN client formatting extracts correct values."""
    raw = {
        "connected_clients": [
            {
                "name": "Client A",
                "remoteIP": "1.2.3.4",
                "remote_ipv6": "2001:db8::1",
                "assigned_ip": "10.0.0.5",
                "assigned_ipv6": "fd00::5",
                "geoip": {
                    "country": "Poland",
                    "city": "Warsaw",
                    "isp": "ISP1",
                },
            },
            {
                "user": "Client B",
                "public_ip": "5.6.7.8",
                "public_ipv6": "2001:db8::2",
                "client": {"ip": "10.0.0.6"},
                "client_ipv6": "fd00::6",
                "ip_geo": {
                    "country_name": "Germany",
                    "region": "Berlin",
                },
                "isp_info": {"organization": "ISP2"},
            },
            {
                "user-name": "Client C",
                "remote_addr_ipv6": "2001:db8::3",
                "details": {"local_ip": "10.0.0.7"},
                "metadata": {
                    "local_ipv6": "fd00::7",
                    "country": "France",
                    "city": "Paris",
                    "isp_provider": "ISP3",
                },
            },
        ]
    }

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_geolocation",
        side_effect=[{}, {}, {}],
    ), patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        side_effect=[
            {"city": "Poznań", "country": "Poland", "isp": "ISP Name A"},
            {"city": "Munich", "country": "Germany", "isp": "ISP Name B"},
            {"city": "Lyon", "country": "France", "isp": "ISP Name C"},
        ],
    ):
        assert _format_vpn_connected_clients(raw) == [
            "Client A ~ 1.2.3.4 | 2001:db8::1 | 10.0.0.5 | fd00::5 | Poland | Poznań | ISP Name A",
            "Client B ~ 5.6.7.8 | 2001:db8::2 | 10.0.0.6 | fd00::6 | Germany | Munich | ISP Name B",
            "Client C ~ Unknown | 2001:db8::3 | 10.0.0.7 | fd00::7 | France | Lyon | ISP Name C",
        ]


def test_format_vpn_connected_clients_handles_missing_fields():
    """Test that VPN client formatting handles missing fields correctly."""
    raw = {
        "clients": {
            "items": [
                {
                    "name": "Client C",
                }
            ]
        }
    }

    assert _format_vpn_connected_clients(raw) == [
        "Client C ~ Unknown | Unknown | Unknown | Unknown | Unknown | Unknown | Unknown"
    ]


def test_format_vpn_connected_clients_keeps_existing_city_when_whois_lacks_city():
    """Test that VPN client formatting preserves existing city when WHOIS data lacks it."""
    raw = {
        "connected_clients": [
            {
                "name": "Client A",
                "remoteIP": "1.1.1.1",
                "assigned_ip": "10.0.0.5",
                "geoip": {"city": "Initial City"},
            }
        ]
    }

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_geolocation",
        return_value={},
    ), patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        return_value={"state": "Fallback State"},
    ):
        formatted = _format_vpn_connected_clients(raw)

    assert formatted == [
        (
            "Client A ~ 1.1.1.1 | Unknown | 10.0.0.5 | "
            "Unknown | Fallback State | Initial City | Unknown"
        )
    ]


def test_prepare_connected_clients_output_merges_remote_ip_columns_in_html():
    """Test that connected clients output merges remote IP columns in HTML format."""
    raw = {
        "connected_clients": [
            {
                "name": "Client A",
                "remoteIP": "1.2.3.4",
                "remote_ipv6": "2001:db8::1",
                "assigned_ip": "10.0.0.5",
            },
            {
                "name": "Client B",
                "remoteIP": "5.6.7.8",
                "remote_ipv6": "Unknown",
                "assigned_ip": "10.0.0.6",
            },
        ]
    }

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_geolocation",
        return_value={},
    ), patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        return_value={},
    ):
        _, html_value = _prepare_connected_clients_output(raw)

    assert "Remote IPv6" not in html_value
    assert html_value.count("<th") == 6
    assert "1.2.3.4" in html_value
    assert "2001:db8::1" in html_value
    assert "5.6.7.8" in html_value
    assert "Unknown" not in html_value.split("5.6.7.8", 1)[1].split("</td>")[0]
    assert "Internal IPv6" not in html_value


def test_connected_clients_city_uses_ipv6_when_ipv4_lookup_empty():
    """Test that connected clients use IPv6 for city lookup when IPv4 lookup is empty."""
    raw = {
        "connected_clients": [
            {
                "name": "Client IPv6",
                "remoteIP": "1.2.3.4",
                "remote_ipv6": "2001:db8::10",
                "assigned_ip": "10.0.0.8",
                "assigned_ipv6": "fd00::8",
            }
        ]
    }

    def geolocation_side_effect(remote_ip: str):
        if ":" in remote_ip:
            return {"city": "Poznań", "country": "Poland", "isp": "IPv6 ISP"}
        return {}

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_geolocation",
        side_effect=geolocation_side_effect,
    ), patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        return_value={},
    ):
        details = _collect_vpn_connected_clients_details(raw)

    assert details[0]["city"] == "Poznań"
    assert details[0]["country"] == "Poland"
    assert details[0]["isp"] == "IPv6 ISP"


class _DummyClient:
    def instance_key(self) -> str:
        return "dummy"


def test_vpn_sensor_attribute_display_names():
    """Test that VPN sensor has correct attribute display names."""
    sensor = UniFiGatewayVpnUsageSensor(
        coordinator=SimpleNamespace(data=None),
        client=_DummyClient(),
        entry_id="entry-id",
        base_name="Gateway",
        server={},
        linked_network={},
        unique_id="unique",
    )

    assert sensor.extra_state_attribute_names == {
        "connected_clients": "Connected Clients",
        "connected_clients_html": "Connected Clients HTML",
    }

    sensor._connected_clients_html = "<p>content</p>"

    assert sensor.extra_state_attribute_names == {
        "connected_clients": "Connected Clients",
        "connected_clients_html": "Connected Clients HTML",
    }
