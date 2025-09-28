from types import SimpleNamespace
from unittest.mock import patch

from custom_components.unifi_gateway_refactored.sensor import (
    _format_vpn_connected_clients,
    UniFiGatewayVpnUsageSensor,
)


def test_format_vpn_connected_clients_extracts_values():
    raw = {
        "connected_clients": [
            {
                "name": "Client A",
                "remoteIP": "1.2.3.4",
                "assigned_ip": "10.0.0.5",
                "geoip": {
                    "country": "Poland",
                    "city": "Warsaw",
                    "isp": "ISP1",
                },
            },
            {
                "user": "Client B",
                "public_ip": "5.6.7.8",
                "client": {"ip": "10.0.0.6"},
                "ip_geo": {
                    "country_name": "Germany",
                    "region": "Berlin",
                },
                "isp_info": {"organization": "ISP2"},
            },
            {
                "user-name": "Client C",
                "remote_addr": "9.10.11.12",
                "details": {"local_ip": "10.0.0.7"},
                "metadata": {
                    "country": "France",
                    "city": "Paris",
                    "isp_provider": "ISP3",
                },
            },
        ]
    }

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        side_effect=[
            {"city": "Poznań", "country": "Poland", "isp": "ISP Name A"},
            {"city": "Munich", "country": "Germany", "isp": "ISP Name B"},
            {"city": "Lyon", "country": "France", "isp": "ISP Name C"},
        ],
    ):
        assert _format_vpn_connected_clients(raw) == [
            "Client A ~ 1.2.3.4 | 10.0.0.5 | Poland | Poznań | ISP Name A",
            "Client B ~ 5.6.7.8 | 10.0.0.6 | Germany | Munich | ISP Name B",
            "Client C ~ 9.10.11.12 | 10.0.0.7 | France | Lyon | ISP Name C",
        ]


def test_format_vpn_connected_clients_handles_missing_fields():
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
        "Client C ~ Unknown | Unknown | Unknown | Unknown | Unknown"
    ]


class _DummyClient:
    def instance_key(self) -> str:
        return "dummy"


def test_vpn_sensor_attribute_display_names():
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
