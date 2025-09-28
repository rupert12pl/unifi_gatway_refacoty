from unittest.mock import patch

from custom_components.unifi_gateway_refactored.sensor import (
    _format_vpn_connected_clients,
)


def test_format_vpn_connected_clients_extracts_values():
    raw = {
        "connected_clients": [
            {
                "name": "Client A",
                "remote_ip": "1.2.3.4",
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
        ]
    }

    with patch(
        "custom_components.unifi_gateway_refactored.sensor._lookup_remote_ip_whois",
        side_effect=[
            {"city": "Poznań", "country": "Poland", "isp": "ISP Name A"},
            {"city": "Munich", "country": "Germany", "isp": "ISP Name B"},
        ],
    ):
        assert _format_vpn_connected_clients(raw) == [
            "Client A ~ 1.2.3.4 | 10.0.0.5 | Poland | Poznań | ISP Name A",
            "Client B ~ 5.6.7.8 | 10.0.0.6 | Germany | Munich | ISP Name B",
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
