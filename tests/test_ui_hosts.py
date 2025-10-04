import uuid
from unittest.mock import MagicMock

from custom_components.unifi_gateway_refactored.coordinator import (
    _merge_wan_links_with_ui_hosts,
)
from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


def test_normalize_ui_host_wan_extracts_details():
    host = {"id": "host-1", "name": "Gateway"}
    entry = {
        "id": "wan1",
        "wan_ipv6": ["fe80::1", "2001:db8::1"],
        "wan_ipv6_prefix": "2001:db8::/64",
        "gateway_ipv6": "fe80::1",
        "wan_ip": "198.51.100.5",
        "isp": "Example ISP",
    }

    normalized = UniFiOSClient._normalize_ui_host_wan(host, entry)

    assert normalized is not None
    assert normalized["id"] == "wan1"
    assert normalized["name"] == "wan1"
    assert normalized["ui_host_id"] == "host-1"
    assert normalized["ui_host_name"] == "Gateway"
    assert normalized["wan_ipv6"] == ["fe80::1", "2001:db8::1"]
    assert normalized["last_ipv6"] == ["fe80::1", "2001:db8::1"]
    assert normalized["wan_ipv6_prefix"] == "2001:db8::/64"
    assert normalized["gateway_ipv6"] == "fe80::1"
    assert normalized["wan_ip"] == "198.51.100.5"
    assert normalized["last_ipv4"] == "198.51.100.5"
    assert normalized["isp"] == "Example ISP"
    assert normalized["ui_host_source"] == "ui_host"


def test_normalize_ui_host_wan_ignores_placeholder_values():
    host = {"id": "host-1"}
    entry = {"id": "wan1", "wan_ipv6": "Unknown"}

    normalized = UniFiOSClient._normalize_ui_host_wan(host, entry)

    assert normalized is None


def test_merge_wan_links_with_ui_hosts_enriches_existing_links():
    wan_links = [{"id": "wan1", "name": "WAN"}]
    remote = [
        {
            "id": "wan1",
            "wan_ipv6": "2001:db8::2",
            "gateway_ipv6": "fe80::1",
            "wan_ipv6_prefix": "2001:db8::/64",
        }
    ]

    merged = _merge_wan_links_with_ui_hosts(wan_links, remote)

    assert len(merged) == 1
    assert merged[0]["wan_ipv6"] == "2001:db8::2"
    assert merged[0]["gateway_ipv6"] == "fe80::1"
    assert merged[0]["wan_ipv6_prefix"] == "2001:db8::/64"


def test_merge_wan_links_with_ui_hosts_preserves_existing_values():
    wan_links = [{"id": "wan1", "wan_ipv6": "2001:db8::5"}]
    remote = [
        {
            "id": "wan1",
            "wan_ipv6": "Unknown",
            "gateway_ipv6": "fe80::5",
        }
    ]

    merged = _merge_wan_links_with_ui_hosts(wan_links, remote)

    assert len(merged) == 1
    assert merged[0]["wan_ipv6"] == "2001:db8::5"
    assert merged[0]["gateway_ipv6"] == "fe80::5"


def test_merge_wan_links_with_ui_hosts_when_no_local_links():
    remote = [
        {
            "id": "wan1",
            "wan_ipv6": "2001:db8::3",
            "gateway_ipv6": "fe80::3",
        }
    ]

    merged = _merge_wan_links_with_ui_hosts([], remote)

    assert merged == remote


def test_fetch_ui_hosts_enforces_ssl_verification(monkeypatch):
    monkeypatch.setattr(
        UniFiOSClient,
        "_login",
        lambda self, host, port, ssl_verify, timeout: None,
    )
    monkeypatch.setattr(
        UniFiOSClient,
        "_ensure_connected",
        lambda self: None,
    )
    dummy_password = uuid.uuid4().hex
    client = UniFiOSClient("example.com", username="user", password=dummy_password)
    response = MagicMock(status_code=200, text="[]")
    session_get = MagicMock(return_value=response)
    client._session.get = session_get

    assert client._fetch_ui_hosts() == []

    session_get.assert_called_once()
    _, kwargs = session_get.call_args
    assert kwargs["verify"] is True
