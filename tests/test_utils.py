"""Tests for utility helpers."""

import pytest

from custom_components.unifi_gateway_refactored.utils import normalize_host_port


@pytest.mark.parametrize(
    "host,port,expected_host,expected_port",
    [
        ("https://controller.local", None, "controller.local", 443),
        ("https://controller.local:8443", None, "controller.local", 8443),
        ("controller.local:7443", 443, "controller.local", 7443),
        ("controller.local/network/site", None, "controller.local", None),
        ("http://controller.local", 18443, "controller.local", 18443),
        ("[2001:db8::1]:9443", None, "2001:db8::1", 9443),
        ("https://[2001:db8::2]", None, "2001:db8::2", 443),
        (" ", 443, None, 443),
        (None, None, None, None),
    ],
)
def test_normalize_host_port(host, port, expected_host, expected_port):
    result_host, result_port = normalize_host_port(host, port)
    assert result_host == expected_host
    assert result_port == expected_port
