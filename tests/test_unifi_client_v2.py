"""Tests for UniFiOSClient helpers that integrate with the v2 UniFi APIs."""

from __future__ import annotations

import types
from pathlib import Path
from typing import List

import pytest

import sys


sys.path.append(str(Path(__file__).resolve().parents[1]))

custom_components = types.ModuleType("custom_components")
custom_components.__path__ = [
    str(Path(__file__).resolve().parents[1] / "custom_components")
]
sys.modules.setdefault("custom_components", custom_components)

ugw_package = types.ModuleType("custom_components.unifi_gateway_refactored")
ugw_package.__path__ = [
    str(
        Path(__file__).resolve().parents[1]
        / "custom_components"
        / "unifi_gateway_refactored"
    )
]
sys.modules.setdefault("custom_components.unifi_gateway_refactored", ugw_package)

ha_const = types.ModuleType("homeassistant.const")
ha_const.Platform = type(
    "Platform",
    (),
    {"SENSOR": "sensor", "BINARY_SENSOR": "binary_sensor"},
)
sys.modules.setdefault("homeassistant", types.ModuleType("homeassistant"))
sys.modules.setdefault("homeassistant.const", ha_const)

from custom_components.unifi_gateway_refactored.unifi_client import (  # type: ignore  # noqa: E402
    APIError,
    UniFiOSClient,
)


def _build_client() -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._site_name = "default"
    client._api_error_log_state = {}
    return client


def test_get_vpn_remote_users_prefers_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure VPN remote users are fetched from the v2 endpoint when available."""

    client = _build_client()
    calls: List[str] = []

    def _fake_get(path: str, *, timeout: int | None = None) -> dict:
        calls.append(path)
        if path.endswith("v2/api/site/default/vpn/remote-access/users"):
            return {"users": [{"id": "user1"}]}
        raise APIError("not found", expected=True)

    monkeypatch.setattr(client, "_get", _fake_get)

    users = client.get_vpn_remote_users()

    assert calls[0].endswith("v2/api/site/default/vpn/remote-access/users")
    assert users == [{"id": "user1"}]


def test_get_vpn_peers_status_prefers_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure VPN peer status is retrieved from the v2 API when present."""

    client = _build_client()
    calls: List[str] = []

    def _fake_get(path: str, *, timeout: int | None = None) -> dict:
        calls.append(path)
        if path.endswith("v2/api/site/default/vpn/site-to-site/peers"):
            return {"peers": [{"id": "peer-1"}]}
        raise APIError("not found", expected=True)

    monkeypatch.setattr(client, "_get", _fake_get)

    peers = client.get_vpn_peers_status()

    assert calls[0].endswith("v2/api/site/default/vpn/site-to-site/peers")
    assert peers == [{"id": "peer-1"}]


def test_get_wan_links_prefers_v2(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure WAN links prefer the modern v2 endpoint when available."""

    client = _build_client()
    calls: List[str] = []

    def _fake_get_list(path: str, *, timeout: int | None = None) -> list:
        calls.append(path)
        if path.endswith("v2/api/site/default/internet/wan/links"):
            return [{"id": "wan"}]
        return []

    monkeypatch.setattr(client, "_get_list", _fake_get_list)

    links = client.get_wan_links()

    assert calls[0].endswith("v2/api/site/default/internet/wan/links")
    assert links == [{"id": "wan"}]
