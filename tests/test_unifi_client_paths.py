from __future__ import annotations

import time

import pytest

from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


def _make_client(site_name: str = "default", site_id: str | None = "site-guid") -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._site_name = site_name  # type: ignore[attr-defined]
    client._site_id = site_id  # type: ignore[attr-defined]
    client._unavailable_paths = {}  # type: ignore[attr-defined]
    client._supports_stat_alert = None  # type: ignore[attr-defined]
    client._internet_api_supported = None  # type: ignore[attr-defined]
    return client


def test_iter_speedtest_paths_includes_fallbacks() -> None:
    client = _make_client()

    paths = client._iter_speedtest_paths("stat/speedtest/status")

    assert "stat/speedtest/status" in paths
    assert "api/s/default/stat/speedtest/status" in paths
    assert "api/s/site-guid/stat/speedtest/status" in paths
    assert "v2/api/site/default/stat/speedtest/status" in paths
    assert "v2/api/site/site-guid/stat/speedtest/status" in paths


def test_iter_speedtest_paths_avoids_duplicate_prefixes() -> None:
    client = _make_client(site_id="default")

    paths = client._iter_speedtest_paths("api/s/default/stat/speedtest/status")

    assert "api/s/default/stat/speedtest/status" in paths
    assert "stat/speedtest/status" in paths
    assert "v2/api/site/default/stat/speedtest/status" in paths
    for candidate in paths:
        assert "api/s/default/api/s/default" not in candidate
        assert "v2/api/site/default/api/s/default" not in candidate


def test_get_alerts_prefers_list_alarm(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client()

    calls: list[str] = []

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        if self._is_path_unavailable(path):  # type: ignore[attr-defined]
            calls.append(f"skip:{path}")
            return []
        calls.append(path)
        if path.endswith("list/alarm"):
            return [{"id": "alarm"}]
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    alerts = client.get_alerts()

    assert alerts == [{"id": "alarm"}]
    assert calls == ["api/s/default/list/alarm"]


def test_get_alerts_prefers_modern_even_if_legacy_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client()
    client._supports_stat_alert = True  # type: ignore[attr-defined]

    calls: list[str] = []

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        calls.append(path)
        if path.endswith("list/alarm"):
            return [{"id": "alarm"}]
        if path.endswith("stat/alert"):
            pytest.fail("legacy alerts endpoint should not be queried when modern data exists")
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    alerts = client.get_alerts()

    assert alerts == [{"id": "alarm"}]
    assert calls == ["api/s/default/list/alarm"]


def test_get_alerts_marks_stat_alert_support(monkeypatch: pytest.MonkeyPatch) -> None:
    client = _make_client()

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        if path.endswith("stat/alert"):
            return [{"id": "legacy"}]
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    alerts = client.get_alerts()

    assert alerts == [{"id": "legacy"}]
    assert client._supports_stat_alert is True  # type: ignore[attr-defined]


def test_get_alerts_skips_known_unavailable_stat_alert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client()
    expiry = time.monotonic() + 60
    client._unavailable_paths["api/s/default/stat/alert"] = expiry  # type: ignore[index]

    calls: list[str] = []

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        if self._is_path_unavailable(path):  # type: ignore[attr-defined]
            calls.append(f"skip:{path}")
            return []
        calls.append(path)
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    alerts = client.get_alerts()

    assert alerts == []
    assert "api/s/default/stat/alert" not in calls
    assert client._supports_stat_alert is False  # type: ignore[attr-defined]


def test_get_wan_links_disables_internet_api_when_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client()
    expiry = time.monotonic() + 60
    client._unavailable_paths["api/s/default/internet/wan"] = expiry  # type: ignore[index]
    client._unavailable_paths["api/s/default/rest/internet"] = expiry  # type: ignore[index]

    calls: list[str] = []

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        if self._is_path_unavailable(path):  # type: ignore[attr-defined]
            calls.append(f"skip:{path}")
            return []
        calls.append(path)
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    links = client.get_wan_links()

    assert links == []
    assert calls == [
        "api/s/default/stat/waninfo",
        "api/s/default/stat/wan",
        "skip:api/s/default/internet/wan",
        "skip:api/s/default/rest/internet",
    ]
    assert client._internet_api_supported is False  # type: ignore[attr-defined]


def test_get_wan_links_uses_internet_api_when_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = _make_client()

    calls: list[str] = []

    def fake_get_list(self: UniFiOSClient, path: str, *, timeout=None):
        calls.append(path)
        if path.endswith("internet/wan"):
            return [{"id": "wan"}]
        return []

    monkeypatch.setattr(UniFiOSClient, "_get_list", fake_get_list)

    links = client.get_wan_links()

    assert links == [{"id": "wan"}]
    assert calls == [
        "api/s/default/stat/waninfo",
        "api/s/default/stat/wan",
        "api/s/default/internet/wan",
    ]
    assert client._internet_api_supported is True  # type: ignore[attr-defined]
