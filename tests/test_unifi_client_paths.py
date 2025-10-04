from __future__ import annotations

from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


def _make_client(site_name: str = "default", site_id: str | None = "site-guid") -> UniFiOSClient:
    client = object.__new__(UniFiOSClient)
    client._site_name = site_name  # type: ignore[attr-defined]
    client._site_id = site_id  # type: ignore[attr-defined]
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
