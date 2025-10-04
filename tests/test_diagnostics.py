from __future__ import annotations

import asyncio

from custom_components.unifi_gateway_refactored import diagnostics
from custom_components.unifi_gateway_refactored.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_TIMEOUT,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
)
from custom_components.unifi_gateway_refactored.unifi_client import APIError, UniFiOSClient
from homeassistant.config_entries import ConfigEntry


class DummyClient(UniFiOSClient):
    """UniFi client stub returning predetermined health payloads."""

    def __init__(self, health: list[dict[str, str]] | Exception) -> None:
        self._health = health

    def get_healthinfo(self):  # type: ignore[override]
        if isinstance(self._health, Exception):
            raise self._health
        return self._health

    def get_controller_url(self):  # type: ignore[override]
        return "https://controller.example/ui"

    def get_controller_api_url(self):  # type: ignore[override]
        return "https://controller.example/api"

    def get_site(self):  # type: ignore[override]
        return "default"

    def close(self) -> None:  # type: ignore[override]
        return None


def test_diagnostics_handles_expected_errors_from_runtime_client(hass) -> None:
    entry = ConfigEntry(
        entry_id="entry-1",
        data={
            CONF_HOST: "controller.example",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "secret",
            CONF_PORT: DEFAULT_PORT,
            CONF_SITE_ID: DEFAULT_SITE,
            CONF_TIMEOUT: DEFAULT_TIMEOUT,
            CONF_USE_PROXY_PREFIX: DEFAULT_USE_PROXY_PREFIX,
            CONF_VERIFY_SSL: DEFAULT_VERIFY_SSL,
        },
        options={},
    )
    error = APIError("Not found", status_code=404)
    client = DummyClient(error)
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {"client": client}

    result = asyncio.run(diagnostics.async_get_config_entry_diagnostics(hass, entry))

    assert result["source"] == "runtime"
    controller = result["controller"]
    assert controller["health"] == []
    assert controller["errors"]["health"]["status"] == 404
    assert controller["errors"]["health"]["reason"] == "not_found"
    assert result["config"]["data"][CONF_PASSWORD] == "REDACTED"
    assert result["config"]["data"][CONF_USERNAME] == "REDACTED"


def test_diagnostics_collects_direct_client_with_expected_failures(monkeypatch, hass) -> None:
    entry = ConfigEntry(
        entry_id="entry-2",
        data={
            CONF_HOST: "controller.example",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "secret",
            CONF_PORT: DEFAULT_PORT,
            CONF_SITE_ID: DEFAULT_SITE,
            CONF_TIMEOUT: DEFAULT_TIMEOUT,
            CONF_USE_PROXY_PREFIX: DEFAULT_USE_PROXY_PREFIX,
            CONF_VERIFY_SSL: DEFAULT_VERIFY_SSL,
        },
        options={},
    )

    class FactoryClient(UniFiOSClient):
        instance: "FactoryClient | None" = None

        def __init__(self, *args, **kwargs):  # type: ignore[override]
            FactoryClient.instance = self
            self.closed = False

        def get_healthinfo(self):  # type: ignore[override]
            raise APIError("Bad request", status_code=400)

        def get_controller_url(self):  # type: ignore[override]
            return "https://controller.example/ui"

        def get_controller_api_url(self):  # type: ignore[override]
            return "https://controller.example/api"

        def get_site(self):  # type: ignore[override]
            return "default"

        def close(self) -> None:  # type: ignore[override]
            self.closed = True

    monkeypatch.setattr(diagnostics, "UniFiOSClient", FactoryClient)

    result = asyncio.run(diagnostics.async_get_config_entry_diagnostics(hass, entry))

    assert result["source"] == "direct"
    controller = result["controller"]
    assert controller["health"] == []
    assert controller["errors"]["health"]["reason"] == "bad_request"
    assert FactoryClient.instance is not None and FactoryClient.instance.closed
