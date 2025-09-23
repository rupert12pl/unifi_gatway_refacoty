import asyncio


from tests.helpers import REDACTED, load_stubs

load_stubs()

# ruff: noqa: E402

from homeassistant.config_entries import ConfigEntry

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
from custom_components.unifi_gateway_refactored import diagnostics
from custom_components.unifi_gateway_refactored.diagnostics import (
    TO_REDACT,
    async_get_config_entry_diagnostics,
)
from custom_components.unifi_gateway_refactored.unifi_client import UniFiOSClient


class DummyClient(UniFiOSClient):
    """Minimal UniFi client stub that avoids network access for diagnostics tests."""

    def __init__(self) -> None:
        # ``UniFiOSClient`` performs network lookups in ``__init__`` so we bypass the
        # parent constructor and only provide the attributes exercised by diagnostics.
        self._health = [
            {
                "subsystem": "wan",
                "status": "ok",
                "mac": "aa:bb:cc:dd:ee:ff",
                "ip": "203.0.113.5",
                "wan_ip": "198.51.100.2",
            }
        ]
        self._sites = [
            {
                "name": "Default",
                "id": "site-id",
                "wan_ip": "198.51.100.2",
            }
        ]

    def get_healthinfo(self):
        return [dict(item) for item in self._health]

    def list_sites(self):
        return [dict(item) for item in self._sites]

    def get_controller_url(self) -> str:
        return "https://controller.example/login?redirect=%2Fdashboard"

    def get_controller_api_url(self) -> str:
        return "https://controller.example"

    def get_site(self) -> str:
        return "default"


class DummyHass:
    def __init__(self) -> None:
        self.data: dict[str, dict[str, dict[str, DummyClient]]] = {}

    async def async_add_executor_job(self, func, *args):
        return func(*args)


def test_diagnostics_redacts_sensitive_fields_with_cached_client() -> None:
    hass = DummyHass()
    client = DummyClient()
    entry = ConfigEntry()
    entry.entry_id = "entry"
    entry.data = {
        CONF_HOST: "controller.example",
        CONF_USERNAME: "user",
        CONF_PASSWORD: "pass",
        CONF_PORT: DEFAULT_PORT,
        CONF_SITE_ID: DEFAULT_SITE,
        CONF_VERIFY_SSL: DEFAULT_VERIFY_SSL,
        CONF_USE_PROXY_PREFIX: DEFAULT_USE_PROXY_PREFIX,
        CONF_TIMEOUT: DEFAULT_TIMEOUT,
    }
    entry.options = {}
    hass.data = {DOMAIN: {entry.entry_id: {"client": client}}}

    result = asyncio.run(async_get_config_entry_diagnostics(hass, entry))

    assert result["controller_ui"] == REDACTED
    assert result["controller_api"] == REDACTED
    assert result["site"] == REDACTED
    assert result["health"][0]["mac"] == REDACTED
    assert result["health"][0]["status"] == "ok"
    assert result["sites"][0]["wan_ip"] == REDACTED
    assert result["sites"][0]["name"] == "Default"
    # ensure the original cached data is not mutated by redaction
    assert client._health[0]["mac"] == "aa:bb:cc:dd:ee:ff"


def test_diagnostics_redacts_with_new_client(monkeypatch) -> None:
    hass = DummyHass()
    entry = ConfigEntry()
    entry.entry_id = "entry"
    entry.data = {
        CONF_HOST: "controller.example",
        CONF_USERNAME: "user",
        CONF_PASSWORD: "pass",
        CONF_PORT: DEFAULT_PORT,
        CONF_SITE_ID: DEFAULT_SITE,
        CONF_VERIFY_SSL: DEFAULT_VERIFY_SSL,
        CONF_USE_PROXY_PREFIX: DEFAULT_USE_PROXY_PREFIX,
        CONF_TIMEOUT: DEFAULT_TIMEOUT,
    }
    entry.options = {}
    hass.data = {DOMAIN: {}}

    created_clients: list[DummyClient] = []

    class FactoryClient(DummyClient):
        def __init__(self, **_kwargs):
            super().__init__()
            created_clients.append(self)

    def fake_client_factory(**kwargs):
        assert kwargs["host"] == entry.data[CONF_HOST]
        return FactoryClient()

    monkeypatch.setattr(diagnostics, "UniFiOSClient", fake_client_factory)

    result = asyncio.run(async_get_config_entry_diagnostics(hass, entry))

    assert created_clients, "Expected a UniFi client to be created"
    assert result["controller_ui"] == REDACTED
    assert result["health"][0]["mac"] == REDACTED
    assert created_clients[0]._health[0]["mac"] == "aa:bb:cc:dd:ee:ff"
    # ensure TO_REDACT includes sensitive tokens for future coverage
    for key in ("mac", "wan_ip", "password"):
        assert key in TO_REDACT
