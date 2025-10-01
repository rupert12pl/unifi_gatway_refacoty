from __future__ import annotations

import asyncio
from datetime import datetime
from unittest.mock import MagicMock

from custom_components.unifi_gateway_refactored import diagnostics
from custom_components.unifi_gateway_refactored.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DATA_CLIENT,
    DATA_COORDINATOR,
    DATA_ERRORS,
    DOMAIN,
)
from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData


class DummyClient:
    def get_controller_url(self) -> str:
        return "https://host"

    def get_controller_api_url(self) -> str:
        return "https://host/api"

    def get_site(self) -> str:
        return "default"


class DummyCoordinator:
    def __init__(self, data: UniFiGatewayData) -> None:
        self.data = data


def test_diagnostics_redact_and_truncate(hass) -> None:
    long_payload = [{"value": "x" * 2048}]
    data = UniFiGatewayData(
        trace_id="trace",
        status="ok",
        controller={"site": "default"},
        health=long_payload,
        alerts=long_payload,
        devices=[],
        errors=[],
        last_updated=datetime.utcnow(),
        available=True,
    )
    entry = MagicMock()
    entry.entry_id = "entry"
    entry.data = {
        CONF_HOST: "udm",
        CONF_PORT: 443,
        CONF_SITE_ID: "default",
        CONF_TIMEOUT: 10,
        CONF_VERIFY_SSL: False,
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "secret",
    }
    hass.data.setdefault(DOMAIN, {})[entry.entry_id] = {
        DATA_CLIENT: DummyClient(),
        DATA_COORDINATOR: DummyCoordinator(data),
        DATA_ERRORS: [
            {"endpoint": "health", "code": "UGDA_TIMEOUT", "message": "timeout"}
        ],
    }

    async def _run() -> None:
        diag = await diagnostics.async_get_config_entry_diagnostics(hass, entry)
        assert diag["config"][CONF_PASSWORD] == "***"
        assert diag["config"][CONF_USERNAME] == "***"
        assert diag["errors"]
        assert diag["data"]["alerts"]["truncated"] is True

    asyncio.run(_run())
