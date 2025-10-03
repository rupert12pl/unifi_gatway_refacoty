"""Tests covering the UniFi Gateway options flow."""

from __future__ import annotations

import pytest

from custom_components.unifi_gateway_refactored.config_flow import OptionsFlow
from custom_components.unifi_gateway_refactored.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SITE_ID,
    CONF_SPEEDTEST_ENTITIES,
    CONF_SPEEDTEST_INTERVAL,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    CONF_WIFI_GUEST,
    CONF_WIFI_IOT,
    DEFAULT_SITE,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant


@pytest.mark.asyncio
async def test_options_flow_updates_entry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure options flow updates the config entry and returns sanitized options."""
    hass = HomeAssistant()
    entry = ConfigEntry(
        title="UniFi old-host",
        data={
            CONF_HOST: "old-host",
            CONF_PORT: 443,
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_SITE_ID: DEFAULT_SITE,
            CONF_VERIFY_SSL: False,
            CONF_USE_PROXY_PREFIX: True,
            CONF_TIMEOUT: 10,
            CONF_SPEEDTEST_INTERVAL: 3600,
            CONF_SPEEDTEST_ENTITIES: "sensor.speedtest_download",
            CONF_WIFI_GUEST: "GuestNet",
        },
        options={
            CONF_SPEEDTEST_INTERVAL: 3600,
            CONF_WIFI_GUEST: "GuestNet",
        },
    )

    flow = OptionsFlow(entry)
    flow.hass = hass

    captured_payload: list[dict[str, object]] = []

    async def _fake_validate(_hass: HomeAssistant, payload: dict[str, object]) -> dict[str, object]:
        captured_payload.append(payload)
        return {"ping": True, "sites": []}

    monkeypatch.setattr(
        "custom_components.unifi_gateway_refactored.config_flow._validate",
        _fake_validate,
    )

    user_input = {
        CONF_HOST: "new-host",
        CONF_PORT: 8443,
        CONF_USERNAME: "admin",
        CONF_PASSWORD: "new-pass",
        CONF_SITE_ID: "main",
        CONF_VERIFY_SSL: True,
        CONF_USE_PROXY_PREFIX: False,
        CONF_TIMEOUT: 25,
        CONF_SPEEDTEST_INTERVAL: 15,
        CONF_SPEEDTEST_ENTITIES: "sensor.alpha\n sensor.beta ",
        CONF_WIFI_GUEST: " ",
        CONF_WIFI_IOT: "IoT SSID",
    }

    result = await flow.async_step_init(user_input)

    assert result["data"][CONF_SPEEDTEST_INTERVAL] == 15 * 60
    assert result["data"][CONF_SPEEDTEST_ENTITIES] == "sensor.alpha,sensor.beta"
    assert CONF_WIFI_GUEST not in result["data"]
    assert result["data"][CONF_WIFI_IOT] == "IoT SSID"

    assert entry.data[CONF_HOST] == "new-host"
    assert entry.data[CONF_PORT] == 8443
    assert entry.data[CONF_USERNAME] == "admin"
    assert entry.data[CONF_PASSWORD] == "new-pass"
    assert entry.data[CONF_SITE_ID] == "main"
    assert entry.data[CONF_VERIFY_SSL] is True
    assert entry.data[CONF_USE_PROXY_PREFIX] is False
    assert entry.data[CONF_TIMEOUT] == 25
    assert entry.data[CONF_SPEEDTEST_INTERVAL] == 15 * 60
    assert entry.data[CONF_SPEEDTEST_ENTITIES] == "sensor.alpha,sensor.beta"
    assert CONF_WIFI_GUEST not in entry.data
    assert entry.data[CONF_WIFI_IOT] == "IoT SSID"
    assert entry.title == "UniFi new-host"

    assert entry.options == result["data"]

    assert captured_payload
    payload = captured_payload[0]
    assert payload[CONF_HOST] == "new-host"
    assert payload[CONF_SPEEDTEST_INTERVAL] == 15 * 60
    assert payload[CONF_WIFI_IOT] == "IoT SSID"
