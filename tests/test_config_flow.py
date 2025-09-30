"""Tests for the config and options flow."""
from __future__ import annotations

import pytest
from custom_components.unifi_gateway_refactory import config_flow
from custom_components.unifi_gateway_refactory.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SITE,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
)
from homeassistant import config_entries


@pytest.fixture
def flow(hass):
    flow_obj = config_flow.UniFiGatewayConfigFlow()
    flow_obj.hass = hass
    return flow_obj


def test_show_user_form(flow: config_flow.UniFiGatewayConfigFlow, event_loop) -> None:
    result = event_loop.run_until_complete(flow.async_step_user())
    assert result["type"] == "form"
    assert result["step_id"] == "user"


def test_create_entry(
    monkeypatch: pytest.MonkeyPatch,
    flow: config_flow.UniFiGatewayConfigFlow,
    event_loop,
) -> None:
    async def _validate(hass, data):
        return {"title": data[CONF_HOST]}

    monkeypatch.setattr(config_flow, "_async_validate_input", _validate)

    user_input = {
        CONF_HOST: "gateway.local",
        CONF_USERNAME: "user",
        CONF_PASSWORD: "pass",
        CONF_SITE: DEFAULT_SITE,
        CONF_VERIFY_SSL: True,
    }

    result = event_loop.run_until_complete(flow.async_step_user(user_input))
    assert result["type"] == "create_entry"
    assert result["data"] == user_input


def test_invalid_auth(
    monkeypatch: pytest.MonkeyPatch,
    flow: config_flow.UniFiGatewayConfigFlow,
    event_loop,
) -> None:
    async def _raise(hass, data):
        raise config_flow.AuthFailedError

    monkeypatch.setattr(config_flow, "_async_validate_input", _raise)

    result = event_loop.run_until_complete(
        flow.async_step_user(
            {
                CONF_HOST: "gateway.local",
                CONF_USERNAME: "user",
                CONF_PASSWORD: "wrong",
                CONF_SITE: DEFAULT_SITE,
                CONF_VERIFY_SSL: True,
            }
        )
    )
    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth"


def test_unexpected_error(
    monkeypatch: pytest.MonkeyPatch,
    flow: config_flow.UniFiGatewayConfigFlow,
    event_loop,
) -> None:
    class _Client:
        def __init__(self, hass, data):
            self.hass = hass
            self.data = data

        async def fetch_metrics(self):
            raise ValueError("boom")

    monkeypatch.setattr(config_flow, "UniFiGatewayApiClient", _Client)

    result = event_loop.run_until_complete(
        flow.async_step_user(
            {
                CONF_HOST: "gateway.local",
                CONF_USERNAME: "user",
                CONF_PASSWORD: "pass",
                CONF_SITE: DEFAULT_SITE,
                CONF_VERIFY_SSL: True,
            }
        )
    )

    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"


def test_options_flow(monkeypatch: pytest.MonkeyPatch, event_loop) -> None:
    entry = config_entries.ConfigEntry(
        entry_id="entry",
        data={
            CONF_HOST: "gateway.local",
            CONF_USERNAME: "user",
            CONF_PASSWORD: "pass",
            CONF_SITE: DEFAULT_SITE,
        },
        options={},
    )
    options_flow = config_flow.UniFiGatewayOptionsFlow(entry)

    result = event_loop.run_until_complete(options_flow.async_step_init())
    assert result["type"] == "form"

    result = event_loop.run_until_complete(
        options_flow.async_step_init({CONF_SCAN_INTERVAL: 10, CONF_VERIFY_SSL: False})
    )
    assert result["type"] == "create_entry"
    assert result["data"][CONF_SCAN_INTERVAL] == DEFAULT_SCAN_INTERVAL
    assert result["data"][CONF_VERIFY_SSL] is False
