"""Tests for the config options flow."""
from __future__ import annotations

import asyncio
from typing import Any, Dict, cast

import pytest
import voluptuous as vol

from custom_components.unifi_gateway_refactored import config_flow
from custom_components.unifi_gateway_refactored.const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_SPEEDTEST_ENTITIES,
    CONF_SPEEDTEST_INTERVAL,
    CONF_TIMEOUT,
    CONF_USE_PROXY_PREFIX,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_SITE,
)
from homeassistant.config_entries import ConfigEntry


def test_options_flow_form_hides_disallowed_fields(hass: object) -> None:
    """Ensure the options flow omits host, site, and WiFi fields."""

    entry = ConfigEntry(
        data={
            CONF_HOST: "192.0.2.1",
            CONF_PORT: DEFAULT_PORT,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
            config_flow.CONF_SITE_ID: DEFAULT_SITE,
            CONF_VERIFY_SSL: True,
            CONF_USE_PROXY_PREFIX: False,
            CONF_TIMEOUT: 30,
            CONF_SPEEDTEST_INTERVAL: 600,
            CONF_SPEEDTEST_ENTITIES: "sensor.download,sensor.upload",
        }
    )

    flow = config_flow.OptionsFlow(entry)
    flow.hass = hass  # ensure validation helpers can access hass if needed

    captured: Dict[str, Any] = {}

    def _capture_form(**kwargs):
        captured.update(kwargs)
        return {"type": "form"}

    flow.async_show_form = _capture_form  # type: ignore[assignment]

    asyncio.run(flow.async_step_init())

    assert "data_schema" in captured
    schema = cast(vol.Schema, captured["data_schema"])
    field_names: set[str] = set()
    for key in schema.schema:
        if hasattr(key, "key"):
            marker = key.key  # type: ignore[attr-defined]
            if isinstance(marker, (tuple, list)) and marker:
                field_names.add(str(marker[0]))
            else:
                field_names.add(str(marker))
        else:
            field_names.add(str(key))

    assert CONF_HOST not in field_names
    assert config_flow.CONF_SITE_ID not in field_names
    assert config_flow.CONF_WIFI_GUEST not in field_names
    assert config_flow.CONF_WIFI_IOT not in field_names

    assert {
        CONF_PORT,
        CONF_USERNAME,
        CONF_PASSWORD,
        CONF_VERIFY_SSL,
        CONF_USE_PROXY_PREFIX,
        CONF_TIMEOUT,
        CONF_SPEEDTEST_INTERVAL,
        CONF_SPEEDTEST_ENTITIES,
    }.issubset(field_names)


def test_options_flow_updates_without_host(
    monkeypatch: pytest.MonkeyPatch, hass: object
) -> None:
    """The options flow should accept updates without providing host details."""

    entry = ConfigEntry(
        data={
            CONF_HOST: "198.51.100.10",
            CONF_PORT: DEFAULT_PORT,
            CONF_USERNAME: "admin",
            CONF_PASSWORD: "secret",
            config_flow.CONF_SITE_ID: DEFAULT_SITE,
            CONF_VERIFY_SSL: True,
            CONF_USE_PROXY_PREFIX: True,
            CONF_TIMEOUT: 20,
            CONF_SPEEDTEST_INTERVAL: 600,
            CONF_SPEEDTEST_ENTITIES: "sensor.download,sensor.upload",
        }
    )

    flow = config_flow.OptionsFlow(entry)
    flow.hass = hass

    observed: Dict[str, Any] = {}

    async def _stub_validate(hass_obj, data):  # type: ignore[no-untyped-def]
        observed["data"] = data
        return {"ping": True, "sites": []}

    monkeypatch.setattr(config_flow, "_validate", _stub_validate)

    result = asyncio.run(
        flow.async_step_init(
            {
                CONF_PORT: 8443,
                CONF_USERNAME: "new_admin",
                CONF_PASSWORD: "new_secret",
                CONF_VERIFY_SSL: False,
                CONF_USE_PROXY_PREFIX: False,
                CONF_TIMEOUT: 45,
                CONF_SPEEDTEST_INTERVAL: 15,
                CONF_SPEEDTEST_ENTITIES: "sensor.latency",
            }
        )
    )

    result_data = cast(Dict[str, Any], result["data"])
    assert result_data[CONF_PORT] == 8443
    assert result_data[CONF_SPEEDTEST_INTERVAL] == 900
    assert result_data[CONF_SPEEDTEST_ENTITIES] == "sensor.latency"
    assert CONF_HOST not in result_data
    assert config_flow.CONF_SITE_ID not in result_data

    merged = cast(Dict[str, Any], observed["data"])
    assert merged[CONF_HOST] == entry.data[CONF_HOST]
    assert merged[config_flow.CONF_SITE_ID] == entry.data[config_flow.CONF_SITE_ID]
