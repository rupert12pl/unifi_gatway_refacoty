"""Tests for the UniFi Gateway config flow."""
from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from custom_components.unifi_gateway_refactory.config_flow import ConfigFlow
from custom_components.unifi_gateway_refactory.const import (
    CONF_SCAN_INTERVAL,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
)
from custom_components.unifi_gateway_refactory.coordinator import (
    UniFiGatewayAuthError,
    UniFiGatewayError,
)


@pytest.mark.parametrize("verify_ssl", [True, False])
async def test_user_flow_success(hass: HomeAssistant, verify_ssl: bool) -> None:
    flow = ConfigFlow()
    flow.hass = hass
    flow.context = {}

    with patch(
        "custom_components.unifi_gateway_refactory.config_flow.async_validate_input",
        return_value={"title": "Gateway"},
    ) as mock_validate:
        result: FlowResult = await flow.async_step_user()
        assert result["type"] == "form"

        user_input: dict[str, Any] = {
            "host": "https://gateway.local",
            "username": "user",
            "password": "pass",
            "site": "default",
            "verify_ssl": verify_ssl,
        }
        result2: FlowResult = await flow.async_step_user(user_input)

    assert result2["type"] == "create_entry"
    assert result2["title"] == "Gateway"
    assert result2["data"]["host"] == user_input["host"]
    assert result2["options"][CONF_VERIFY_SSL] == verify_ssl
    assert result2["options"][CONF_SCAN_INTERVAL] == DEFAULT_SCAN_INTERVAL
    mock_validate.assert_called_once()


async def test_user_flow_invalid_auth(hass: HomeAssistant) -> None:
    flow = ConfigFlow()
    flow.hass = hass
    flow.context = {}

    with patch(
        "custom_components.unifi_gateway_refactory.config_flow.async_validate_input",
        side_effect=UniFiGatewayAuthError,
    ):
        user_input: dict[str, Any] = {
            "host": "https://gateway.local",
            "username": "user",
            "password": "pass",
        }
        result: FlowResult = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "invalid_auth"


async def test_user_flow_cannot_connect(hass: HomeAssistant) -> None:
    flow = ConfigFlow()
    flow.hass = hass
    flow.context = {}

    with patch(
        "custom_components.unifi_gateway_refactory.config_flow.async_validate_input",
        side_effect=UniFiGatewayError,
    ):
        user_input: dict[str, Any] = {
            "host": "https://gateway.local",
            "username": "user",
            "password": "pass",
        }
        result: FlowResult = await flow.async_step_user(user_input)

    assert result["type"] == "form"
    assert result["errors"]["base"] == "cannot_connect"
