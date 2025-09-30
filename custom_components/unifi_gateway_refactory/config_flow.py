"""Config flow for the UniFi Gateway Refactory integration."""
from __future__ import annotations

import inspect
import logging
from collections.abc import Awaitable
from typing import Any, cast

import voluptuous as vol
from homeassistant import config_entries
from homeassistant.core import HomeAssistant

try:
    from homeassistant.data_entry_flow import FlowResult
except ImportError:  # pragma: no cover - fallback for tests without Home Assistant
    FlowResult = dict[str, Any]  # type: ignore[assignment]

from .const import (
    CONF_HOST,
    CONF_PASSWORD,
    CONF_SCAN_INTERVAL,
    CONF_SITE,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_SCAN_INTERVAL,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    DOMAIN,
    MAX_SCAN_INTERVAL,
    MIN_SCAN_INTERVAL,
)
from .coordinator import AuthFailedError, GatewayApiError, UniFiGatewayApiClient

_LOGGER = logging.getLogger(__name__)


async def _resolve_flow_result(
    result: FlowResult | Awaitable[FlowResult],
) -> FlowResult:
    """Return a flow result regardless of sync/async implementation."""

    if inspect.isawaitable(result):
        return cast(FlowResult, await cast(Awaitable[FlowResult], result))
    return cast(FlowResult, result)


async def _async_validate_input(hass: HomeAssistant, data: dict[str, Any]) -> dict[str, Any]:
    """Validate the provided configuration data."""

    client = UniFiGatewayApiClient(hass, data)
    try:
        await client.fetch_metrics()
    except GatewayApiError:
        raise
    except Exception as err:  # pragma: no cover - defensive
        raise GatewayApiError("Unexpected error during validation") from err
    return {"title": data[CONF_HOST]}


class UniFiGatewayConfigFlow(  # type: ignore[misc, call-arg]
    config_entries.ConfigFlow, domain=DOMAIN
):
    """Handle a config flow for UniFi Gateway."""

    VERSION = 1

    async def async_step_user(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                info = await _async_validate_input(self.hass, user_input)
            except AuthFailedError:
                errors["base"] = "invalid_auth"
            except GatewayApiError:
                errors["base"] = "cannot_connect"
            except Exception:  # pragma: no cover - defensive logging
                _LOGGER.exception("Unexpected error during UniFi Gateway config flow")
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(user_input[CONF_HOST])
                self._abort_if_unique_id_configured()
                return await self.async_create_entry(title=info["title"], data=user_input)

        data_schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
                vol.Optional(CONF_SITE, default=DEFAULT_SITE): str,
                vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
            }
        )
        return await _resolve_flow_result(
            self.async_show_form(step_id="user", data_schema=data_schema, errors=errors)
        )

    async def async_step_reauth(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        if user_input is None:
            user_input = {}
        combined = {**self.context.get("entry_data", {}), **user_input}
        errors: dict[str, str] = {}
        if CONF_PASSWORD in user_input:
            try:
                await _async_validate_input(self.hass, combined)
            except AuthFailedError:
                errors["base"] = "invalid_auth"
            except GatewayApiError:
                errors["base"] = "cannot_connect"
            else:
                existing = self.hass.config_entries.async_get_entry(self.context["entry_id"])
                if existing:
                    updated = {**existing.data, CONF_PASSWORD: user_input[CONF_PASSWORD]}
                    self.hass.config_entries.async_update_entry(existing, data=updated)
                return self.async_abort(reason="reauth_successful")

        return await _resolve_flow_result(
            self.async_show_form(
                step_id="reauth",
                data_schema=vol.Schema({vol.Required(CONF_PASSWORD): str}),
                errors=errors,
            )
        )

    @staticmethod
    def async_get_options_flow(
        config_entry: config_entries.ConfigEntry,
    ) -> config_entries.OptionsFlow:
        return UniFiGatewayOptionsFlow(config_entry)


class UniFiGatewayOptionsFlow(config_entries.OptionsFlow):
    """Options flow for UniFi Gateway."""

    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self.config_entry = entry

    async def async_step_init(self, user_input: dict[str, Any] | None = None) -> FlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            interval = int(user_input.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL))
            interval = max(MIN_SCAN_INTERVAL, min(MAX_SCAN_INTERVAL, interval))
            user_input[CONF_SCAN_INTERVAL] = interval
            return await self.async_create_entry(title="Options", data=user_input)

        options_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_SCAN_INTERVAL,
                    default=self.config_entry.options.get(
                        CONF_SCAN_INTERVAL,
                        self.config_entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL),
                    ),
                ): vol.All(int, vol.Clamp(min=MIN_SCAN_INTERVAL, max=MAX_SCAN_INTERVAL)),
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=self.config_entry.options.get(
                        CONF_VERIFY_SSL,
                        self.config_entry.data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                    ),
                ): bool,
            }
        )
        return await _resolve_flow_result(
            self.async_show_form(
                step_id="init",
                data_schema=options_schema,
                errors=errors,
            )
        )
