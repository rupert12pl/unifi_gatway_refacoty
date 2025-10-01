"""Config flow for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

from typing import Any, Dict, Optional

import voluptuous as vol
from aiohttp import ClientSession, ClientTimeout
from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResult

from .const import (
    CLIENT_CONNECT_TIMEOUT,
    CLIENT_SOCK_READ_TIMEOUT,
    CLIENT_TOTAL_TIMEOUT,
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
from .unifi_client import UniFiApiClient, UniFiAuthError, UniFiClientError


async def _validate_input(hass: HomeAssistant, data: Dict[str, Any]) -> Dict[str, Any]:
    timeout = ClientTimeout(
        total=CLIENT_TOTAL_TIMEOUT,
        connect=CLIENT_CONNECT_TIMEOUT,
        sock_read=CLIENT_SOCK_READ_TIMEOUT,
    )
    async with ClientSession(timeout=timeout) as session:
        client = UniFiApiClient(
            session=session,
            host=data[CONF_HOST],
            username=data[CONF_USERNAME],
            password=data[CONF_PASSWORD],
            port=data.get(CONF_PORT, DEFAULT_PORT),
            site_id=data.get(CONF_SITE_ID, DEFAULT_SITE),
            verify_ssl=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            use_proxy_prefix=data.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
            request_timeout=data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        )
        await client.async_login(trace_id="config_flow")
        await client.async_probe()
        health = await client.async_request_health(trace_id="config_flow")
        sites = await client.async_request_sites(trace_id="config_flow")
    return {"health": health, "sites": sites}


class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow for the integration."""

    VERSION = 1

    def __init__(self) -> None:
        self._cached: Dict[str, Any] = {}

    async def async_step_user(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            self._cached.update(user_input)
            return await self.async_step_advanced()

        schema = vol.Schema(
            {
                vol.Required(CONF_HOST): str,
                vol.Required(CONF_USERNAME): str,
                vol.Required(CONF_PASSWORD): str,
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_advanced(
        self, user_input: Optional[Dict[str, Any]] = None
    ) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            self._cached.update(user_input)
            data = dict(self._cached)
            try:
                await _validate_input(self.hass, data)
            except UniFiAuthError:
                errors["base"] = "invalid_auth"
            except UniFiClientError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(
                    f"{data[CONF_HOST]}-{data.get(CONF_SITE_ID, DEFAULT_SITE)}"
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=data[CONF_HOST], data=data)

        schema = vol.Schema(
            {
                vol.Required(
                    CONF_PORT, default=self._cached.get(CONF_PORT, DEFAULT_PORT)
                ): int,
                vol.Optional(
                    CONF_SITE_ID, default=self._cached.get(CONF_SITE_ID, DEFAULT_SITE)
                ): str,
                vol.Optional(
                    CONF_TIMEOUT,
                    default=self._cached.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                ): int,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=self._cached.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                ): bool,
                vol.Optional(
                    CONF_USE_PROXY_PREFIX,
                    default=self._cached.get(
                        CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
                    ),
                ): bool,
            }
        )
        return self.async_show_form(
            step_id="advanced", data_schema=schema, errors=errors
        )
