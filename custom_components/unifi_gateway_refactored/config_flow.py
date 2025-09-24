
from __future__ import annotations
import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

from homeassistant import config_entries
from homeassistant.core import HomeAssistant

if TYPE_CHECKING:
    from homeassistant.data_entry_flow import FlowResult
else:  # pragma: no cover - fallback for older Home Assistant
    FlowResult = Dict[str, Any]  # type: ignore[misc, assignment]
import voluptuous as vol

from .const import (
    DOMAIN,
    CONF_USERNAME,
    CONF_PASSWORD,
    CONF_HOST,
    CONF_PORT,
    CONF_VERIFY_SSL,
    CONF_USE_PROXY_PREFIX,
    CONF_SITE_ID,
    CONF_TIMEOUT,
    CONF_SPEEDTEST_INTERVAL,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_TIMEOUT,
    DEFAULT_SPEEDTEST_INTERVAL,
)
from .unifi_client import UniFiOSClient, APIError, AuthError, ConnectivityError

_LOGGER = logging.getLogger(__name__)

async def _validate(hass: HomeAssistant, data: Dict[str, Any]) -> Dict[str, Any]:
    def _sync():
        client = UniFiOSClient(
            host=data[CONF_HOST],
            username=data.get(CONF_USERNAME),
            password=data.get(CONF_PASSWORD),
            port=data.get(CONF_PORT, DEFAULT_PORT),
            site_id=data.get(CONF_SITE_ID, DEFAULT_SITE),
            ssl_verify=data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
            use_proxy_prefix=data.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
            timeout=data.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        )
        ping = client.ping()
        sites = client.list_sites()
        return {"ping": ping, "sites": sites}
    return await hass.async_add_executor_job(_sync)

class ConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    def __init__(self) -> None:
        self._cached: Dict[str, Any] = {}

    @staticmethod
    def _clean_auth_fields(user_input: Dict[str, Any]) -> Dict[str, Any]:
        cleaned: Dict[str, Any] = {}
        for key, value in user_input.items():
            if key in (CONF_USERNAME, CONF_PASSWORD):
                if value is None:
                    continue
                if isinstance(value, str):
                    stripped = value.strip()
                    if not stripped:
                        continue
                    cleaned[key] = stripped
                    continue
            cleaned[key] = value
        return cleaned

    @staticmethod
    def _has_auth(data: Dict[str, Any]) -> bool:
        username = data.get(CONF_USERNAME)
        password = data.get(CONF_PASSWORD)
        return bool(username and password)

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            sanitized = self._clean_auth_fields(user_input)
            if self._has_auth(sanitized):
                self._cached.update(sanitized)
                return await self.async_step_advanced()
            errors["base"] = "missing_auth"

        basic_schema = vol.Schema({
            vol.Required(CONF_HOST): str,
            vol.Required(CONF_USERNAME): str,
            vol.Required(CONF_PASSWORD): str,
            vol.Optional(CONF_VERIFY_SSL, default=DEFAULT_VERIFY_SSL): bool,
        })
        return self.async_show_form(step_id="user", data_schema=basic_schema, errors=errors)

    async def async_step_advanced(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            sanitized = self._clean_auth_fields(user_input)
            self._cached.update(sanitized)
            data = dict(self._cached)
            try:
                await _validate(self.hass, data)
                await self.async_set_unique_id(f"{data[CONF_HOST]}:{data.get(CONF_PORT, DEFAULT_PORT)}")
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=f"UniFi {data[CONF_HOST]}", data=data)
            except AuthError:
                errors["base"] = "invalid_auth"
            except ConnectivityError:
                errors["base"] = "cannot_connect"
            except APIError:
                errors["base"] = "unknown"
            except Exception:
                errors["base"] = "unknown"

        adv_schema = vol.Schema(
            {
                vol.Optional(CONF_PORT, default=self._cached.get(CONF_PORT, DEFAULT_PORT)): int,
                vol.Optional(
                    CONF_SITE_ID,
                    default=self._cached.get(CONF_SITE_ID, DEFAULT_SITE),
                ): str,
                vol.Optional(
                    CONF_USE_PROXY_PREFIX,
                    default=self._cached.get(
                        CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
                    ),
                ): bool,
                vol.Optional(
                    CONF_TIMEOUT,
                    default=self._cached.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                ): int,
                vol.Optional(
                    CONF_SPEEDTEST_INTERVAL,
                    default=self._cached.get(
                        CONF_SPEEDTEST_INTERVAL, DEFAULT_SPEEDTEST_INTERVAL
                    ),
                ): int,
            }
        )
        return self.async_show_form(step_id="advanced", data_schema=adv_schema, errors=errors)

    async def async_step_import(self, user_input: Dict[str, Any]) -> FlowResult:
        sanitized = self._clean_auth_fields(user_input)
        self._cached.update(sanitized)
        return await self.async_step_advanced()

    @staticmethod
    def async_get_options_flow(config_entry: config_entries.ConfigEntry):
        return OptionsFlow(config_entry)

class OptionsFlow(config_entries.OptionsFlow):
    def __init__(self, entry: config_entries.ConfigEntry) -> None:
        self._entry = entry

    async def async_step_init(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            cleaned = ConfigFlow._clean_auth_fields(user_input)
            merged = {**self._entry.data, **self._entry.options, **cleaned}
            if not ConfigFlow._has_auth(merged):
                errors["base"] = "missing_auth"
            else:
                try:
                    await _validate(self.hass, merged)
                    return self.async_create_entry(title="", data=cleaned)
                except AuthError:
                    errors["base"] = "invalid_auth"
                except ConnectivityError:
                    errors["base"] = "cannot_connect"
                except APIError:
                    errors["base"] = "unknown"
                except Exception:
                    errors["base"] = "unknown"

        current = {**self._entry.data, **self._entry.options}
        schema = vol.Schema(
            {
                vol.Optional(CONF_HOST, default=current.get(CONF_HOST)): str,
                vol.Optional(CONF_PORT, default=current.get(CONF_PORT, DEFAULT_PORT)): int,
                vol.Optional(CONF_USERNAME, default=current.get(CONF_USERNAME)): str,
                vol.Optional(CONF_PASSWORD, default=current.get(CONF_PASSWORD)): str,
                vol.Optional(CONF_SITE_ID, default=current.get(CONF_SITE_ID, DEFAULT_SITE)): str,
                vol.Optional(
                    CONF_VERIFY_SSL,
                    default=current.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                ): bool,
                vol.Optional(
                    CONF_USE_PROXY_PREFIX,
                    default=current.get(
                        CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX
                    ),
                ): bool,
                vol.Optional(
                    CONF_TIMEOUT,
                    default=current.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
                ): int,
                vol.Optional(
                    CONF_SPEEDTEST_INTERVAL,
                    default=current.get(
                        CONF_SPEEDTEST_INTERVAL, DEFAULT_SPEEDTEST_INTERVAL
                    ),
                ): int,
            }
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
