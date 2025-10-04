
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp

from homeassistant import config_entries
from homeassistant.data_entry_flow import AbortFlow
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
    CONF_SPEEDTEST_ENTITIES,
    CONF_WIFI_GUEST,
    CONF_WIFI_IOT,
    CONF_UI_API_KEY,
    DEFAULT_PORT,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    DEFAULT_USE_PROXY_PREFIX,
    DEFAULT_TIMEOUT,
    DEFAULT_SPEEDTEST_INTERVAL,
    DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
    DEFAULT_SPEEDTEST_ENTITIES,
    LEGACY_CONF_SPEEDTEST_INTERVAL_MIN,
)
from .cloud_client import (
    UiCloudAuthError,
    UiCloudClient,
    UiCloudError,
    UiCloudRateLimitError,
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
        try:
            health = client.get_healthinfo()
        finally:
            client.close()
        return {"health": health}
    return await hass.async_add_executor_job(_sync)


async def _validate_ui_api_key(api_key: Optional[str]) -> None:
    if not api_key:
        return
    timeout = aiohttp.ClientTimeout(total=10)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        client = UiCloudClient(session, api_key)
        await client.async_get_hosts()


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

    @staticmethod
    def _minutes_to_seconds(value: Any) -> int:
        try:
            minutes = int(value)
        except (TypeError, ValueError):
            return 0
        minutes = max(0, minutes)
        if minutes == 0:
            return 0
        return minutes * 60

    @staticmethod
    def _seconds_to_minutes(value: Any) -> int:
        try:
            seconds = int(value)
        except (TypeError, ValueError):
            return 0
        if seconds <= 0:
            return 0
        return (seconds + 59) // 60

    @staticmethod
    def _resolve_interval_seconds(data: Dict[str, Any]) -> int:
        candidate = data.get(CONF_SPEEDTEST_INTERVAL)
        if isinstance(candidate, (int, float, str)):
            try:
                seconds = int(candidate)
            except (TypeError, ValueError):
                seconds = None
        else:
            seconds = None
        if seconds is not None and seconds >= 0:
            return seconds

        legacy_candidate = data.get(LEGACY_CONF_SPEEDTEST_INTERVAL_MIN)
        if isinstance(legacy_candidate, (int, float, str)):
            try:
                minutes = int(legacy_candidate)
            except (TypeError, ValueError):
                minutes = None
        else:
            minutes = None
        if minutes is not None and minutes >= 0:
            return minutes * 60

        return DEFAULT_SPEEDTEST_INTERVAL

    @staticmethod
    def _normalize_optional_text(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if isinstance(value, bool):
            return None
        if isinstance(value, (int, float)):
            cleaned = str(value).strip()
            return cleaned or None
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned or None
        cleaned = str(value).strip()
        return cleaned or None

    @staticmethod
    def _normalize_api_key(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned or None
        cleaned = str(value).strip()
        return cleaned or None

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
            if CONF_SPEEDTEST_INTERVAL in sanitized:
                sanitized[CONF_SPEEDTEST_INTERVAL] = self._minutes_to_seconds(
                    sanitized[CONF_SPEEDTEST_INTERVAL]
                )
            if CONF_SPEEDTEST_ENTITIES in sanitized:
                value = sanitized[CONF_SPEEDTEST_ENTITIES]
                if isinstance(value, str):
                    collapsed = ",".join(
                        segment.strip()
                        for segment in value.replace("\n", ",").split(",")
                        if segment.strip()
                    )
                    sanitized[CONF_SPEEDTEST_ENTITIES] = (
                        collapsed or DEFAULT_SPEEDTEST_ENTITIES
                    )
                elif isinstance(value, (list, tuple, set)):
                    collapsed = ",".join(str(item).strip() for item in value if str(item).strip())
                    sanitized[CONF_SPEEDTEST_ENTITIES] = (
                        collapsed or DEFAULT_SPEEDTEST_ENTITIES
                    )
            self._cached.update(sanitized)
            data = dict(self._cached)
            for key in (CONF_WIFI_GUEST, CONF_WIFI_IOT):
                if key in data:
                    normalized = self._normalize_optional_text(data[key])
                    if normalized is None:
                        data.pop(key, None)
                        self._cached.pop(key, None)
                    else:
                        data[key] = normalized
                        self._cached[key] = normalized
            if CONF_UI_API_KEY in data:
                normalized_key = self._normalize_api_key(data[CONF_UI_API_KEY])
                if normalized_key is None:
                    data.pop(CONF_UI_API_KEY, None)
                    self._cached.pop(CONF_UI_API_KEY, None)
                else:
                    data[CONF_UI_API_KEY] = normalized_key
                    self._cached[CONF_UI_API_KEY] = normalized_key
            try:
                # Ensure Home Assistant context is available before validation.
                assert self.hass is not None  # nosec B101
                await _validate(self.hass, data)
                await _validate_ui_api_key(data.get(CONF_UI_API_KEY))
                await self.async_set_unique_id(
                    f"{data[CONF_HOST]}:{data.get(CONF_PORT, DEFAULT_PORT)}"
                )
                self._abort_if_unique_id_configured()
                return self.async_create_entry(title=f"UniFi {data[CONF_HOST]}", data=data)
            except AuthError:
                errors["base"] = "invalid_auth"
            except ConnectivityError:
                errors["base"] = "cannot_connect"
            except UiCloudAuthError:
                errors["base"] = "invalid_api_key"
            except UiCloudRateLimitError:
                errors["base"] = "api_rate_limited"
            except UiCloudError:
                errors["base"] = "api_unavailable"
            except APIError as err:
                _LOGGER.error(
                    "UniFi API error while validating controller %s:%s: %s",
                    data.get(CONF_HOST),
                    data.get(CONF_PORT, DEFAULT_PORT),
                    err,
                )
                errors["base"] = "cannot_connect" if not err.expected else "unknown"
            except AbortFlow:
                raise
            except Exception as err:  # pragma: no cover - defensive guard
                _LOGGER.exception(
                    "Unexpected error while validating UniFi controller %s:%s: %s",
                    data.get(CONF_HOST),
                    data.get(CONF_PORT, DEFAULT_PORT),
                    err,
                )
                errors["base"] = "unknown"

        interval_default = self._seconds_to_minutes(
            self._resolve_interval_seconds(self._cached)
        )
        if interval_default <= 0:
            interval_default = DEFAULT_SPEEDTEST_INTERVAL_MINUTES

        entities_default = self._cached.get(
            CONF_SPEEDTEST_ENTITIES, DEFAULT_SPEEDTEST_ENTITIES
        )
        if isinstance(entities_default, (list, tuple, set)):
            entities_default = ",".join(
                str(item).strip() for item in entities_default if str(item).strip()
            )
        if not entities_default:
            entities_default = DEFAULT_SPEEDTEST_ENTITIES

        adv_schema = vol.Schema(
            {
                vol.Optional(
                    CONF_PORT,
                    default=self._cached.get(CONF_PORT, DEFAULT_PORT),
                ): vol.All(vol.Coerce(int), vol.Clamp(min=1, max=65535)),
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
                ): vol.All(vol.Coerce(int), vol.Clamp(min=1)),
                vol.Optional(
                    CONF_SPEEDTEST_INTERVAL,
                    default=self._seconds_to_minutes(
                        self._resolve_interval_seconds(self._cached)
                    )
                    or DEFAULT_SPEEDTEST_INTERVAL_MINUTES,
                ): vol.All(vol.Coerce(int), vol.Clamp(min=5)),
                vol.Optional(
                    CONF_SPEEDTEST_ENTITIES,
                    default=entities_default,
                ): str,
                vol.Optional(
                    CONF_UI_API_KEY,
                    default=self._cached.get(CONF_UI_API_KEY, ""),
                ): str,
                vol.Optional(
                    CONF_WIFI_GUEST,
                    default=self._cached.get(CONF_WIFI_GUEST, ""),
                ): str,
                vol.Optional(
                    CONF_WIFI_IOT,
                    default=self._cached.get(CONF_WIFI_IOT, ""),
                ): str,
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
            if CONF_SPEEDTEST_INTERVAL in cleaned:
                cleaned[CONF_SPEEDTEST_INTERVAL] = ConfigFlow._minutes_to_seconds(
                    cleaned[CONF_SPEEDTEST_INTERVAL]
                )
            if CONF_SPEEDTEST_ENTITIES in cleaned:
                value = cleaned[CONF_SPEEDTEST_ENTITIES]
                if isinstance(value, str):
                    collapsed = ",".join(
                        segment.strip()
                        for segment in value.replace("\n", ",").split(",")
                        if segment.strip()
                    )
                    cleaned[CONF_SPEEDTEST_ENTITIES] = (
                        collapsed or DEFAULT_SPEEDTEST_ENTITIES
                    )
                elif isinstance(value, (list, tuple, set)):
                    collapsed = ",".join(str(item).strip() for item in value if str(item).strip())
                    cleaned[CONF_SPEEDTEST_ENTITIES] = (
                        collapsed or DEFAULT_SPEEDTEST_ENTITIES
                    )
            for key in (CONF_WIFI_GUEST, CONF_WIFI_IOT):
                if key in cleaned:
                    cleaned[key] = ConfigFlow._normalize_optional_text(cleaned[key])
            if CONF_UI_API_KEY in cleaned:
                cleaned[CONF_UI_API_KEY] = ConfigFlow._normalize_api_key(
                    cleaned[CONF_UI_API_KEY]
                )
            merged = {**self._entry.data, **self._entry.options, **cleaned}
            if not ConfigFlow._has_auth(merged):
                errors["base"] = "missing_auth"
            else:
                try:
                    # Ensure Home Assistant context is available before validation.
                    assert self.hass is not None  # nosec B101
                    await _validate(self.hass, merged)
                    await _validate_ui_api_key(merged.get(CONF_UI_API_KEY))
                    if CONF_UI_API_KEY in cleaned:
                        current_options = dict(self._entry.options)
                        normalized_key = cleaned[CONF_UI_API_KEY]
                        if normalized_key is None:
                            current_options.pop(CONF_UI_API_KEY, None)
                        else:
                            current_options[CONF_UI_API_KEY] = normalized_key
                        cleaned.pop(CONF_UI_API_KEY, None)
                        self.hass.config_entries.async_update_entry(
                            self._entry,
                            options=current_options,
                        )
                    return self.async_create_entry(title="", data=cleaned)
                except AuthError:
                    errors["base"] = "invalid_auth"
                except ConnectivityError as err:
                    _LOGGER.error(
                        "Connectivity issue while validating UniFi controller %s:%s during options flow: %s",
                        merged.get(CONF_HOST),
                        merged.get(CONF_PORT, DEFAULT_PORT),
                        err,
                    )
                    errors["base"] = "cannot_connect"
                except UiCloudAuthError:
                    errors["base"] = "invalid_api_key"
                except UiCloudRateLimitError:
                    errors["base"] = "api_rate_limited"
                except UiCloudError:
                    errors["base"] = "api_unavailable"
                except APIError as err:
                    _LOGGER.error(
                        "UniFi API error while validating controller %s:%s during options flow: %s",
                        merged.get(CONF_HOST),
                        merged.get(CONF_PORT, DEFAULT_PORT),
                        err,
                    )
                    errors["base"] = "cannot_connect" if not err.expected else "unknown"
                except Exception as err:  # pragma: no cover - defensive guard
                    _LOGGER.exception(
                        "Unexpected error while validating UniFi controller %s:%s during options flow: %s",
                        merged.get(CONF_HOST),
                        merged.get(CONF_PORT, DEFAULT_PORT),
                        err,
                    )
                    errors["base"] = "unknown"

        current = {**self._entry.data, **self._entry.options}
        interval_default = ConfigFlow._seconds_to_minutes(
            ConfigFlow._resolve_interval_seconds(current)
        )
        if interval_default <= 0:
            interval_default = DEFAULT_SPEEDTEST_INTERVAL_MINUTES
        entities_default = current.get(
            CONF_SPEEDTEST_ENTITIES, DEFAULT_SPEEDTEST_ENTITIES
        )
        if isinstance(entities_default, (list, tuple, set)):
            entities_default = ",".join(
                str(item).strip() for item in entities_default if str(item).strip()
            )
        if not entities_default:
            entities_default = DEFAULT_SPEEDTEST_ENTITIES
        schema_fields: Dict[Any, Any] = {}

        host_default = current.get(CONF_HOST)
        if host_default is None:
            schema_fields[vol.Optional(CONF_HOST)] = str
        else:
            schema_fields[vol.Optional(CONF_HOST, default=host_default)] = str

        schema_fields[vol.Optional(
            CONF_PORT,
            default=current.get(CONF_PORT, DEFAULT_PORT),
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=1, max=65535))

        username_default = current.get(CONF_USERNAME)
        if username_default is None:
            schema_fields[vol.Optional(CONF_USERNAME)] = str
        else:
            schema_fields[vol.Optional(CONF_USERNAME, default=username_default)] = str

        password_default = current.get(CONF_PASSWORD)
        if password_default is None:
            schema_fields[vol.Optional(CONF_PASSWORD)] = str
        else:
            schema_fields[vol.Optional(CONF_PASSWORD, default=password_default)] = str

        site_default = current.get(CONF_SITE_ID)
        if site_default is None and CONF_SITE_ID not in current:
            site_default = DEFAULT_SITE
        if site_default is None:
            schema_fields[vol.Optional(CONF_SITE_ID)] = str
        else:
            schema_fields[vol.Optional(CONF_SITE_ID, default=site_default)] = str

        schema_fields[vol.Optional(
            CONF_VERIFY_SSL,
            default=current.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
        )] = bool
        schema_fields[vol.Optional(
            CONF_USE_PROXY_PREFIX,
            default=current.get(CONF_USE_PROXY_PREFIX, DEFAULT_USE_PROXY_PREFIX),
        )] = bool
        schema_fields[vol.Optional(
            CONF_TIMEOUT,
            default=current.get(CONF_TIMEOUT, DEFAULT_TIMEOUT),
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=1))
        schema_fields[vol.Optional(
            CONF_SPEEDTEST_INTERVAL,
            default=interval_default,
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=5))
        schema_fields[vol.Optional(
            CONF_SPEEDTEST_ENTITIES,
            default=entities_default,
        )] = str
        schema_fields[vol.Optional(
            CONF_UI_API_KEY,
            default=current.get(CONF_UI_API_KEY, ""),
        )] = vol.Any(str, None)
        schema_fields[vol.Optional(
            CONF_WIFI_GUEST,
            default=current.get(CONF_WIFI_GUEST),
        )] = vol.Any(str, None)
        schema_fields[vol.Optional(
            CONF_WIFI_IOT,
            default=current.get(CONF_WIFI_IOT),
        )] = vol.Any(str, None)

        schema = vol.Schema(schema_fields)
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
