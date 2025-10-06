
from __future__ import annotations

import logging
from typing import Any, Dict, Optional, TYPE_CHECKING

import aiohttp

from homeassistant import config_entries
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import AbortFlow

if TYPE_CHECKING:  # pragma: no cover - provide precise types for static analysis
    from homeassistant.helpers.selector import (  # type: ignore[import-not-found]
        TextSelector,
        TextSelectorConfig,
        TextSelectorType,
    )

try:  # pragma: no cover - optional selector support for newer Home Assistant
    from homeassistant.helpers.selector import (  # type: ignore[import-not-found]
        TextSelector as _RuntimeTextSelector,
        TextSelectorConfig as _RuntimeTextSelectorConfig,
        TextSelectorType as _RuntimeTextSelectorType,
    )
except (ImportError, AttributeError):  # pragma: no cover - fallback for test stubs
    _RuntimeTextSelector = None
    _RuntimeTextSelectorConfig = None
    _RuntimeTextSelectorType = None

if TYPE_CHECKING:
    from homeassistant.data_entry_flow import FlowResult
else:  # pragma: no cover - fallback for older Home Assistant
    FlowResult = Dict[str, Any]  # type: ignore[misc, assignment]
import voluptuous as vol

if TYPE_CHECKING:  # pragma: no cover - only for static analysis
    from voluptuous.validators import Any as VolAny  # type: ignore[import-not-found]
else:  # pragma: no cover - runtime compatibility for test stubs
    try:
        from voluptuous.validators import Any as VolAny  # type: ignore[attr-defined, import-not-found]
    except (ImportError, AttributeError):
        VolAny = type(vol.Any(str))  # type: ignore[assignment]

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


if (
    _RuntimeTextSelector is not None
    and _RuntimeTextSelectorConfig is not None
    and _RuntimeTextSelectorType is not None
):
    _UI_API_KEY_SELECTOR = _RuntimeTextSelector(
        _RuntimeTextSelectorConfig(type=_RuntimeTextSelectorType.PASSWORD)
    )
else:  # pragma: no cover - fallback when selectors are unavailable
    _UI_API_KEY_SELECTOR = str


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
        try:
            await client.async_get_hosts()
        except UiCloudError:
            raise
        except (TypeError, ValueError) as err:
            raise UiCloudAuthError(400) from err


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
            if key == CONF_HOST:
                normalized_host = ConfigFlow._normalize_host(value)
                if normalized_host is None:
                    continue
                cleaned[key] = normalized_host
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
        if isinstance(value, bool):
            return None
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned or None
        cleaned = str(value).strip()
        return cleaned or None

    @staticmethod
    def _normalize_host(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if isinstance(value, str):
            cleaned = value.strip()
            return cleaned or None
        cleaned = str(value).strip()
        return cleaned or None

    @staticmethod
    def _coerce_int(
        value: Any,
        *,
        minimum: Optional[int] = None,
        maximum: Optional[int] = None,
    ) -> Optional[int]:
        try:
            int_value = int(value)
        except (TypeError, ValueError):
            return None
        if minimum is not None and int_value < minimum:
            return None
        if maximum is not None and int_value > maximum:
            return None
        return int_value

    @staticmethod
    def _normalize_speedtest_entities(value: Any) -> str:
        if isinstance(value, str):
            collapsed = ",".join(
                segment.strip()
                for segment in value.replace("\n", ",").split(",")
                if segment.strip()
            )
            return collapsed or DEFAULT_SPEEDTEST_ENTITIES
        if isinstance(value, (list, tuple, set)):
            items: list[str] = []
            for item in value:
                if item is None:
                    continue
                if isinstance(item, str):
                    trimmed = item.strip()
                else:
                    trimmed = str(item).strip()
                if trimmed:
                    items.append(trimmed)
            collapsed = ",".join(items)
            if collapsed:
                return collapsed
            return DEFAULT_SPEEDTEST_ENTITIES
        normalized = ConfigFlow._normalize_optional_text(value)
        if normalized:
            return normalized
        return DEFAULT_SPEEDTEST_ENTITIES

    @staticmethod
    def _collapse_nullable_any(validator: Any) -> Any:
        """Replace nullable Any validators with a simple concrete validator."""

        if isinstance(validator, VolAny):
            filtered = [candidate for candidate in validator.validators if candidate is not None]
            if not filtered:
                return str
            primary = filtered[0]
            if isinstance(primary, type):
                return primary
            return str
        return validator

    @staticmethod
    def _build_schema(fields: Dict[Any, Any]) -> vol.Schema:
        """Create a voluptuous schema that Home Assistant can serialize."""

        sanitized: Dict[Any, Any] = {}
        for key, validator in fields.items():
            sanitized[key] = ConfigFlow._collapse_nullable_any(validator)
        return vol.Schema(sanitized)

    async def async_step_user(self, user_input: Optional[Dict[str, Any]] = None) -> FlowResult:
        errors: Dict[str, str] = {}
        if user_input is not None:
            sanitized = self._clean_auth_fields(user_input)
            host = sanitized.get(CONF_HOST)
            if host is None:
                errors["base"] = "missing_host"
            elif self._has_auth(sanitized):
                self._cached.update(sanitized)
                return await self.async_step_advanced()
            else:
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
                sanitized[CONF_SPEEDTEST_ENTITIES] = self._normalize_speedtest_entities(
                    sanitized[CONF_SPEEDTEST_ENTITIES]
                )
            self._cached.update(sanitized)
            data = dict(self._cached)
            normalized_host = self._normalize_host(data.get(CONF_HOST))
            if normalized_host is None:
                errors["base"] = "missing_host"
                self._cached.pop(CONF_HOST, None)
            else:
                data[CONF_HOST] = normalized_host
                self._cached[CONF_HOST] = normalized_host
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
            if not errors:
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

        entities_default = self._normalize_speedtest_entities(
            self._cached.get(CONF_SPEEDTEST_ENTITIES)
        )

        adv_schema = ConfigFlow._build_schema(
            {
                vol.Optional(
                    CONF_PORT,
                    default=self._coerce_int(
                        self._cached.get(CONF_PORT),
                        minimum=1,
                        maximum=65535,
                    )
                    or DEFAULT_PORT,
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
                    default=self._coerce_int(
                        self._cached.get(CONF_TIMEOUT), minimum=1
                    )
                    or DEFAULT_TIMEOUT,
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
                    default=self._normalize_api_key(
                        self._cached.get(CONF_UI_API_KEY)
                    )
                    or "",
                ): _UI_API_KEY_SELECTOR,
                vol.Optional(
                    CONF_WIFI_GUEST,
                    default=self._normalize_optional_text(
                        self._cached.get(CONF_WIFI_GUEST)
                    )
                    or "",
                ): str,
                vol.Optional(
                    CONF_WIFI_IOT,
                    default=self._normalize_optional_text(
                        self._cached.get(CONF_WIFI_IOT)
                    )
                    or "",
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
        wifi_cleared: set[str] = set()
        if user_input is not None:
            cleaned = ConfigFlow._clean_auth_fields(user_input)
            host_provided = CONF_HOST in user_input
            provided_host = (
                ConfigFlow._normalize_host(user_input.get(CONF_HOST))
                if host_provided
                else None
            )
            wifi_cleared = set()
            for wifi_key in (CONF_WIFI_GUEST, CONF_WIFI_IOT):
                if wifi_key in user_input:
                    normalized_wifi = ConfigFlow._normalize_optional_text(
                        user_input.get(wifi_key)
                    )
                    if normalized_wifi is None:
                        wifi_cleared.add(wifi_key)
                        cleaned.pop(wifi_key, None)
                    else:
                        cleaned[wifi_key] = normalized_wifi
            if CONF_SPEEDTEST_INTERVAL in cleaned:
                cleaned[CONF_SPEEDTEST_INTERVAL] = ConfigFlow._minutes_to_seconds(
                    cleaned[CONF_SPEEDTEST_INTERVAL]
                )
            if CONF_SPEEDTEST_ENTITIES in cleaned:
                cleaned[CONF_SPEEDTEST_ENTITIES] = ConfigFlow._normalize_speedtest_entities(
                    cleaned[CONF_SPEEDTEST_ENTITIES]
                )
            for key in (CONF_WIFI_GUEST, CONF_WIFI_IOT):
                if key in cleaned:
                    normalized_wifi = ConfigFlow._normalize_optional_text(cleaned[key])
                    if normalized_wifi is None:
                        cleaned.pop(key, None)
                    else:
                        cleaned[key] = normalized_wifi
            if CONF_UI_API_KEY in cleaned:
                normalized_key = ConfigFlow._normalize_api_key(cleaned[CONF_UI_API_KEY])
                if normalized_key is None:
                    cleaned.pop(CONF_UI_API_KEY, None)
                else:
                    cleaned[CONF_UI_API_KEY] = normalized_key
            merged = {**self._entry.data, **self._entry.options, **cleaned}
            normalized_host = ConfigFlow._normalize_host(merged.get(CONF_HOST))
            if host_provided and provided_host is None:
                errors["base"] = "missing_host"
            elif normalized_host is None:
                errors["base"] = "missing_host"
            elif not ConfigFlow._has_auth(merged):
                errors["base"] = "missing_auth"
            else:
                try:
                    # Ensure Home Assistant context is available before validation.
                    assert self.hass is not None  # nosec B101
                    merged[CONF_HOST] = normalized_host
                    cleaned[CONF_HOST] = normalized_host
                    normalized_key = ConfigFlow._normalize_api_key(
                        merged.get(CONF_UI_API_KEY)
                    )
                    if normalized_key is None:
                        merged.pop(CONF_UI_API_KEY, None)
                    else:
                        merged[CONF_UI_API_KEY] = normalized_key
                        cleaned.setdefault(CONF_UI_API_KEY, normalized_key)
                    if CONF_SPEEDTEST_ENTITIES in merged:
                        merged[CONF_SPEEDTEST_ENTITIES] = (
                            ConfigFlow._normalize_speedtest_entities(
                                merged[CONF_SPEEDTEST_ENTITIES]
                            )
                        )
                        if CONF_SPEEDTEST_ENTITIES in cleaned:
                            cleaned[CONF_SPEEDTEST_ENTITIES] = merged[
                                CONF_SPEEDTEST_ENTITIES
                            ]
                    for wifi_key in (CONF_WIFI_GUEST, CONF_WIFI_IOT):
                        if wifi_key in wifi_cleared:
                            merged.pop(wifi_key, None)
                            cleaned.pop(wifi_key, None)
                            continue
                        normalized_wifi = ConfigFlow._normalize_optional_text(
                            merged.get(wifi_key)
                        )
                        if normalized_wifi is None:
                            merged.pop(wifi_key, None)
                            cleaned.pop(wifi_key, None)
                        else:
                            merged[wifi_key] = normalized_wifi
                            if wifi_key in cleaned:
                                cleaned[wifi_key] = normalized_wifi
                    await _validate(self.hass, merged)
                    await _validate_ui_api_key(merged.get(CONF_UI_API_KEY))
                    if self.hass is not None:
                        current_data = dict(self._entry.data)
                        updated = False
                        relevant_keys = {
                            CONF_HOST,
                            CONF_USERNAME,
                            CONF_PASSWORD,
                            CONF_PORT,
                            CONF_SITE_ID,
                            CONF_VERIFY_SSL,
                            CONF_USE_PROXY_PREFIX,
                            CONF_TIMEOUT,
                            CONF_SPEEDTEST_INTERVAL,
                            CONF_SPEEDTEST_ENTITIES,
                            CONF_UI_API_KEY,
                            CONF_WIFI_GUEST,
                            CONF_WIFI_IOT,
                        }
                        for key in relevant_keys:
                            if key in merged:
                                value = merged[key]
                                if current_data.get(key) != value:
                                    current_data[key] = value
                                    updated = True
                            elif key in current_data:
                                current_data.pop(key)
                                updated = True
                        if updated:
                            self.hass.config_entries.async_update_entry(
                                self._entry,
                                data=current_data,
                            )
                    if CONF_UI_API_KEY in cleaned:
                        current_options = dict(self._entry.options)
                        normalized_key = cleaned[CONF_UI_API_KEY]
                        if normalized_key is None:
                            current_options.pop(CONF_UI_API_KEY, None)
                        else:
                            current_options[CONF_UI_API_KEY] = normalized_key
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
        host_default = ConfigFlow._normalize_host(current.get(CONF_HOST))
        if host_default is not None:
            current[CONF_HOST] = host_default
        else:
            current.pop(CONF_HOST, None)
        interval_default = ConfigFlow._seconds_to_minutes(
            ConfigFlow._resolve_interval_seconds(current)
        )
        if interval_default <= 0:
            interval_default = DEFAULT_SPEEDTEST_INTERVAL_MINUTES
        entities_default = ConfigFlow._normalize_speedtest_entities(
            current.get(CONF_SPEEDTEST_ENTITIES)
        )
        schema_fields: Dict[Any, Any] = {}

        host_default = current.get(CONF_HOST)
        if host_default is None:
            schema_fields[vol.Optional(CONF_HOST)] = str
        else:
            schema_fields[vol.Optional(CONF_HOST, default=host_default)] = str

        schema_fields[vol.Optional(
            CONF_PORT,
            default=ConfigFlow._coerce_int(
                current.get(CONF_PORT), minimum=1, maximum=65535
            )
            or DEFAULT_PORT,
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=1, max=65535))

        username_default = ConfigFlow._normalize_optional_text(
            current.get(CONF_USERNAME)
        )
        if username_default is None:
            schema_fields[vol.Optional(CONF_USERNAME)] = str
        else:
            schema_fields[vol.Optional(CONF_USERNAME, default=username_default)] = str

        password_default = ConfigFlow._normalize_optional_text(
            current.get(CONF_PASSWORD)
        )
        if password_default is None:
            schema_fields[vol.Optional(CONF_PASSWORD)] = str
        else:
            schema_fields[vol.Optional(CONF_PASSWORD, default=password_default)] = str

        site_default = ConfigFlow._normalize_optional_text(current.get(CONF_SITE_ID))
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
            default=ConfigFlow._coerce_int(
                current.get(CONF_TIMEOUT), minimum=1
            )
            or DEFAULT_TIMEOUT,
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=1))
        schema_fields[vol.Optional(
            CONF_SPEEDTEST_INTERVAL,
            default=interval_default,
        )] = vol.All(vol.Coerce(int), vol.Clamp(min=5))
        schema_fields[vol.Optional(
            CONF_SPEEDTEST_ENTITIES,
            default=entities_default,
        )] = str
        ui_key_default = (
            ConfigFlow._normalize_api_key(current.get(CONF_UI_API_KEY)) or ""
        )
        schema_fields[vol.Optional(
            CONF_UI_API_KEY,
            default=ui_key_default,
        )] = _UI_API_KEY_SELECTOR
        wifi_guest_default = (
            ConfigFlow._normalize_optional_text(current.get(CONF_WIFI_GUEST)) or ""
        )
        schema_fields[vol.Optional(
            CONF_WIFI_GUEST,
            default=wifi_guest_default,
        )] = vol.Any(str, None)
        wifi_iot_default = (
            ConfigFlow._normalize_optional_text(current.get(CONF_WIFI_IOT)) or ""
        )
        schema_fields[vol.Optional(
            CONF_WIFI_IOT,
            default=wifi_iot_default,
        )] = vol.Any(str, None)

        schema = ConfigFlow._build_schema(schema_fields)
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)
