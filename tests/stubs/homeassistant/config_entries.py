"""Config entries stubs."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from .core import HomeAssistant


class HandlerRegistry:
    """Simple registry used by the integration under test."""

    def register(self, _domain: str) -> Callable[[type[Any]], type[Any]]:
        def decorator(cls: type[Any]) -> type[Any]:
            return cls

        return decorator


HANDLERS = HandlerRegistry()


@dataclass
class ConfigEntry:
    """Representation of a stored config entry."""

    entry_id: str
    data: dict[str, Any]
    options: dict[str, Any] = field(default_factory=dict)

    def add_update_listener(self, listener: Callable[[HomeAssistant, ConfigEntry], None]) -> Callable[[], None]:
        def _remove() -> None:
            return None

        return _remove

    def async_on_unload(self, callback: Callable[[], None]) -> Callable[[], None]:
        return callback


class ConfigFlow:
    """Base config flow implementation with helpers used in tests."""

    VERSION = 1

    def __init__(self) -> None:
        self.hass: HomeAssistant
        self.context: dict[str, Any] = {}
        self._unique_id: str | None = None

    async def async_set_unique_id(self, unique_id: str) -> None:
        self._unique_id = unique_id

    def _abort_if_unique_id_configured(self) -> None:
        return None

    def async_create_entry(self, *, title: str, data: dict[str, Any], options: dict[str, Any]) -> dict[str, Any]:
        return {"type": "create_entry", "title": title, "data": data, "options": options}

    def async_show_form(
        self, *, step_id: str, data_schema: Any, errors: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return {"type": "form", "step_id": step_id, "errors": errors or {}, "data_schema": data_schema}

    def async_abort(self, *, reason: str) -> dict[str, Any]:
        return {"type": "abort", "reason": reason}


class OptionsFlow:
    """Base options flow used in tests."""

    def async_create_entry(self, *, title: str, data: dict[str, Any]) -> dict[str, Any]:
        return {"type": "create_entry", "title": title, "data": data}

    def async_show_form(
        self, *, step_id: str, data_schema: Any, errors: dict[str, str] | None = None
    ) -> dict[str, Any]:
        return {"type": "form", "step_id": step_id, "errors": errors or {}, "data_schema": data_schema}
