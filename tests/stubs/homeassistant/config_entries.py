"""Stub for homeassistant.config_entries."""

from dataclasses import dataclass, field
from typing import Any, Dict, Callable


@dataclass
class ConfigEntry:
    """Simplified ConfigEntry."""

    entry_id: str = "test"
    title: str | None = None
    data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)

    def async_on_unload(self, func: Callable[[], Any]) -> Callable[[], Any]:
        return func


class ConfigFlow:
    """Minimal ConfigFlow stub supporting domain kwarg."""

    domain: str | None = None
    hass: Any | None = None

    def __init_subclass__(cls, *, domain: str | None = None, **_: Any) -> None:
        cls.domain = domain

    async def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any | None = None,
        errors: Dict[str, str] | None = None,
        description_placeholders: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {}

    async def async_create_entry(
        self, *, title: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {"title": title, "data": data}

    async def async_abort(self, reason: str) -> Dict[str, Any]:
        return {"type": "abort", "reason": reason}

    async def async_set_unique_id(
        self, unique_id: str, *, raise_on_progress: bool = False
    ) -> None:
        return None

    def _abort_if_unique_id_configured(self) -> None:
        return None


class OptionsFlow:
    """Minimal OptionsFlow stub."""

    def __init__(self, entry: ConfigEntry) -> None:
        self.config_entry = entry
        self.hass: Any | None = None

    async def async_create_entry(
        self, *, title: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {"title": title, "data": data}

    async def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any | None = None,
        errors: Dict[str, str] | None = None,
        description_placeholders: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {}


__all__ = ["ConfigEntry", "ConfigFlow", "OptionsFlow"]
