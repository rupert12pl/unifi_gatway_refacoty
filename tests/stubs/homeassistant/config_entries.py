"""Simplified Home Assistant config entry stubs used in tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib import import_module
from typing import Any, Callable, Dict, Iterable, MutableMapping
from uuid import uuid4


@dataclass
class ConfigEntry:
    """Lightweight representation of a Home Assistant config entry."""

    entry_id: str = field(default_factory=lambda: uuid4().hex)
    domain: str = ""
    title: str | None = None
    data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    unique_id: str | None = None
    state: str = "not_loaded"

    def async_on_unload(self, func: Callable[[], Any]) -> Callable[[], Any]:
        """Register a function to call when config entry is unloaded."""
        return func


class ConfigEntries:
    """Minimal config entries manager with async setup helpers."""

    def __init__(self, hass: Any, entries: MutableMapping[str, ConfigEntry] | None = None) -> None:
        self.hass = hass
        self._entries: MutableMapping[str, ConfigEntry] = entries or {}

    def add(self, entry: ConfigEntry) -> None:
        """Register a config entry with the manager."""
        self._entries[entry.entry_id] = entry
        entry.hass = self.hass  # type: ignore[attr-defined]

    def remove(self, entry_id: str) -> None:
        """Remove an entry from the registry if present."""
        self._entries.pop(entry_id, None)

    async def async_setup(self, entry_id: str) -> bool:
        """Load the integration's ``async_setup_entry`` for the stored entry."""
        entry = self._entries[entry_id]
        module = import_module(f"custom_components.{entry.domain}")
        setup_entry = module.async_setup_entry  # type: ignore[attr-defined]
        result = await setup_entry(self.hass, entry)
        entry.state = "loaded"
        return result

    async def async_forward_entry_setups(
        self, entry: ConfigEntry, platforms: Iterable[str]
    ) -> bool:
        """Pretend to forward the config entry setup to platform loaders."""
        return True

    async def async_unload_platforms(self, entry: ConfigEntry, platforms: Iterable[str]) -> bool:
        """Unload platforms associated with an entry."""
        entry.state = "not_loaded"
        return True


class ConfigFlow:
    """Minimal ConfigFlow stub supporting domain kwarg."""

    domain: str | None = None
    hass: Any | None = None

    def __init_subclass__(cls, *, domain: str | None = None, **_: Any) -> None:
        cls.domain = domain

    def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any | None = None,
        errors: Dict[str, str] | None = None,
        description_placeholders: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {}

    def async_create_entry(
        self, *, title: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {"title": title, "data": data}

    def async_abort(self, reason: str) -> Dict[str, Any]:
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

    def async_create_entry(
        self, *, title: str, data: Dict[str, Any]
    ) -> Dict[str, Any]:
        return {"title": title, "data": data}

    def async_show_form(
        self,
        *,
        step_id: str,
        data_schema: Any | None = None,
        errors: Dict[str, str] | None = None,
        description_placeholders: Dict[str, Any] | None = None,
    ) -> Dict[str, Any]:
        return {}


__all__ = [
    "ConfigEntry",
    "ConfigEntries",
    "ConfigFlow",
    "OptionsFlow",
]
