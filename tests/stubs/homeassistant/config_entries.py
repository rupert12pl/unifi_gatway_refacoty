"""Home Assistant config entries stubs for testing."""

from __future__ import annotations

import importlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, Awaitable, Callable, Dict


@dataclass
class ConfigEntry:
    """Simplified ConfigEntry."""

    entry_id: str = "test"
    title: str | None = None
    data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    domain: str | None = None

    def add_to_hass(self, hass: Any) -> None:
        """Register this entry with the provided Home Assistant instance."""

        hass.config_entries.async_add(self)

    def async_on_unload(self, func: Callable[[], Any]) -> Callable[[], Any]:
        """Register a function to call when config entry is unloaded.

        Args:
            func: Function to call when entry is unloaded.

        Returns:
            The function itself for convenience.
        """
        return func


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


class ConfigEntries:
    """Very small async config entries manager used in tests."""

    def __init__(self, hass: Any, store: Dict[str, Any] | None = None) -> None:
        self.hass = hass
        self._store = store or {}
        self._entries: Dict[str, ConfigEntry] = {}

    def async_add(self, entry: ConfigEntry) -> None:
        """Add an entry to the manager without setting it up."""

        self._entries[entry.entry_id] = entry

    async def async_setup(self, entry_id: str) -> bool:
        """Call the integration's ``async_setup_entry`` for the entry."""

        entry = self._entries.get(entry_id)
        if entry is None or not entry.domain:
            return False

        module = importlib.import_module(
            f"custom_components.{entry.domain}"
        )
        setup: Callable[[Any, ConfigEntry], Awaitable[bool]] | None = getattr(
            module, "async_setup_entry", None
        )
        if setup is None:
            return False

        result = await setup(self.hass, entry)
        if result:
            self._store.setdefault(entry.domain, {})[entry.entry_id] = entry
        return result

    async def async_unload(self, entry_id: str) -> bool:
        """Call the integration's ``async_unload_entry`` if available."""

        entry = self._entries.get(entry_id)
        if entry is None or not entry.domain:
            return False

        module = importlib.import_module(
            f"custom_components.{entry.domain}"
        )
        unload: Callable[[Any, ConfigEntry], Awaitable[bool]] | None = getattr(
            module, "async_unload_entry", None
        )
        if unload is None:
            return False

        result = await unload(self.hass, entry)
        if result:
            self._store.get(entry.domain, {}).pop(entry.entry_id, None)
        return result

    async def async_setup_platforms(
        self, entry: ConfigEntry, platforms: Iterable[Any]
    ) -> bool:
        """Placeholder to match Home Assistant's API."""

        return True

    async def async_forward_entry_setups(
        self, entry: ConfigEntry, platforms: Iterable[Any]
    ) -> bool:
        """Pretend to forward entry setups."""

        return True

    async def async_unload_platforms(
        self, entry: ConfigEntry, platforms: Iterable[Any]
    ) -> bool:
        """Pretend to unload forwarded platforms."""

        return True

    def async_update_entry(
        self,
        entry: ConfigEntry,
        *,
        data: Dict[str, Any] | None = None,
        options: Dict[str, Any] | None = None,
        title: str | None = None,
    ) -> None:
        """Update entry attributes in place to mimic HA behavior."""

        if data is not None:
            entry.data = data
        if options is not None:
            entry.options = options
        if title is not None:
            entry.title = title


__all__ = ["ConfigEntries", "ConfigEntry", "ConfigFlow", "OptionsFlow"]
