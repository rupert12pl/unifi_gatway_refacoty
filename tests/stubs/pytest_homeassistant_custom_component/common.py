"""Minimal subset of pytest-homeassistant-custom-component helpers used in tests."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List
from uuid import uuid4


@dataclass
class MockConfigEntry:
    """Lightweight stand-in for Home Assistant's MockConfigEntry helper."""

    domain: str
    data: Dict[str, Any] | None = None
    options: Dict[str, Any] | None = None
    title: str | None = None
    entry_id: str = ""
    unique_id: str | None = None
    source: str | None = None
    state: str | None = None
    version: int = 1
    minor_version: int = 1
    pref_disable_new_entities: bool = False
    pref_disable_polling: bool = False
    supports_unload: bool = True
    runtime_data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.entry_id:
            self.entry_id = uuid4().hex
        if self.data is None:
            self.data = {}
        if self.options is None:
            self.options = {}

    def add_to_hass(self, hass: Any) -> None:
        """Register this config entry with the provided Home Assistant instance."""

        hass.config_entries.async_add(self)  # type: ignore[attr-defined]

    def add_update_listener(
        self, listener: Callable[[MockConfigEntry], None]
    ) -> Callable[[MockConfigEntry], None]:
        """Store update listeners to align with the real helper API."""

        if "update_listeners" not in self.runtime_data:
            self.runtime_data["update_listeners"] = []
        listeners: List[Callable[[MockConfigEntry], None]] = self.runtime_data[
            "update_listeners"
        ]
        listeners.append(listener)
        return listener

    async def async_run_listeners(self) -> None:
        """Invoke update listeners similar to Home Assistant's helper."""

        for listener in list(self.runtime_data.get("update_listeners", [])):
            await listener(self)

    def as_dict(self) -> Dict[str, Any]:
        """Return a dictionary representation used by some tests."""

        data: Dict[str, Any] = dict(self.data or {})
        options: Dict[str, Any] = dict(self.options or {})

        return {
            "entry_id": self.entry_id,
            "version": self.version,
            "minor_version": self.minor_version,
            "domain": self.domain,
            "title": self.title,
            "data": data,
            "options": options,
            "pref_disable_new_entities": self.pref_disable_new_entities,
            "pref_disable_polling": self.pref_disable_polling,
            "source": self.source,
            "unique_id": self.unique_id,
            "disabled_by": None,
        }

    def mock_async_remove(self, hass: Any) -> None:
        """Helper to mimic removal in the actual helper."""

        domain_entries = hass.config_entries._store.get(self.domain, {})  # type: ignore[attr-defined,unused-ignore]
        domain_entries.pop(self.entry_id, None)

    def add_to_storage(self, hass: Any) -> None:
        """Store the entry in the in-memory storage used by the config entries stub."""

        hass.config_entries._store.setdefault(self.domain, {})[self.entry_id] = self  # type: ignore[attr-defined]


__all__ = ["MockConfigEntry"]
