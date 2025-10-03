"""Stubs for ``pytest_homeassistant_custom_component.common`` utilities."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict
from uuid import uuid4

from homeassistant.config_entries import ConfigEntry


@dataclass
class MockConfigEntry(ConfigEntry):
    """Simplified stand-in for Home Assistant's ``MockConfigEntry`` utility."""

    domain: str = ""
    data: Dict[str, Any] = field(default_factory=dict)
    options: Dict[str, Any] = field(default_factory=dict)
    entry_id: str = field(default_factory=lambda: uuid4().hex)

    def add_to_hass(self, hass: Any) -> None:
        """Register the config entry with a Home Assistant instance."""
        if not hasattr(hass, "config_entries"):
            raise AttributeError("HomeAssistant instance missing config_entries manager")

        self.hass = hass
        if hasattr(hass.config_entries, "add"):
            hass.config_entries.add(self)
        else:  # pragma: no cover - defensive fallback for unexpected stubs
            hass.config_entries._entries[self.entry_id] = self  # type: ignore[attr-defined]

    def as_dict(self) -> Dict[str, Any]:  # noqa: D401 - mimic HA helper naming
        """Return a dictionary representation of the entry."""
        return {
            "entry_id": self.entry_id,
            "domain": self.domain,
            "data": dict(self.data),
            "options": dict(self.options),
        }


__all__ = ["MockConfigEntry"]
