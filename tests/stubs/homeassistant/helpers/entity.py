from __future__ import annotations

from typing import Any, Dict


"""Test stubs for Home Assistant entity helpers."""

from typing import Any, Dict

class Entity:
    """Simplified Entity base class for testing."""

    _attr_unique_id: str | None = None
    _attr_name: str | None = None
    _attr_icon: str | None = None
    _attr_device_info: Dict[str, Any] | None = None

    @property
    def name(self) -> str | None:
        """Return the entity name."""
        return self._attr_name

    @property
    def unique_id(self) -> str | None:
        """Return entity unique ID."""
        return self._attr_unique_id

    @property
    def icon(self) -> str | None:
        """Return the entity icon."""
        return self._attr_icon

    @property
    def device_info(self) -> Dict[str, Any] | None:
        """Return device information about this entity."""
        return self._attr_device_info

    async def async_added_to_hass(self) -> None:
        """Run when entity about to be added to hass."""
        ...

    async def async_will_remove_from_hass(self) -> None:
        """Run when entity about to be removed from hass."""
        ...

    async def async_update(self) -> None:
        """Update the entity."""
        ...

    async def async_write_ha_state(self) -> None:
        """Write the state to Home Assistant."""
        ...


class EntityCategory:
    """Minimal enumeration replacement."""

    DIAGNOSTIC = "diagnostic"
    CONFIG = "config"
