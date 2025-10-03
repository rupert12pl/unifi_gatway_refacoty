from __future__ import annotations

from typing import Any, Dict


class Entity:
    """Minimal Home Assistant Entity stub."""

    _attr_unique_id: str | None = None
    _attr_name: str | None = None
    _attr_icon: str | None = None
    _attr_device_info: Dict[str, Any] | None = None

    @property
    def name(self) -> str | None:
        return self._attr_name

    @property
    def unique_id(self) -> str | None:
        return self._attr_unique_id

    @property
    def icon(self) -> str | None:
        return self._attr_icon

    @property
    def device_info(self) -> Dict[str, Any] | None:
        return self._attr_device_info

    async def async_added_to_hass(self) -> None: ...

    async def async_will_remove_from_hass(self) -> None: ...

    async def async_update(self) -> None: ...

    async def async_write_ha_state(self) -> None: ...


class EntityCategory:
    """Minimal enumeration replacement."""

    DIAGNOSTIC = "diagnostic"
    CONFIG = "config"
