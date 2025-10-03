"""Button entity stub for Home Assistant."""

from __future__ import annotations

from typing import Any

from homeassistant.helpers.entity import Entity


class ButtonEntity(Entity):
    """Base class for button entities."""

    _attr_entity_category: Any

    async def async_press(self) -> None:
        """Press the button."""
        ...
