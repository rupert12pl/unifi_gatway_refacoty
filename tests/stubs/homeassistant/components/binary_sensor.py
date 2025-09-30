"""Binary sensor platform stubs."""
from __future__ import annotations

from typing import Any


class BinarySensorEntity:
    """Minimal binary sensor entity base class."""

    _attr_has_entity_name = False

    def __init__(self) -> None:
        self._attr_unique_id: str | None = None

    @property
    def available(self) -> bool:
        return True

    @property
    def is_on(self) -> bool | None:
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return None
