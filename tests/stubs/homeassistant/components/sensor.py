"""Sensor platform stubs."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True, slots=True, kw_only=True)
class SensorEntityDescription:
    """Description of a sensor entity."""

    key: str
    translation_key: str | None = None
    native_unit_of_measurement: str | None = None
    suggested_display_precision: int | None = None


class SensorEntity:
    """Minimal sensor entity."""

    _attr_has_entity_name = False

    def __init__(self) -> None:
        self.entity_description: SensorEntityDescription | None = None
        self._attr_unique_id: str | None = None

    @property
    def native_value(self) -> Any:
        return None

    @property
    def extra_state_attributes(self) -> dict[str, Any] | None:
        return None
