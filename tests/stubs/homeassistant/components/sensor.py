from __future__ import annotations

from enum import Enum


class SensorDeviceClass(str, Enum):
    NONE = "none"


class SensorStateClass(str, Enum):
    MEASUREMENT = "measurement"


class SensorEntity:
    def __init__(self) -> None:
        self._attr_name: object = None
        self._attr_icon: object = None
        self._attr_device_class: object = None
        self._attr_state_class: object = None
        self._attr_device_info: object = None

    @property
    def available(self) -> bool:
        return True

    @property
    def native_value(self):
        return None

    def async_write_ha_state(self) -> None:
        return None
