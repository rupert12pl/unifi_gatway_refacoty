"""Minimal stubs for Home Assistant sensor module."""


from typing import Any, Dict


class SensorEntity:
    """Basic sensor entity stub."""

    _attr_should_poll = False
    _attr_available: bool = True
    _attr_native_value: Any | None = None
    _attr_extra_state_attributes: Dict[str, Any] | None = None
    hass: Any | None = None

    def __init__(self, *args, **kwargs) -> None:
        self._attr_name = kwargs.get("name")

    @property
    def native_value(self) -> Any | None:
        return self._attr_native_value

    @property
    def extra_state_attributes(self) -> Dict[str, Any] | None:
        return self._attr_extra_state_attributes

    @property
    def available(self) -> bool:
        return self._attr_available

    def async_write_ha_state(self) -> None:
        return None

    async def async_added_to_hass(self) -> None:
        return None


class SensorDeviceClass:
    """Stub of Home Assistant sensor device classes."""

    TIMESTAMP = "timestamp"
    DURATION = "duration"


class SensorStateClass:
    """Stub of Home Assistant sensor state classes."""

    MEASUREMENT = "measurement"
