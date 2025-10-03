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
        """Initialize the sensor."""
        self._attr_name = kwargs.get("name")

    @property
    def native_value(self) -> Any | None:
        """Return the native sensor value."""
        return self._attr_native_value

    @property
    def extra_state_attributes(self) -> Dict[str, Any] | None:
        """Return extra state attributes."""
        return self._attr_extra_state_attributes

    @property
    def available(self) -> bool:
        """Return True if entity is available."""
        return self._attr_available

    def async_write_ha_state(self) -> None:
        """Write the state to Home Assistant."""
        return None

    async def async_added_to_hass(self) -> None:
        """Run when entity about to be added to Home Assistant."""
        return None


class SensorDeviceClass:
    """Stub of Home Assistant sensor device classes."""

    TIMESTAMP = "timestamp"
    DURATION = "duration"


class SensorStateClass:
    """Stub of Home Assistant sensor state classes."""

    MEASUREMENT = "measurement"
