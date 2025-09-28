"""Minimal stubs for Home Assistant sensor module."""


class SensorEntity:
    """Basic sensor entity stub."""

    _attr_should_poll = False

    def __init__(self, *args, **kwargs) -> None:
        self._attr_name = kwargs.get("name")


class SensorDeviceClass:
    """Stub of Home Assistant sensor device classes."""

    TIMESTAMP = "timestamp"
    DURATION = "duration"


class SensorStateClass:
    """Stub of Home Assistant sensor state classes."""

    MEASUREMENT = "measurement"
