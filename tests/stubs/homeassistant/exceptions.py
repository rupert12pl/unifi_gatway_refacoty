"""Home Assistant exception stubs used in tests."""

from __future__ import annotations


class HomeAssistantError(Exception):
    """Exception raised for Home Assistant specific errors."""


class ConfigEntryAuthFailed(HomeAssistantError):  # noqa: N818 - matches Home Assistant API
    """Raised when authentication for a config entry fails."""


class ConfigEntryNotReady(HomeAssistantError):  # noqa: N818 - matches Home Assistant API
    """Raised when a config entry is not ready to be set up."""


__all__ = [
    "HomeAssistantError",
    "ConfigEntryAuthFailed",
    "ConfigEntryNotReady",
]
