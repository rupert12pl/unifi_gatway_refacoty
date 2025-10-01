"""Home Assistant exception stubs."""


class HomeAssistantError(Exception):
    """Exception raised for Home Assistant specific errors."""


class ConfigEntryAuthFailed(HomeAssistantError):
    """Raised when authentication for a config entry fails."""


class ConfigEntryNotReady(HomeAssistantError):
    """Raised when a config entry is not ready to be set up."""


__all__ = [
    "HomeAssistantError",
    "ConfigEntryAuthFailed",
    "ConfigEntryNotReady",
]
