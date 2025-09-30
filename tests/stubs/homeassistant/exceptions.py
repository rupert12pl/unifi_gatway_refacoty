"""Home Assistant exception stubs."""


class HomeAssistantError(Exception):
    """Base class for Home Assistant errors."""


class ConfigEntryAuthFailed(HomeAssistantError):
    """Raised when authentication fails for a config entry."""


class ConfigEntryNotReady(HomeAssistantError):
    """Raised when a config entry cannot be set up yet."""
