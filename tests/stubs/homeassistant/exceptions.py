"""Exceptions raised by Home Assistant."""
from __future__ import annotations


class HomeAssistantError(Exception):
    """Base Home Assistant exception."""


class ConfigEntryAuthFailed(HomeAssistantError):
    """Raised when authentication fails for a config entry."""


class ConfigEntryNotReady(HomeAssistantError):
    """Raised when a config entry cannot be setup."""
