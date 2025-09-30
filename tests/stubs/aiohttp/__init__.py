"""Minimal aiohttp stub for unit tests."""
from __future__ import annotations

from dataclasses import dataclass


class ClientError(Exception):
    """Base exception for aiohttp client errors."""


class ContentTypeError(ClientError):
    """Raised when JSON decoding fails."""


@dataclass
class BasicAuth:
    """Simple container representing basic auth credentials."""

    login: str
    password: str


@dataclass
class ClientTimeout:
    """Timeout configuration placeholder."""

    total: float | None = None
