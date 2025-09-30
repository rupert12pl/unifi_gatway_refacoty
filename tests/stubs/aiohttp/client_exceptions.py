"""Stub aiohttp.client_exceptions module for tests."""
from __future__ import annotations


class ClientError(Exception):
    """Base error for client exceptions."""


class ClientConnectorError(ClientError):
    """Connection failure exception."""

