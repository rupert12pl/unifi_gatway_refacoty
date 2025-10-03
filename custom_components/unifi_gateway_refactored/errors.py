"""Error handling utilities for UniFi Gateway integration."""
from typing import Optional


class UniFiGatewayError(Exception):
    """Base class for UniFi Gateway errors."""


class ConnectionFailedError(UniFiGatewayError):
    """Error to indicate failed connection attempt."""

    def __init__(self, host: str, reason: Optional[str] = None):
        """Initialize the error."""
        message = (
            f"Failed to connect to {host}: {reason}"
            if reason
            else f"Failed to connect to {host}"
        )
        super().__init__(message)
        self.host = host
        self.reason = reason


class ValidationError(UniFiGatewayError):
    """Error to indicate invalid configuration."""

    def __init__(self, msg: str):
        """Initialize the error."""
        super().__init__(msg)
