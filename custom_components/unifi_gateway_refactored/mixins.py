"""UniFi Gateway Integration mixins."""
from __future__ import annotations

from typing import Any, Dict


from .const import DOMAIN
from .unifi_client import UniFiOSClient


class UniFiDeviceInfoMixin:
    """Mixin that provides consistent device info for UniFi Gateway entities."""

    def __init__(
        self,
        client: UniFiOSClient,
        device_name: str,
    ) -> None:
        """Initialize the mixin."""
        self._client = client
        self._device_name = device_name

    @property
    def device_info(self) -> Dict[str, Any]:
        """Return device information."""
        return {
            "identifiers": {(DOMAIN, self._client.instance_key())},
            "manufacturer": "Ubiquiti Networks",
            "name": self._device_name,
            "configuration_url": self._client.get_controller_url(),
        }