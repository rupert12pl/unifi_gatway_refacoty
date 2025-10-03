"""UniFi Gateway async client implementation."""
from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, List, Optional, TypeVar, Generic

from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.exceptions import HomeAssistantError

from .const import DEFAULT_TIMEOUT
from .unifi_client import UniFiOSClient, APIError, ConnectivityError, AuthError

_LOGGER = logging.getLogger(__name__)
T = TypeVar("T")

class UniFiGatewayAsyncClient:
    """Async client wrapper for UniFi Gateway."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: UniFiOSClient,
    ) -> None:
        """Initialize the async client."""
        self.hass = hass
        self._client = client
        self._lock = asyncio.Lock()

    async def _async_with_retry(
        self,
        method: str,
        *args: Any,
        retries: int = 3,
        **kwargs: Any,
    ) -> Any:
        """Execute a client method with retry logic."""
        last_exception = None
        
        for attempt in range(retries):
            try:
                async with self._lock:
                    return await self.hass.async_add_executor_job(
                        lambda: getattr(self._client, method)(*args, **kwargs)
                    )
            except (ConnectivityError, APIError) as err:
                last_exception = err
                if attempt == retries - 1:
                    raise
                _LOGGER.debug(
                    "Attempt %d/%d for %s failed: %s",
                    attempt + 1,
                    retries,
                    method,
                    err,
                )
                await asyncio.sleep(min(2 ** attempt, 10))

        if last_exception:
            raise last_exception
        
        raise HomeAssistantError(f"Failed to execute {method} after {retries} attempts")

    async def async_ping(self) -> bool:
        """Test connection to the controller."""
        return await self._async_with_retry("ping")

    async def async_get_wlans(self) -> List[Dict[str, Any]]:
        """Get WLAN configurations."""
        return await self._async_with_retry("get_wlans")

    async def async_get_clients(self) -> List[Dict[str, Any]]:
        """Get client list."""
        return await self._async_with_retry("get_clients")

    async def async_get_vpn_servers(self) -> List[Dict[str, Any]]:
        """Get VPN server configurations."""
        return await self._async_with_retry("get_vpn_servers")

    async def async_get_vpn_peers(self) -> List[Dict[str, Any]]:
        """Get VPN peer configurations."""
        return await self._async_with_retry("get_vpn_peers")

    async def async_get_wan_links(self) -> List[Dict[str, Any]]:
        """Get WAN link information."""
        return await self._async_with_retry("get_wan_links")

    async def async_close(self) -> None:
        """Close the client connection."""
        await self.hass.async_add_executor_job(self._client.close)