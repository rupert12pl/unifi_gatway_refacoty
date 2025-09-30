"""Data coordinator and API client for the UniFi Gateway Refactory integration."""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urljoin

from aiohttp import BasicAuth, ClientSession, ClientTimeout
from aiohttp.client_exceptions import ClientConnectorError, ClientError
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    BACKOFF_BASE,
    INITIAL_BACKOFF,
    MAX_BACKOFF,
    MAX_RETRIES,
    RATE_LIMIT,
    REQUEST_TIMEOUT,
)

_LOGGER = logging.getLogger(__name__)


class UniFiGatewayError(Exception):
    """Base error for UniFi Gateway failures."""


class UniFiGatewayApiError(UniFiGatewayError):
    """Raised when the UniFi controller returns a non-successful response."""


class UniFiGatewayAuthError(UniFiGatewayError):
    """Raised when authentication fails."""


class UniFiGatewayInvalidResponse(UniFiGatewayError):
    """Raised when the controller returns malformed data."""


@dataclass(slots=True)
class UniFiGatewayData:
    """Container for coordinator data."""

    health: list[dict[str, Any]]
    wlans: list[dict[str, Any]]
    last_fetch: datetime


def as_float(value: Any) -> float | None:
    """Convert a value to float in a defensive way."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str) and value.strip():
        try:
            return float(value)
        except ValueError:  # pragma: no cover - guardrail for bad payloads
            return None
    return None


class UniFiGatewayApi:
    """Minimal UniFi controller API client."""

    def __init__(
        self,
        *,
        session: ClientSession,
        host: str,
        username: str,
        password: str,
        site: str,
        verify_ssl: bool,
    ) -> None:
        self._session = session
        self._host = host.rstrip("/") + "/"
        self._auth = BasicAuth(username, password, encoding="utf-8")
        self._site = site
        self.verify_ssl = verify_ssl
        self._timeout = ClientTimeout(total=REQUEST_TIMEOUT)
        self._semaphore = asyncio.Semaphore(RATE_LIMIT)

    async def async_fetch_data(self) -> UniFiGatewayData:
        """Fetch controller data for sensors."""
        health, wlans = await asyncio.gather(
            self._async_request_json("GET", self._site_url("stat/health")),
            self._async_request_json("GET", self._site_url("rest/wlanconf")),
        )
        now = datetime.now(timezone.utc)
        return UniFiGatewayData(
            health=health if isinstance(health, list) else [],
            wlans=wlans if isinstance(wlans, list) else [],
            last_fetch=now,
        )

    def _site_url(self, path: str) -> str:
        return urljoin(self._host, f"proxy/network/api/s/{self._site}/{path}")

    async def _async_request_json(self, method: str, url: str) -> Any:
        backoff = INITIAL_BACKOFF
        last_error: Exception | None = None
        for attempt in range(1, MAX_RETRIES + 1):
            async with self._semaphore:
                try:
                    async with self._session.request(
                        method,
                        url,
                        auth=self._auth,
                        timeout=self._timeout,
                    ) as response:
                        if response.status in (401, 403):
                            raise UniFiGatewayAuthError("Invalid credentials")
                        if response.status == 429 or 500 <= response.status < 600:
                            _LOGGER.debug(
                                "Transient error %s on %s (attempt %s/%s)",
                                response.status,
                                url,
                                attempt,
                                MAX_RETRIES,
                            )
                            last_error = UniFiGatewayApiError(
                                f"Controller returned status {response.status}"
                            )
                        elif response.status >= 400:
                            text = await response.text()
                            raise UniFiGatewayApiError(
                                f"Controller error {response.status}: {text[:128]}"
                            )
                        else:
                            try:
                                return await response.json(content_type=None)
                            except ClientError as err:  # pragma: no cover - defensive
                                raise UniFiGatewayInvalidResponse("Failed to parse response") from err
                            except ValueError as err:
                                raise UniFiGatewayInvalidResponse(
                                    "Invalid JSON received from controller"
                                ) from err
                except ClientConnectorError as err:
                    last_error = err
                    _LOGGER.debug("Connection error to %s: %s", url, err)
                except ClientError as err:
                    last_error = err
                    _LOGGER.debug("HTTP error calling %s: %s", url, err)

            if attempt == MAX_RETRIES:
                break
            sleep_time = min(backoff, MAX_BACKOFF) + _SYSTEM_RANDOM.uniform(0, 0.5)
            await asyncio.sleep(sleep_time)
            backoff *= BACKOFF_BASE

        if last_error:
            raise UniFiGatewayApiError(str(last_error)) from last_error
        raise UniFiGatewayApiError("Unknown error calling controller")


class UniFiGatewayCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinator handling UniFi gateway updates."""

    def __init__(
        self,
        *,
        hass: HomeAssistant,
        api: UniFiGatewayApi,
        update_interval_seconds: int,
    ) -> None:
        super().__init__(
            hass,
            _LOGGER,
            name="UniFi Gateway Refactory",
            update_interval=None,
        )
        self.api = api
        self._update_interval_seconds = update_interval_seconds
        self.update_interval: timedelta | None
        self.update_interval = self._resolve_interval()

    async def _async_update_data(self) -> UniFiGatewayData:
        try:
            data = await self.api.async_fetch_data()
        except UniFiGatewayAuthError as err:
            raise ConfigEntryAuthFailed("Authentication failed") from err
        except UniFiGatewayInvalidResponse as err:
            raise UpdateFailed(str(err)) from err
        except UniFiGatewayError as err:
            raise UpdateFailed(str(err)) from err
        return data

    async def async_config_entry_first_refresh(self) -> None:
        await super().async_config_entry_first_refresh()
        self.update_interval = self._resolve_interval()

    @property
    def update_interval_seconds(self) -> int:
        return self._update_interval_seconds

    @update_interval_seconds.setter
    def update_interval_seconds(self, value: int) -> None:
        self._update_interval_seconds = max(1, int(value))
        self.update_interval = self._resolve_interval()

    def _resolve_interval(self) -> timedelta:
        return timedelta(seconds=self._update_interval_seconds)
_SYSTEM_RANDOM = random.SystemRandom()

