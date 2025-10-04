"""Asynchronous client for retrieving WAN metadata from the UniFi Cloud API."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, AsyncContextManager, Final, NotRequired, TypedDict, cast

import aiohttp
from aiohttp import ClientResponse

from .const import API_CLOUD_HOSTS_URL

DEFAULT_TIMEOUT: Final[int] = 15
MAX_BACKOFF: Final[float] = 30.0
MAX_ATTEMPTS: Final[int] = 4


class UiCloudError(Exception):
    """Base error raised for UniFi cloud client failures."""


class UiCloudAuthError(UiCloudError):
    """Raised when authentication with the UniFi cloud API fails."""

    def __init__(self, status: int) -> None:
        super().__init__(f"Authentication with UniFi Cloud API failed (status={status})")
        self.status = status


class UiCloudRateLimitError(UiCloudError):
    """Raised when the UniFi cloud API responds with HTTP 429."""

    def __init__(self, retry_after: float | None) -> None:
        message = "UniFi Cloud API rate limited"
        if retry_after is not None:
            message = f"{message}; retry in {retry_after:.1f}s"
        super().__init__(message)
        self.retry_after = retry_after


class UiCloudRequestError(UiCloudError):
    """Raised when the UniFi cloud API request fails permanently."""

    def __init__(self, status: int, message: str | None = None) -> None:
        description = message or "Unexpected response from UniFi Cloud API"
        super().__init__(f"{description} (status={status})")
        self.status = status


class WanEntry(TypedDict, total=False):
    type: str
    interface: str
    associatedInterface: NotRequired[str]
    mac: NotRequired[str]
    ipv4: NotRequired[str]
    ipv6: NotRequired[str]


class ReportedState(TypedDict, total=False):
    hostname: NotRequired[str]
    ip: NotRequired[str]
    wans: NotRequired[list[WanEntry]]


class Hardware(TypedDict, total=False):
    mac: NotRequired[str]
    name: NotRequired[str]


class HostItem(TypedDict, total=False):
    type: NotRequired[str]
    reportedState: NotRequired[ReportedState]
    hardware: NotRequired[Hardware]


class HostsResponse(TypedDict):
    data: list[HostItem]
    httpStatusCode: int


@dataclass(slots=True)
class UiCloudClient:
    """Small aiohttp-based client for the UniFi Cloud API."""

    session: aiohttp.ClientSession
    api_key: str
    hosts_url: str = API_CLOUD_HOSTS_URL
    request_timeout: int = DEFAULT_TIMEOUT

    async def async_get_hosts(self) -> HostsResponse:
        """Return the hosts payload from the UniFi Cloud API."""

        url = self.hosts_url.rstrip("/")
        headers = {
            "Accept": "application/json",
            "X-API-Key": self.api_key,
        }
        backoff = 0.5
        last_error: UiCloudError | None = None

        timeout_config = aiohttp.ClientTimeout(total=self.request_timeout)
        for attempt in range(1, MAX_ATTEMPTS + 1):
            if attempt > 1:
                await asyncio.sleep(min(backoff, MAX_BACKOFF))
                backoff = min(backoff * 2, MAX_BACKOFF)
            try:
                request_cm = self.session.get(
                    url, headers=headers, timeout=timeout_config
                )
                async with cast(AsyncContextManager[ClientResponse], request_cm) as resp:
                    status = resp.status
                    if status in (401, 403):
                        raise UiCloudAuthError(status)
                    if status == 429:
                        retry_after = _parse_retry_after(resp.headers.get("Retry-After"))
                        if attempt == MAX_ATTEMPTS:
                            raise UiCloudRateLimitError(retry_after)
                        await asyncio.sleep(retry_after or backoff)
                        backoff = min((retry_after or backoff) * 2, MAX_BACKOFF)
                        continue
                    if status >= 500:
                        last_error = UiCloudRequestError(status, "Server error from UniFi Cloud API")
                        continue
                    if status >= 400:
                        raise UiCloudRequestError(status)
                    data: Any = await resp.json(content_type=None)
            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                last_error = UiCloudRequestError(-1, str(err))
                continue
            else:
                if isinstance(data, dict):
                    data.setdefault("httpStatusCode", status)
                    payload = cast(HostsResponse, data)
                else:
                    payload = {
                        "data": [],
                        "httpStatusCode": status,
                    }
                return cast(HostsResponse, payload)

        if last_error is None:
            last_error = UiCloudRequestError(-1, "Failed to fetch UniFi Cloud hosts")
        raise last_error


def _parse_retry_after(value: str | None) -> float | None:
    if value is None:
        return None
    try:
        retry_after = float(value)
    except (TypeError, ValueError):
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        if parsed is None:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        delay = (parsed - now).total_seconds()
        if delay <= 0:
            return 0.0
        return delay
    return max(0.0, retry_after)


__all__ = [
    "HostItem",
    "HostsResponse",
    "ReportedState",
    "UiCloudAuthError",
    "UiCloudClient",
    "UiCloudError",
    "UiCloudRateLimitError",
    "UiCloudRequestError",
    "WanEntry",
]
