"""Client for the UniFi UI Cloud API used to retrieve WAN IPv6 addresses."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

import aiohttp


class UiCloudError(Exception):
    """Base exception for UI Cloud API failures."""


class UiCloudAuthError(UiCloudError):
    """Raised when authentication with the UI Cloud API fails."""

    def __init__(self, status: int) -> None:
        super().__init__(f"UI Cloud API authentication failed (status={status})")
        self.status = status


class UiCloudRateLimitError(UiCloudError):
    """Raised when the UI Cloud API responds with HTTP 429."""

    def __init__(self, retry_after: float | None) -> None:
        message = "UI Cloud API rate limited"
        if retry_after is not None:
            message = f"{message}; retry in {retry_after:.1f}s"
        super().__init__(message)
        self.retry_after = retry_after


class UiCloudRequestError(UiCloudError):
    """Raised when the UI Cloud API request ultimately fails."""


@dataclass(slots=True)
class UiCloudClient:
    """Thin asynchronous client for the UniFi UI Cloud API."""

    session: aiohttp.ClientSession
    api_key: str
    base_url: str = "https://api.ui.com"
    _base: str = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._base = self.base_url.rstrip("/")

    async def fetch_hosts(self) -> Dict[str, Any]:
        """Return the raw hosts payload from the UI Cloud API."""

        url = f"{self._base}/v1/hosts"
        headers = {"Accept": "application/json", "X-API-Key": self.api_key}
        timeouts = aiohttp.ClientTimeout(total=10)
        backoffs = (0.0, 0.5, 1.0, 2.0)
        last_error: UiCloudRequestError | None = None

        for attempt, delay in enumerate(backoffs, start=1):
            if delay:
                await asyncio.sleep(delay)
            try:
                resp = await self.session.get(url, headers=headers, timeout=timeouts)
            except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                last_error = UiCloudRequestError("Error communicating with UI Cloud API")
                last_error.__cause__ = err
                continue

            async with resp:
                status = resp.status
                if status == 429:
                    retry_after = self._parse_retry_after(resp.headers.get("Retry-After"))
                    if attempt == len(backoffs):
                        raise UiCloudRateLimitError(retry_after)
                    await asyncio.sleep(retry_after if retry_after is not None else 5.0)
                    continue
                if status in (401, 403):
                    raise UiCloudAuthError(status)
                if 500 <= status:
                    last_error = UiCloudRequestError(
                        f"UI Cloud API server error (status={status})"
                    )
                    continue
                if status >= 400:
                    raise UiCloudRequestError(
                        f"Unexpected UI Cloud API response (status={status})"
                    )

                try:
                    return await resp.json()
                except aiohttp.ContentTypeError as err:
                    last_error = UiCloudRequestError("Invalid JSON response")
                    last_error.__cause__ = err
                    continue

        if last_error is None:
            last_error = UiCloudRequestError("Failed to fetch UI Cloud hosts")
        raise last_error

    @staticmethod
    def _parse_retry_after(value: Optional[str]) -> Optional[float]:
        if value is None:
            return None
        try:
            parsed = float(value)
        except (TypeError, ValueError):
            return None
        return max(0.0, parsed)

    async def fetch_ipv6_for_mac(self, target_mac: str) -> Optional[str]:
        """Return the IPv6 address for the provided WAN MAC."""

        normalized_mac = _normalize_mac(target_mac)
        if not normalized_mac:
            return None

        payload = await self.fetch_hosts()
        for console in payload.get("data", []):
            reported = console.get("reportedState") or {}
            wans = reported.get("wans") or []
            for wan in wans:
                if not isinstance(wan, dict):
                    continue
                mac = _normalize_mac(wan.get("mac"))
                if not mac or mac != normalized_mac:
                    continue
                if not _wan_candidate_enabled(wan):
                    continue
                ipv6 = wan.get("ipv6")
                if isinstance(ipv6, str) and ipv6.strip():
                    return ipv6.strip()
            # If the console doesn't contain the target MAC continue searching.
        return None


def _wan_candidate_enabled(wan: Dict[str, Any]) -> bool:
    if not wan.get("enabled", True):
        return False
    wan_type = str(wan.get("type") or "").upper()
    if wan_type and wan_type not in {"WAN", "WAN1", "PRIMARY"}:
        return False
    return True


def _normalize_mac(value: Any) -> Optional[str]:
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        value = str(value)
    hex_chars = [char for char in value if char.isalnum()]
    cleaned = "".join(hex_chars)
    if len(cleaned) != 12:
        return None
    try:
        int(cleaned, 16)
    except ValueError:
        return None
    pairs = [cleaned[i:i + 2] for i in range(0, 12, 2)]
    return ":".join(pairs).lower()


__all__ = [
    "UiCloudClient",
    "UiCloudError",
    "UiCloudAuthError",
    "UiCloudRateLimitError",
    "UiCloudRequestError",
]
