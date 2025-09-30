"""Data update coordinator and API client for UniFi Gateway."""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from datetime import datetime
from ipaddress import ip_address, ip_network
from typing import Any, Iterable, Mapping
from urllib.parse import urljoin, urlparse

import aiohttp
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers import aiohttp_client
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    API_BACKOFF_FACTOR,
    API_MAX_ATTEMPTS,
    API_MAX_BACKOFF,
    API_REQUEST_TIMEOUT,
    CONF_HOST,
    CONF_PASSWORD,
    CONF_PORT,
    CONF_RATE_LIMIT,
    CONF_SITE,
    CONF_USERNAME,
    CONF_VERIFY_SSL,
    DEFAULT_PORT,
    DEFAULT_RATE_LIMIT,
    DEFAULT_SITE,
    DEFAULT_VERIFY_SSL,
    VPN_STATUS_SUBSYSTEM,
    WAN_STATUS_SUBSYSTEM,
    as_float,
)

_LOGGER = logging.getLogger(__name__)


class GatewayApiError(Exception):
    """Base exception for API related errors."""


class AuthFailedError(GatewayApiError):
    """Raised when authentication fails."""


class InvalidResponseError(GatewayApiError):
    """Raised when the API returns malformed data."""


@dataclass
class UniFiGatewayMetrics:
    """Structured metrics returned by the coordinator."""

    last_fetch: datetime
    wan: dict[str, Any]
    vpn: dict[str, Any]
    clients: dict[str, Any]
    raw_health: list[dict[str, Any]]
    raw_wlans: list[dict[str, Any]]


class UniFiGatewayApiClient:
    """Async UniFi Gateway API client using aiohttp."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry | Mapping[str, Any],
        *,
        options: Mapping[str, Any] | None = None,
        semaphore: asyncio.Semaphore | None = None,
    ) -> None:
        self._hass = hass

        if isinstance(entry, ConfigEntry):
            data = entry.data
            opts: Mapping[str, Any] = entry.options
        else:
            data = dict(entry)
            opts = options or {}

        self._session = aiohttp_client.async_get_clientsession(
            hass,
            verify_ssl=bool(
                opts.get(
                    CONF_VERIFY_SSL,
                    data.get(CONF_VERIFY_SSL, DEFAULT_VERIFY_SSL),
                )
            ),
        )
        self._base_host, self._port = self._normalize_host(data.get(CONF_HOST, ""))
        self._port = self._port or int(data.get(CONF_PORT, DEFAULT_PORT))
        self._site = data.get(CONF_SITE, DEFAULT_SITE)
        self._auth = aiohttp.BasicAuth(
            data.get(CONF_USERNAME, ""),
            data.get(CONF_PASSWORD, ""),
        )
        limit = int(
            opts.get(
                CONF_RATE_LIMIT,
                data.get(CONF_RATE_LIMIT, DEFAULT_RATE_LIMIT),
            )
        )
        self._semaphore = semaphore or asyncio.Semaphore(max(1, limit))

    @staticmethod
    def _normalize_host(host: str) -> tuple[str, int | None]:
        if not host:
            host = "https://localhost"
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        parsed = urlparse(host)
        scheme = parsed.scheme or "https"
        hostname = parsed.hostname or parsed.netloc or parsed.path or "localhost"
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        base_host = f"{scheme}://{hostname.strip('/')}"
        return base_host, parsed.port

    @property
    def base_url(self) -> str:
        """Return the normalized base URL with port."""

        if self._port is None:
            return self._base_host
        return f"{self._base_host}:{self._port}"

    async def fetch_metrics(self) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Fetch health and wlan configuration payloads."""

        health_task = asyncio.create_task(
            self._request_json(
                "GET",
                f"/proxy/network/api/s/{self._site}/stat/health",
            )
        )
        wlan_task = asyncio.create_task(
            self._request_json(
                "GET",
                f"/proxy/network/api/s/{self._site}/rest/wlanconf",
            )
        )
        health, wlan = await asyncio.gather(health_task, wlan_task)
        return self._ensure_list(health), self._ensure_list(wlan)

    @staticmethod
    def _ensure_list(payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            data = payload.get("data")
            if isinstance(data, list):
                return [item for item in data if isinstance(item, dict)]
        return []

    async def _request_json(self, method: str, path: str) -> Any:
        """Execute an HTTP request with retry semantics."""

        url = urljoin(self.base_url + "/", path.lstrip("/"))
        last_error: Exception | None = None
        for attempt in range(1, API_MAX_ATTEMPTS + 1):
            async with self._semaphore:
                try:
                    response = await self._session.request(
                        method,
                        url,
                        auth=self._auth,
                        timeout=aiohttp.ClientTimeout(total=API_REQUEST_TIMEOUT),
                    )
                except (aiohttp.ClientError, asyncio.TimeoutError) as err:
                    last_error = err
                    _LOGGER.debug("HTTP request error on attempt %s: %s", attempt, err)
                else:
                    async with response:
                        status = response.status
                        if status in (401, 403):
                            raise AuthFailedError("Invalid credentials provided")
                        if status == 204:
                            return {}
                        if status >= 400:
                            body = await response.text()
                            if status == 429 or status >= 500:
                                last_error = GatewayApiError(
                                    f"Server error {status}: {body[:256]}"
                                )
                            else:
                                raise GatewayApiError(
                                    f"Unexpected response {status}: {body[:256]}"
                                )
                        else:
                            try:
                                return await response.json()
                            except aiohttp.ContentTypeError as err:
                                raise InvalidResponseError("Response is not JSON") from err
                            except ValueError as err:
                                raise InvalidResponseError("Failed to decode JSON") from err
            if attempt < API_MAX_ATTEMPTS:
                delay = min(
                    API_MAX_BACKOFF,
                    API_BACKOFF_FACTOR ** attempt + random.uniform(0.1, 0.5),
                )
                await asyncio.sleep(delay)
        if last_error is None:
            raise GatewayApiError("Unable to complete request")
        if isinstance(last_error, GatewayApiError):
            raise last_error
        raise GatewayApiError(str(last_error))


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayMetrics]):
    """Coordinator responsible for collecting UniFi Gateway metrics."""

    def __init__(
        self,
        hass: HomeAssistant,
        entry: ConfigEntry,
        *,
        update_interval: Any | None = None,
    ) -> None:
        super().__init__(
            hass,
            logger=_LOGGER,
            name="UniFi Gateway Refactory",
            update_interval=update_interval,
        )
        self.entry = entry
        self._client = UniFiGatewayApiClient(hass, entry)

    async def _async_update_data(self) -> UniFiGatewayMetrics:
        try:
            health, wlan = await self._client.fetch_metrics()
        except AuthFailedError as err:
            raise ConfigEntryAuthFailed from err
        except InvalidResponseError as err:
            raise UpdateFailed(str(err)) from err
        except GatewayApiError as err:
            raise UpdateFailed(str(err)) from err

        metrics = self._build_metrics(health, wlan)
        return metrics

    def _build_metrics(
        self,
        health_data: list[dict[str, Any]],
        wlan_data: list[dict[str, Any]],
    ) -> UniFiGatewayMetrics:
        """Transform raw payloads into structured metrics."""

        wan_info = self._extract_subsystem(health_data, WAN_STATUS_SUBSYSTEM)
        vpn_info = self._extract_subsystem(health_data, VPN_STATUS_SUBSYSTEM)

        wan_metrics = {
            "status": (wan_info.get("status") or "unknown").lower(),
            "latency_ms": as_float(wan_info.get("latency")),
            "packet_loss_pct": as_float(wan_info.get("packet_loss")),
            "throughput_mbps": self._calculate_throughput(wan_info),
            "ipv6": self._extract_ipv6_metrics(wan_info, health_data),
        }

        vpn_metrics = {
            "active_tunnels": self._safe_int(vpn_info.get("num_active")),
            "clients": self._safe_list(vpn_info.get("clients")),
        }

        clients_metrics = self._aggregate_clients(health_data, wlan_data)

        return UniFiGatewayMetrics(
            last_fetch=datetime.utcnow(),
            wan=wan_metrics,
            vpn=vpn_metrics,
            clients=clients_metrics,
            raw_health=health_data,
            raw_wlans=wlan_data,
        )

    def _extract_ipv6_metrics(
        self,
        wan_info: dict[str, Any],
        health_data: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Build normalized IPv6 WAN metrics."""

        candidates = self._gather_ipv6_candidates(wan_info)
        # Include nested WAN details that may live in sibling dicts.
        for item in health_data:
            if not isinstance(item, dict):
                continue
            if item is wan_info:
                continue
            if item.get("subsystem") == WAN_STATUS_SUBSYSTEM:
                other = self._gather_ipv6_candidates(item)
                candidates["addresses"].extend(
                    value
                    for value in other["addresses"]
                    if value not in candidates["addresses"]
                )
                candidates["link_local"].extend(
                    value
                    for value in other["link_local"]
                    if value not in candidates["link_local"]
                )
                candidates["prefix"].extend(
                    value
                    for value in other["prefix"]
                    if value not in candidates["prefix"]
                )
                for length in other["prefix_length"]:
                    if length not in candidates["prefix_length"]:
                        candidates["prefix_length"].append(length)

        global_ipv6 = self._select_global_ipv6(candidates["addresses"])
        link_local_ipv6 = self._select_link_local(candidates["link_local"])
        delegated_prefix = self._select_delegated_prefix(
            candidates["prefix"], candidates["prefix_length"]
        )

        if global_ipv6:
            source = "global"
            display_value: str | None = global_ipv6
        elif delegated_prefix:
            source = "pd"
            display_value = delegated_prefix
        else:
            source = "unknown"
            display_value = "unknown"

        return {
            "display_value": display_value,
            "wan_ipv6_global": global_ipv6,
            "wan_ipv6_link_local": link_local_ipv6,
            "delegated_prefix": delegated_prefix,
            "ipv6_source": source,
            "has_ipv6_connectivity": source in {"global", "pd"},
        }

    def _gather_ipv6_candidates(
        self, payload: dict[str, Any]
    ) -> dict[str, list[Any]]:
        """Collect potential IPv6 fields from payload."""

        addresses: list[str] = []
        link_local: list[str] = []
        prefixes: list[str] = []
        prefix_lengths: list[int] = []

        def _walk(obj: Any, parent_key: str | None = None) -> None:
            if isinstance(obj, dict):
                for key, value in obj.items():
                    _walk(value, key)
                return
            if isinstance(obj, list):
                for item in obj:
                    _walk(item, parent_key)
                return
            if not isinstance(obj, str):
                if parent_key in {"pd_length", "pd_prefixlen", "prefixlen", "ipv6_prefixlen"}:
                    length = self._safe_int(obj)
                    if length and length not in prefix_lengths:
                        prefix_lengths.append(length)
                return

            value = obj.strip()
            if not value:
                return

            key = (parent_key or "").lower()
            if key in {
                "ipv6",
                "ip6",
                "wan_ipv6",
                "wan_ip6",
                "wan_ip",
                "wan_ipaddr",
                "wan_addr",
                "addr",
                "address",
            }:
                if value not in addresses:
                    addresses.append(value)
            elif key in {
                "ipv6_link_local",
                "link_local",
                "linklocal",
                "linklocal_ip",
                "linklocal_ipv6",
                "link_local_ipv6",
            }:
                if value not in link_local:
                    link_local.append(value)
            elif key in {
                "pd_prefix",
                "ipv6_pd_prefix",
                "delegated_prefix",
                "prefix",
            }:
                if value not in prefixes:
                    prefixes.append(value)
            elif key in {"pd_length", "pd_prefixlen", "prefixlen", "ipv6_prefixlen"}:
                length = self._safe_int(value)
                if length and length not in prefix_lengths:
                    prefix_lengths.append(length)

        _walk(payload)
        return {
            "addresses": addresses,
            "link_local": link_local,
            "prefix": prefixes,
            "prefix_length": prefix_lengths,
        }

    @staticmethod
    def _sanitize_ipv6(value: str) -> str | None:
        cleaned = value.split("%", 1)[0].strip()
        if not cleaned:
            return None
        try:
            ip_obj = ip_address(cleaned)
        except ValueError:
            return None
        if ip_obj.version != 6:
            return None
        return str(ip_obj)

    def _select_global_ipv6(self, candidates: Iterable[str]) -> str | None:
        for candidate in candidates:
            sanitized = self._sanitize_ipv6(candidate)
            if not sanitized:
                continue
            ip_obj = ip_address(sanitized)
            if ip_obj.version == 6 and ip_obj.is_global:
                return str(ip_obj)
        return None

    def _select_link_local(self, candidates: Iterable[str]) -> str | None:
        for candidate in candidates:
            sanitized = self._sanitize_ipv6(candidate)
            if not sanitized:
                continue
            ip_obj = ip_address(sanitized)
            if ip_obj.version == 6 and ip_obj.is_link_local:
                return str(ip_obj)
        return None

    def _select_delegated_prefix(
        self, prefixes: Iterable[str], prefix_lengths: Iterable[int]
    ) -> str | None:
        # Try explicit prefixes with length.
        for prefix in prefixes:
            normalized = prefix.strip()
            if not normalized:
                continue
            attempt_values: list[str] = []
            if "/" not in normalized:
                for length in prefix_lengths:
                    attempt_values.append(f"{normalized}/{length}")
            attempt_values.append(normalized)
            for value in attempt_values:
                try:
                    network = ip_network(value, strict=False)
                except ValueError:
                    continue
                if network.version == 6 and network.prefixlen:
                    return str(network)

        # As a last resort combine prefix and first prefix length.
        for prefix in prefixes:
            cleaned = prefix.strip()
            if not cleaned or "/" in cleaned:
                continue
            for length in prefix_lengths:
                try:
                    network = ip_network(f"{cleaned}/{length}", strict=False)
                except ValueError:
                    continue
                if network.version == 6:
                    return str(network)
        return None

    @staticmethod
    def _extract_subsystem(
        data: Iterable[dict[str, Any]], subsystem: str
    ) -> dict[str, Any]:
        for item in data:
            if isinstance(item, dict) and item.get("subsystem") == subsystem:
                return item
        return {}

    @staticmethod
    def _safe_int(value: Any) -> int:
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            stripped = value.strip()
            if stripped.isdigit():
                return int(stripped)
        return 0

    @staticmethod
    def _safe_list(value: Any) -> list[Any]:
        if isinstance(value, list):
            return value
        return []

    def _aggregate_clients(
        self,
        health_data: list[dict[str, Any]],
        wlan_data: list[dict[str, Any]],
    ) -> dict[str, Any]:
        total_clients = 0
        wired_clients = 0
        wireless_clients = 0

        for item in health_data:
            if not isinstance(item, dict):
                continue
            total_clients = max(total_clients, self._safe_int(item.get("num_clients")))
            wired_clients = max(wired_clients, self._safe_int(item.get("num_sta")))

        for wlan in wlan_data:
            if not isinstance(wlan, dict):
                continue
            wireless_clients += self._safe_int(wlan.get("num_sta"))

        total_clients = max(total_clients, wired_clients + wireless_clients)

        return {
            "total": total_clients,
            "wired": wired_clients,
            "wireless": wireless_clients,
        }

    @staticmethod
    def _calculate_throughput(data: dict[str, Any]) -> float | None:
        downstream = as_float(data.get("wan_down"))
        upstream = as_float(data.get("wan_up"))
        if downstream is None and upstream is None:
            return None
        downstream = downstream or 0
        upstream = upstream or 0
        return round((downstream + upstream) / 2, 3)


__all__ = [
    "AuthFailedError",
    "GatewayApiError",
    "InvalidResponseError",
    "UniFiGatewayApiClient",
    "UniFiGatewayDataUpdateCoordinator",
    "UniFiGatewayMetrics",
]
