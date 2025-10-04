from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import re
import time
from typing import Any, Dict, List, Mapping, Optional

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .cloud_client import (
    HostItem,
    UiCloudAuthError,
    UiCloudClient,
    UiCloudError,
    UiCloudRateLimitError,
    UiCloudRequestError,
)
from .const import ATTR_GW_MAC, ATTR_REASON, CONF_GW_MAC, DOMAIN
from .unifi_client import APIError, ConnectivityError, UniFiOSClient
from .utils import normalize_mac


_LOGGER = logging.getLogger(__name__)


_LOCAL_IPV6_KEYS: tuple[str, ...] = (
    "last_ipv6",
    "ipv6",
    "wan_ipv6",
    "internet_ipv6",
    "public_ipv6",
    "external_ipv6",
    "ip6",
    "ip_v6",
    "wan_ip6",
    "wan_ipv6_address",
    "wan_ipv6_ip",
    "ipv6_address",
    "global_ipv6",
    "public_ip6",
)


@dataclass(slots=True)
class UniFiGatewayData:
    """Container describing the data returned by the coordinator."""

    controller: dict[str, Any]
    health: list[dict[str, Any]] = field(default_factory=list)
    health_by_subsystem: dict[str, dict[str, Any]] = field(default_factory=dict)
    wan_health: list[dict[str, Any]] = field(default_factory=list)
    alerts: list[dict[str, Any]] = field(default_factory=list)
    devices: list[dict[str, Any]] = field(default_factory=list)
    wan_links: list[dict[str, Any]] = field(default_factory=list)
    networks: list[dict[str, Any]] = field(default_factory=list)
    lan_networks: list[dict[str, Any]] = field(default_factory=list)
    network_map: dict[str, dict[str, Any]] = field(default_factory=dict)
    wlans: list[dict[str, Any]] = field(default_factory=list)
    clients: list[dict[str, Any]] = field(default_factory=list)
    speedtest: Optional[dict[str, Any]] = None
    wan: dict[str, Any] = field(default_factory=dict)
    wan_attrs: dict[str, Any] = field(default_factory=dict)
    wan_ipv6: str | None = None

    def __getitem__(self, key: str) -> Any:
        if key == "wan":
            return self.wan
        if key == "wan_attrs":
            return self.wan_attrs
        if key == "wan_ipv6":
            return self.wan_ipv6
        raise KeyError(key)


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: UniFiOSClient,
        *,
        speedtest_interval: int | None = None,
        ui_cloud_client: UiCloudClient | None = None,
        config_entry: ConfigEntry | None = None,
        stored_gw_mac: str | None = None,
    ) -> None:
        self._client = client
        self._ui_cloud_client = ui_cloud_client
        self._config_entry = config_entry
        self._stored_gw_mac = normalize_mac(stored_gw_mac)
        self._last_gw_mac = self._stored_gw_mac
        self._wan_ipv6_cache: dict[str, tuple[float, str]] = {}
        self._cloud_cache_ttl = 300.0
        self._cloud_backoff_until = 0.0
        self._cloud_retry_attempts = 0
        self._cloud_last_fetch = 0.0
        self._cloud_fetch_interval = 60.0
        self._warned_missing_gw_mac = False
        self._speedtest_interval = self._sanitize_speedtest_interval(speedtest_interval)
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=15),
        )
        if self._ui_cloud_client is not None:
            _LOGGER.info("Using UniFi Cloud API for WAN IPv6 lookups")

    @staticmethod
    def _sanitize_speedtest_interval(value: int | None) -> int:
        try:
            interval = int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0
        return max(0, interval)

    @staticmethod
    def _speedtest_last_timestamp(record: Optional[Dict[str, Any]]) -> Optional[float]:
        if not isinstance(record, dict):
            return None
        for key in ("rundate", "timestamp", "time", "date", "start_time"):
            if key not in record:
                continue
            value = record.get(key)
            if value in (None, ""):
                continue
            if isinstance(value, (int, float)):
                number = float(value)
                if number > 1e11:
                    number /= 1000.0
                if number > 0:
                    return number
                continue
            dt_value: Optional[datetime] = None
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    continue
                try:
                    number = float(text)
                except (TypeError, ValueError):
                    dt_value = dt_util.parse_datetime(text)
                else:
                    if number > 1e11:
                        number /= 1000.0
                    if number > 0:
                        return number
                    continue
            elif isinstance(value, datetime):
                dt_value = value
            if dt_value is None:
                continue
            dt_utc = dt_util.as_utc(dt_value)
            return dt_utc.timestamp()
        return None

    @staticmethod
    def _build_health_lookup(records: List[Dict[str, Any]]) -> dict[str, Dict[str, Any]]:
        lookup: dict[str, Dict[str, Any]] = {}
        keys = ("id", "_id", "ifname", "name", "wan_name", "display_name")
        for record in records:
            if not isinstance(record, dict):
                continue
            for key in keys:
                if key not in record:
                    continue
                for identifier in UniFiGatewayDataUpdateCoordinator._normalized_identifiers(
                    record.get(key)
                ):
                    if identifier not in lookup:
                        lookup[identifier] = record
        return lookup

    def _resolve_wan_mac(
        self,
        link: Mapping[str, Any],
        health_lookup: dict[str, Dict[str, Any]],
    ) -> tuple[Optional[str], Optional[Dict[str, Any]]]:
        identifiers = self._collect_link_identifiers(link)
        health_record: Optional[Dict[str, Any]] = None
        for identifier in identifiers:
            if identifier in health_lookup:
                health_record = health_lookup[identifier]
                break

        mac = self._extract_mac_from_mapping(link)
        if mac:
            if health_record is None:
                for identifier in identifiers:
                    if identifier in health_lookup:
                        health_record = health_lookup[identifier]
                        break
            return mac, health_record

        if health_record is not None:
            mac = self._extract_mac_from_mapping(health_record)
            if mac:
                return mac, health_record

        return None, health_record

    @staticmethod
    def _select_primary_wan_link(
        links: List[Dict[str, Any]]
    ) -> Optional[Dict[str, Any]]:
        if not links:
            return None
        preferred: Optional[Dict[str, Any]] = None
        for link in links:
            if not isinstance(link, dict):
                continue
            identifier = str(
                link.get("id")
                or link.get("_id")
                or link.get("ifname")
                or link.get("interface")
                or ""
            ).strip().lower()
            name = str(link.get("name") or "").strip().lower()
            if identifier in {"wan", "wan1", "wan_1"}:
                return link
            if name in {"wan", "wan 1", "wan1"}:
                return link
            if preferred is None:
                preferred = link
        return preferred or next(
            (link for link in links if isinstance(link, dict)),
            None,
        )

    def _infer_gateway_identity(
        self,
        data: UniFiGatewayData,
        primary_link: Optional[Mapping[str, Any]],
    ) -> tuple[Optional[str], Optional[str]]:
        hostname = self._clean_text(
            primary_link.get("hostname") if primary_link else None
        )
        if not hostname and primary_link is not None:
            hostname = self._clean_text(primary_link.get("name"))
        ip_address = None
        if primary_link is not None:
            for key in ("ip", "last_ip", "last_ipv4", "wan_ip", "ipv4"):
                ip_address = self._clean_text(primary_link.get(key))
                if ip_address:
                    break

        for record in data.wan_health:
            if not isinstance(record, Mapping):
                continue
            if not hostname:
                hostname = self._clean_text(record.get("hostname") or record.get("name"))
            if not ip_address:
                for key in (
                    "wan_ip",
                    "ip",
                    "wan_ipaddr",
                    "wan_ip_address",
                    "last_ip",
                    "gateway_ip",
                ):
                    ip_address = self._clean_text(record.get(key))
                    if ip_address:
                        break
            if hostname and ip_address:
                break

        if not hostname or not ip_address:
            for device in data.devices:
                if not isinstance(device, Mapping):
                    continue
                if not hostname:
                    hostname = self._clean_text(
                        device.get("hostname") or device.get("name")
                    )
                if not ip_address:
                    ip_address = self._clean_text(device.get("ip") or device.get("ipv4"))
                if hostname and ip_address:
                    break

        return hostname, ip_address

    async def _async_persist_gw_mac(self, mac: Optional[str]) -> None:
        normalized = normalize_mac(mac)
        if normalized is None:
            return
        self._last_gw_mac = normalized
        if normalized == self._stored_gw_mac:
            return
        if self._config_entry is None:
            self._stored_gw_mac = normalized
            return
        options = dict(self._config_entry.options)
        existing = normalize_mac(options.get(CONF_GW_MAC))
        if existing == normalized:
            self._stored_gw_mac = normalized
            return
        options[CONF_GW_MAC] = normalized
        await self.hass.config_entries.async_update_entry(
            self._config_entry,
            options=options,
        )
        updated = self.hass.config_entries.async_get_entry(self._config_entry.entry_id)
        if updated is not None:
            self._config_entry = updated
        self._stored_gw_mac = normalized

    async def _async_refresh_wan_cloud_state(self, data: UniFiGatewayData) -> None:
        primary_link = self._select_primary_wan_link(data.wan_links)
        health_lookup = self._build_health_lookup(data.wan_health)
        gw_mac: Optional[str] = None
        health_record: Optional[Dict[str, Any]] = None
        if primary_link:
            gw_mac, health_record = self._resolve_wan_mac(primary_link, health_lookup)
            if gw_mac:
                primary_link[ATTR_GW_MAC] = gw_mac
        if not gw_mac:
            gw_mac = self._stored_gw_mac
            if primary_link is not None and gw_mac:
                primary_link.setdefault(ATTR_GW_MAC, gw_mac)

        data.wan[ATTR_GW_MAC] = gw_mac
        if gw_mac:
            await self._async_persist_gw_mac(gw_mac)
            self._warned_missing_gw_mac = False

        hostname, ip_address = self._infer_gateway_identity(data, primary_link)
        try:
            hardware_mac = normalize_mac(self._client.get_gateway_mac())
        except Exception:  # pragma: no cover - guard against client failures
            hardware_mac = None

        await self._async_update_wan_ipv6_from_cloud(
            data,
            primary_link,
            health_record,
            gw_mac,
            hardware_mac,
            hostname,
            ip_address,
        )

    async def _async_update_wan_ipv6_from_cloud(
        self,
        data: UniFiGatewayData,
        primary_link: Optional[Dict[str, Any]],
        health_record: Optional[Dict[str, Any]],
        gw_mac: Optional[str],
        hardware_mac: Optional[str],
        hostname: Optional[str],
        ip_address: Optional[str],
    ) -> None:
        attrs = data.wan_attrs
        attrs.pop("error", None)
        attrs.pop(ATTR_REASON, None)
        attrs["available"] = True

        normalized_mac = normalize_mac(gw_mac)
        if normalized_mac:
            data.wan[ATTR_GW_MAC] = normalized_mac
            if primary_link is not None:
                primary_link[ATTR_GW_MAC] = normalized_mac
        else:
            data.wan[ATTR_GW_MAC] = None
            if primary_link is not None:
                primary_link.setdefault(ATTR_GW_MAC, None)

        now = time.monotonic()
        cached_entry = (
            self._wan_ipv6_cache.get(normalized_mac)
            if normalized_mac is not None
            else None
        )
        if cached_entry and (now - cached_entry[0]) <= self._cloud_cache_ttl:
            data.wan_ipv6 = cached_entry[1]
        else:
            data.wan_ipv6 = None

        if self._ui_cloud_client is None or not self._ui_cloud_client.api_key:
            if not self._apply_local_ipv6_fallback(
                data,
                primary_link,
                health_record,
                attrs,
            ):
                attrs[ATTR_REASON] = "missing_api_key"
            return

        if normalized_mac is None:
            attrs[ATTR_REASON] = "missing_gw_mac"
            if not self._warned_missing_gw_mac:
                _LOGGER.warning(
                    (
                        "WAN interface MAC address is unknown; set the gateway MAC in "
                        "integration options or ensure the controller exposes it"
                    )
                )
                self._warned_missing_gw_mac = True
            self._apply_local_ipv6_fallback(
                data,
                primary_link,
                health_record,
                attrs,
            )
            return

        if cached_entry and (now - self._cloud_last_fetch) < self._cloud_fetch_interval:
            data.wan_ipv6 = cached_entry[1]
            if primary_link is not None:
                primary_link.setdefault("last_ipv6", cached_entry[1])
                primary_link.setdefault("wan_ipv6", cached_entry[1])
            if health_record is not None:
                health_record.setdefault("last_ipv6", cached_entry[1])
                health_record.setdefault("wan_ipv6", cached_entry[1])
            return

        if self._cloud_backoff_until and now < self._cloud_backoff_until:
            if cached_entry:
                data.wan_ipv6 = cached_entry[1]
            else:
                attrs[ATTR_REASON] = "cloud_backoff_active"
                attrs["available"] = False
                if self._apply_local_ipv6_fallback(
                    data,
                    primary_link,
                    health_record,
                    attrs,
                ):
                    attrs[ATTR_REASON] = "cloud_backoff_active"
            return

        try:
            hosts = await self._ui_cloud_client.async_get_hosts()
        except UiCloudAuthError as err:
            attrs[ATTR_REASON] = "invalid_api_key"
            attrs["available"] = False
            attrs["error"] = str(err)
            self._apply_local_ipv6_fallback(
                data,
                primary_link,
                health_record,
                attrs,
            )
            return
        except UiCloudRateLimitError as err:
            delay = err.retry_after if err.retry_after is not None else 5.0
            self._cloud_backoff_until = now + min(delay, 30.0)
            self._cloud_retry_attempts = min(self._cloud_retry_attempts + 1, 6)
            attrs[ATTR_REASON] = "cloud_rate_limited"
            if cached_entry:
                data.wan_ipv6 = cached_entry[1]
                if primary_link is not None:
                    primary_link.setdefault("last_ipv6", cached_entry[1])
                    primary_link.setdefault("wan_ipv6", cached_entry[1])
                if health_record is not None:
                    health_record.setdefault("last_ipv6", cached_entry[1])
                    health_record.setdefault("wan_ipv6", cached_entry[1])
            else:
                attrs["available"] = False
                if self._apply_local_ipv6_fallback(
                    data,
                    primary_link,
                    health_record,
                    attrs,
                ):
                    attrs[ATTR_REASON] = "cloud_rate_limited"
            return
        except (UiCloudRequestError, UiCloudError) as err:
            self._cloud_retry_attempts = min(self._cloud_retry_attempts + 1, 6)
            delay = min(30.0, 0.5 * (2 ** self._cloud_retry_attempts))
            self._cloud_backoff_until = now + delay
            attrs[ATTR_REASON] = "cloud_fetch_error"
            attrs["error"] = str(err)
            if cached_entry:
                data.wan_ipv6 = cached_entry[1]
                if primary_link is not None:
                    primary_link.setdefault("last_ipv6", cached_entry[1])
                    primary_link.setdefault("wan_ipv6", cached_entry[1])
                if health_record is not None:
                    health_record.setdefault("last_ipv6", cached_entry[1])
                    health_record.setdefault("wan_ipv6", cached_entry[1])
            else:
                attrs["available"] = False
                if self._apply_local_ipv6_fallback(
                    data,
                    primary_link,
                    health_record,
                    attrs,
                ):
                    attrs[ATTR_REASON] = "cloud_fetch_error"
            return

        self._cloud_last_fetch = time.monotonic()
        self._cloud_backoff_until = 0.0
        self._cloud_retry_attempts = 0

        status = hosts.get("httpStatusCode")
        if status != 200:
            attrs[ATTR_REASON] = f"cloud_status_{status}"
            attrs["available"] = False
            if self._apply_local_ipv6_fallback(
                data,
                primary_link,
                health_record,
                attrs,
            ):
                attrs[ATTR_REASON] = f"cloud_status_{status}"
            return

        data_list = hosts.get("data") or []
        if not isinstance(data_list, list):
            data_list = []

        ipv6 = self._extract_ipv6_for_gw_mac(
            data_list,
            normalized_mac,
            hardware_mac,
            hostname,
            ip_address,
        )

        if ipv6:
            data.wan_ipv6 = ipv6
            attrs["last_ipv6"] = ipv6
            attrs["source"] = "cloud"
            attrs.pop(ATTR_REASON, None)
            if primary_link is not None:
                primary_link["last_ipv6"] = ipv6
                primary_link.setdefault("wan_ipv6", ipv6)
            if health_record is not None:
                health_record["last_ipv6"] = ipv6
                health_record.setdefault("wan_ipv6", ipv6)
            self._wan_ipv6_cache[normalized_mac] = (self._cloud_last_fetch, ipv6)
        else:
            data.wan_ipv6 = None
            attrs[ATTR_REASON] = "no_ipv6_for_gw"
            self._wan_ipv6_cache.pop(normalized_mac, None)

    def _apply_local_ipv6_fallback(
        self,
        data: UniFiGatewayData,
        primary_link: Optional[Dict[str, Any]],
        health_record: Optional[Dict[str, Any]],
        attrs: Dict[str, Any],
    ) -> bool:
        ipv6 = self._extract_local_ipv6(primary_link, health_record)
        if not ipv6:
            return False
        data.wan_ipv6 = ipv6
        attrs["last_ipv6"] = ipv6
        attrs["source"] = "controller"
        attrs["available"] = True
        if primary_link is not None:
            primary_link.setdefault("last_ipv6", ipv6)
            primary_link.setdefault("wan_ipv6", ipv6)
        if health_record is not None:
            health_record.setdefault("last_ipv6", ipv6)
            health_record.setdefault("wan_ipv6", ipv6)
        return True

    @staticmethod
    def _extract_local_ipv6(
        primary_link: Optional[Mapping[str, Any]],
        health_record: Optional[Mapping[str, Any]],
    ) -> Optional[str]:
        for candidate in (
            primary_link,
            health_record,
        ):
            value = UniFiGatewayDataUpdateCoordinator._extract_ipv6_from_mapping(
                candidate
            )
            if value:
                return value
        return None

    @staticmethod
    def _extract_ipv6_from_mapping(
        mapping: Optional[Mapping[str, Any]]
    ) -> Optional[str]:
        if not isinstance(mapping, Mapping):
            return None

        for key in _LOCAL_IPV6_KEYS:
            if key not in mapping:
                continue
            candidate_value = mapping.get(key)
            if isinstance(candidate_value, str):
                cleaned = candidate_value.strip()
                if cleaned:
                    return cleaned
            elif isinstance(candidate_value, (list, tuple)):
                for item in candidate_value:
                    if isinstance(item, str):
                        cleaned = item.strip()
                        if cleaned:
                            return cleaned
                    elif isinstance(item, Mapping):
                        nested = UniFiGatewayDataUpdateCoordinator._extract_ipv6_from_mapping(
                            item
                        )
                        if nested:
                            return nested
            elif isinstance(candidate_value, Mapping):
                nested = UniFiGatewayDataUpdateCoordinator._extract_ipv6_from_mapping(
                    candidate_value
                )
                if nested:
                    return nested

        return None

    @staticmethod
    def _extract_ipv6_for_gw_mac(
        items: List[HostItem],
        gw_mac: Optional[str],
        hardware_mac: Optional[str],
        hostname: Optional[str],
        ip_address: Optional[str],
    ) -> Optional[str]:
        if not items:
            return None

        target_mac = normalize_mac(gw_mac)
        hardware_mac_norm = normalize_mac(hardware_mac)
        hostname_norm = (hostname or "").strip()
        ip_norm = (ip_address or "").strip()

        candidates: List[Mapping[str, Any]] = [
            item for item in items if isinstance(item, Mapping)
        ]
        if not candidates:
            return None

        narrowed = candidates
        if hardware_mac_norm:
            hw_matches = [
                item
                for item in candidates
                if normalize_mac((item.get("hardware") or {}).get("mac"))
                == hardware_mac_norm
            ]
            if hw_matches:
                narrowed = hw_matches

        if narrowed is candidates and hostname_norm:
            host_matches: List[Mapping[str, Any]] = []
            for item in candidates:
                reported = item.get("reportedState") or {}
                reported_hostname = (reported.get("hostname") or "").strip()
                if reported_hostname != hostname_norm:
                    continue
                if ip_norm:
                    reported_ip = UniFiGatewayDataUpdateCoordinator._extract_reported_ipv4(
                        item
                    )
                    if reported_ip and reported_ip != ip_norm:
                        continue
                host_matches.append(item)
            if host_matches:
                narrowed = host_matches

        def _ipv6_from_item(item: Mapping[str, Any]) -> Optional[str]:
            reported = item.get("reportedState") or {}
            wans = reported.get("wans") or []
            for wan in wans:
                if not isinstance(wan, Mapping):
                    continue
                mac = normalize_mac(wan.get("mac"))
                if target_mac and mac != target_mac:
                    continue
                ipv6 = wan.get("ipv6")
                if isinstance(ipv6, str):
                    ipv6_clean = ipv6.strip()
                    if ipv6_clean:
                        return ipv6_clean
            return None

        if target_mac:
            for item in narrowed:
                ipv6_value = _ipv6_from_item(item)
                if ipv6_value:
                    return ipv6_value
            if narrowed is not candidates:
                for item in candidates:
                    ipv6_value = _ipv6_from_item(item)
                    if ipv6_value:
                        return ipv6_value
        else:
            for item in narrowed:
                ipv6_value = _ipv6_from_item(item)
                if ipv6_value:
                    return ipv6_value
        return None

    @staticmethod
    def _extract_reported_ipv4(item: Mapping[str, Any]) -> Optional[str]:
        reported = item.get("reportedState") or {}
        candidate = reported.get("ip")
        if isinstance(candidate, str) and candidate.strip():
            return candidate.strip()
        wans = reported.get("wans") or []
        for wan in wans:
            if not isinstance(wan, Mapping):
                continue
            ipv4 = wan.get("ipv4")
            if isinstance(ipv4, str) and ipv4.strip():
                return ipv4.strip()
        return None

    @staticmethod
    def _collect_link_identifiers(link: Mapping[str, Any]) -> set[str]:
        identifiers: set[str] = set()
        keys = (
            "id",
            "_id",
            "ifname",
            "interface",
            "wan_port",
            "port",
            "display_name",
            "wan_name",
            "name",
        )
        for key in keys:
            if key not in link:
                continue
            identifiers.update(
                UniFiGatewayDataUpdateCoordinator._normalized_identifiers(
                    link.get(key)
                )
            )
        return identifiers

    @staticmethod
    def _normalized_identifiers(value: Any) -> set[str]:
        results: set[str] = set()
        if value in (None, ""):
            return results
        if isinstance(value, str):
            text = value.strip().lower()
        else:
            text = str(value).strip().lower()
        if not text:
            return results
        results.add(text)
        collapsed = text.replace(" ", "")
        if collapsed:
            results.add(collapsed)
        return results

    @staticmethod
    def _extract_mac_from_mapping(mapping: Mapping[str, Any]) -> Optional[str]:
        mac_keys = (
            "mac",
            "wan_mac",
            "gateway_mac",
            "gw_mac",
            "device_mac",
            "port_mac",
            "if_mac",
            "wan_if_mac",
            "remote_mac",
            "primary_mac",
            "mac_address",
            "wan_macaddr",
            "uplink_mac",
        )
        for key in mac_keys:
            normalized = UniFiGatewayDataUpdateCoordinator._normalize_mac(
                mapping.get(key)
            )
            if normalized:
                return normalized
        uplink = mapping.get("uplink")
        if isinstance(uplink, Mapping):
            nested = UniFiGatewayDataUpdateCoordinator._extract_mac_from_mapping(uplink)
            if nested:
                return nested
        return None

    @staticmethod
    def _clean_text(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _normalize_mac(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if not isinstance(value, str):
            value = str(value)
        cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
        if len(cleaned) != 12:
            return None
        try:
            int(cleaned, 16)
        except ValueError:
            return None
        parts = [cleaned[i:i + 2] for i in range(0, 12, 2)]
        return ":".join(parts).lower()

    @staticmethod
    def _wan_candidate_enabled(wan: Mapping[str, Any]) -> bool:
        if wan.get("enabled") is False:
            return False
        wan_type = str(wan.get("type") or "").strip().upper()
        if wan_type and wan_type not in {"WAN", "WAN1", "PRIMARY"}:
            return False
        return True

    async def _async_update_data(self) -> UniFiGatewayData:
        try:
            data = await self.hass.async_add_executor_job(
                self._fetch_data,
            )
        except (ConnectivityError, APIError) as err:
            raise UpdateFailed(str(err)) from err

        if data:
            try:
                await self._async_refresh_wan_cloud_state(data)
            except Exception as err:  # pragma: no cover - defensive logging
                _LOGGER.exception(
                    "Unexpected error while processing WAN IPv6 data from UniFi Cloud API: %s",
                    err,
                )

        return data

    def _fetch_data(self) -> UniFiGatewayData:
        """Fetch data with improved VPN and speedtest handling."""
        start_time = time.monotonic()
        _LOGGER.debug(
            "Starting UniFi Gateway data fetch for instance %s",
            self._client.instance_key(),
        )

        controller_api_url = self._client.get_controller_api_url()
        controller_site = self._client.get_site()
        controller_info = {
            "url": self._client.get_controller_url(),
            "api_url": controller_api_url,
            "site": controller_site,
        }
        _LOGGER.debug(
            "Controller context: url=%s site=%s",
            controller_info["api_url"],
            controller_info["site"],
        )

        health = self._client.get_healthinfo() or []
        _LOGGER.debug("Retrieved %s health records", len(health))
        health_by_subsystem: Dict[str, Dict[str, Any]] = {}
        wan_health: List[Dict[str, Any]] = []
        for record in health:
            subsystem = str(record.get("subsystem") or "").lower()
            if subsystem:
                health_by_subsystem[subsystem] = record
            if subsystem in {"wan", "www", "internet"}:
                wan_health.append(record)
        if not wan_health and health:
            wan_health = list(health)

        alerts_raw = self._client.get_alerts() or []
        alerts = [alert for alert in alerts_raw if not alert.get("archived")]
        _LOGGER.debug(
            "Retrieved %s active alerts (raw=%s)", len(alerts), len(alerts_raw)
        )
        devices = self._client.get_devices() or []
        _LOGGER.debug("Retrieved %s devices", len(devices))

        networks = self._client.get_networks() or []
        _LOGGER.debug("Retrieved %s networks", len(networks))
        lan_networks: List[Dict[str, Any]] = []
        network_map: Dict[str, Dict[str, Any]] = {}
        for net in networks:
            nid = net.get("_id") or net.get("id")
            if nid:
                network_map[str(nid)] = {
                    "id": nid,
                    "name": net.get("name"),
                    "vlan": net.get("vlan"),
                    "subnet": net.get("subnet")
                    or net.get("ip_subnet")
                    or net.get("cidr"),
                    "purpose": net.get("purpose") or net.get("role"),
                }
            purpose = str(net.get("purpose") or net.get("role") or "").lower()
            name = net.get("name") or ""
            if "vpn" in purpose or "wan" in purpose or net.get("is_vpn") or net.get("wan_network"):
                continue
            if "wan" in name.lower():
                continue
            lan_networks.append(net)
        _LOGGER.debug("Identified %s LAN networks", len(lan_networks))

        wan_links_raw = self._client.get_wan_links() or []
        if not wan_links_raw:
            wan_links_raw = self._derive_wan_links_from_networks(networks)
            _LOGGER.debug(
                "WAN link discovery required fallback derivation; derived=%s",
                len(wan_links_raw),
            )

        ipv4: Optional[str] = None
        try:
            wan_ips = self._client.get_wan_ips_from_devices()
        except Exception as err:  # pragma: no cover - defensive guard for API quirks
            _LOGGER.debug("WAN IPs from devices unavailable: %s", err)
        else:
            if isinstance(wan_ips, (list, tuple)) and wan_ips:
                ipv4_candidate = wan_ips[0]
                if isinstance(ipv4_candidate, str) and ipv4_candidate:
                    ipv4 = ipv4_candidate

        if wan_links_raw and ipv4:
            for wan in wan_links_raw:
                if isinstance(wan, dict):
                    if ipv4 and not wan.get("last_ipv4"):
                        wan["last_ipv4"] = ipv4
                else:
                    if ipv4 and not getattr(wan, "last_ipv4", None):
                        setattr(wan, "last_ipv4", ipv4)
        wan_links: List[Dict[str, Any]] = []
        for link in wan_links_raw:
            link_id = link.get("id") or link.get("_id") or link.get("ifname")
            link_name = link.get("name") or link.get("display_name")
            if not link_id:
                link_id = link_name or link.get("isp") or link.get("type") or "wan"
            if not link_name:
                link_name = str(link_id)
            normalized = dict(link)
            normalized["id"] = str(link_id)
            normalized["name"] = link_name
            _LOGGER.debug(
                "WAN LastIP candidates: v4=%s v6=%s (after device-scan)",
                normalized.get("last_ipv4"),
                normalized.get("last_ipv6"),
            )
            wan_links.append(normalized)
        _LOGGER.debug("Processed %s WAN link records", len(wan_links))

        wlans = self._client.get_wlans() or []
        _LOGGER.debug("Retrieved %s WLAN configurations", len(wlans))
        clients_all = self._client.get_clients() or []
        _LOGGER.debug("Retrieved %s clients", len(clients_all))

        # Improved speedtest handling
        speedtest = None
        try:
            speedtest = self._client.get_last_speedtest(cache_sec=5)
            if speedtest:
                # Validate speedtest data
                has_values = any(
                    isinstance(speedtest.get(key), (int, float)) and speedtest[key] > 0
                    for key in ("download_mbps", "upload_mbps", "latency_ms")
                )
                if not has_values:
                    _LOGGER.debug("Cached speedtest result has no valid measurements")
                    speedtest = None
                else:
                    _LOGGER.debug(
                        "Valid speedtest result: %0.1f/%0.1f Mbps, %0.1f ms",
                        speedtest.get("download_mbps", 0),
                        speedtest.get("upload_mbps", 0),
                        speedtest.get("latency_ms", 0)
                    )
        except APIError as err:
            _LOGGER.warning("Failed to fetch speedtest results: %s", err)

        # Improved speedtest trigger logic
        interval = self._speedtest_interval
        if interval > 0:
            last_ts = self._speedtest_last_timestamp(speedtest)
            now_ts = time.time()

            should_trigger = False
            if not speedtest:
                should_trigger = True
                reason = "missing"
            elif last_ts and (now_ts - last_ts) >= interval:
                should_trigger = True
                reason = f"stale ({int(now_ts - last_ts)}s old)"

        if should_trigger:
            cooldown = max(interval, 60)
            try:
                self._client.maybe_start_speedtest(cooldown_sec=cooldown)
                _LOGGER.info(
                    "Triggered speedtest (reason=%s, interval=%ss, cooldown=%ss)",
                    reason,
                    interval,
                    cooldown
                )
            except APIError as err:
                _LOGGER.warning("Failed to trigger speedtest: %s", err)

        data = UniFiGatewayData(
            controller=controller_info,
            health=health,
            health_by_subsystem=health_by_subsystem,
            wan_health=wan_health,
            alerts=alerts,
            devices=devices,
            wan_links=wan_links,
            networks=networks,
            lan_networks=lan_networks,
            network_map=network_map,
            wlans=wlans,
            clients=clients_all,
            speedtest=speedtest,
        )
        fetch_time = time.monotonic() - start_time
        _LOGGER.debug(
            "Completed UniFi Gateway data fetch in %.1fs for instance %s",
            fetch_time,
            self._client.instance_key(),
        )
        return data

    def _derive_wan_links_from_networks(
        self, networks: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        wan_candidates: List[Dict[str, Any]] = []
        for net in networks:
            purpose = str(net.get("purpose") or net.get("role") or "").lower()
            name = net.get("name") or ""
            if "wan" in purpose or net.get("wan_network") or "wan" in name.lower():
                wan_candidates.append(
                    {
                        "id": net.get("_id") or net.get("id") or name or "wan",
                        "name": name or "WAN",
                        "type": net.get("purpose") or net.get("role") or "wan",
                    }
                )
        return wan_candidates
