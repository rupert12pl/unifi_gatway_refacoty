from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
import logging
import re
import time
from typing import Any, Dict, List, Mapping, Optional

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .cloud_client import UiCloudAuthError, UiCloudClient, UiCloudError, UiCloudRateLimitError
from .const import DOMAIN
from .unifi_client import APIError, ConnectivityError, UniFiOSClient


_LOGGER = logging.getLogger(__name__)

_PLACEHOLDER_STRINGS = {
    "unknown",
    "none",
    "null",
    "n/a",
    "na",
    "not available",
    "-",
    "0.0.0.0",
    "::",
    "::/0",
}
_IDENTIFIER_KEYS = (
    "id",
    "name",
    "ifname",
    "interface",
    "iface",
    "wan_id",
    "wan_name",
    "display_name",
    "port",
    "role",
    "slot",
    "interface_name",
)


def _normalize_identifier(value: Any) -> Optional[str]:
    if value in (None, "", [], {}):
        return None
    if isinstance(value, str):
        candidate = value.strip()
    else:
        candidate = str(value).strip()
    if not candidate:
        return None
    return candidate.lower()


def _identifier_candidates(record: Mapping[str, Any]) -> Set[str]:
    if not isinstance(record, Mapping):
        return set()
    candidates: Set[str] = set()
    for key in _IDENTIFIER_KEYS:
        if key not in record:
            continue
        value = record.get(key)
        if isinstance(value, (list, tuple, set)):
            for item in value:
                normalized = _normalize_identifier(item)
                if normalized:
                    candidates.add(normalized)
        else:
            normalized = _normalize_identifier(value)
            if normalized:
                candidates.add(normalized)
    return candidates


def _has_meaningful_value(value: Any) -> bool:
    if value in (None, "", [], {}):
        return False
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return False
        if cleaned.lower() in _PLACEHOLDER_STRINGS:
            return False
    return True


def _merge_wan_link_record(target: Dict[str, Any], source: Mapping[str, Any]) -> None:
    if not isinstance(source, Mapping):
        return
    for key in (
        "wan_ipv6",
        "last_ipv6",
        "gateway_ipv6",
        "wan_ipv6_prefix",
        "wan_ip",
        "last_ipv4",
        "isp",
    ):
        value = source.get(key)
        if not _has_meaningful_value(value):
            continue
        if not _has_meaningful_value(target.get(key)):
            target[key] = value
    for key in ("ui_host_id", "ui_host_name", "ui_host_source"):
        value = source.get(key)
        if _has_meaningful_value(value):
            target[key] = value


def _merge_wan_links_with_ui_hosts(
    wan_links: Iterable[Mapping[str, Any]],
    remote_links: Iterable[Mapping[str, Any]],
) -> List[Dict[str, Any]]:
    local: List[Dict[str, Any]] = [dict(link) for link in wan_links if isinstance(link, Mapping)]
    remote_normalized: List[Dict[str, Any]] = []
    for remote in remote_links:
        if not isinstance(remote, Mapping):
            continue
        if not _identifier_candidates(remote):
            continue
        if not any(
            _has_meaningful_value(remote.get(key))
            for key in ("wan_ipv6", "wan_ip", "gateway_ipv6", "wan_ipv6_prefix")
        ):
            continue
        remote_normalized.append(dict(remote))

    if not local:
        return remote_normalized

    used: Set[int] = set()
    remote_candidates = [_identifier_candidates(remote) for remote in remote_normalized]

    for link in local:
        candidates = _identifier_candidates(link)
        if not candidates:
            continue
        matched_idx: Optional[int] = None
        for idx, remote_ids in enumerate(remote_candidates):
            if idx in used or not remote_ids:
                continue
            if candidates & remote_ids:
                matched_idx = idx
                break
        if matched_idx is None and len(remote_normalized) == 1 and 0 not in used:
            matched_idx = 0
        if matched_idx is None:
            continue
        _merge_wan_link_record(link, remote_normalized[matched_idx])
        used.add(matched_idx)

    for idx, remote in enumerate(remote_normalized):
        if idx in used:
            continue
        local.append(remote)

    return local


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


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: UniFiOSClient,
        *,
        speedtest_interval: int | None = None,
        ui_cloud_client: UiCloudClient | None = None,
    ) -> None:
        self._client = client
        self._ui_cloud_client = ui_cloud_client
        self._wan_ipv6_cache: dict[str, tuple[float, str]] = {}
        self._cloud_cache_ttl = 300.0
        self._speedtest_interval = self._sanitize_speedtest_interval(speedtest_interval)
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=15),
        )
        if self._ui_cloud_client is not None:
            _LOGGER.info("Using UI Cloud API for WAN IPv6")

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

    async def _merge_wan_ipv6_from_cloud(self, data: UniFiGatewayData) -> None:
        if not data or not data.wan_links:
            return

        mapping: dict[str, str] = {}
        if self._ui_cloud_client is None:
            return
        try:
            payload = await self._ui_cloud_client.fetch_hosts()
        except UiCloudAuthError as err:
            _LOGGER.warning(
                "UI Cloud API authentication failed while fetching WAN IPv6 (status=%s)",
                err.status,
            )
        except UiCloudRateLimitError as err:
            retry_desc = (
                f"{err.retry_after:.1f}s" if err.retry_after is not None else "unknown"
            )
            _LOGGER.warning(
                "UI Cloud API rate limited while fetching WAN IPv6 (retry_in=%s)",
                retry_desc,
            )
        except UiCloudError as err:
            _LOGGER.error("Failed to fetch WAN IPv6 from UI Cloud API: %s", err)
        else:
            if isinstance(payload, Mapping):
                mapping = self._extract_ipv6_mapping(payload)
            else:
                _LOGGER.debug(
                    "UI Cloud API returned unexpected payload type: %s",
                    type(payload),
                )

        now = time.monotonic()
        self._apply_wan_ipv6_updates(data, mapping, now)

    @staticmethod
    def _extract_ipv6_mapping(payload: Mapping[str, Any]) -> dict[str, str]:
        mapping: dict[str, str] = {}
        data_list = payload.get("data")
        if not isinstance(data_list, list):
            return mapping
        for console in data_list:
            if not isinstance(console, Mapping):
                continue
            reported = console.get("reportedState")
            if not isinstance(reported, Mapping):
                continue
            wans = reported.get("wans")
            if not isinstance(wans, list):
                continue
            for wan in wans:
                if not isinstance(wan, Mapping):
                    continue
                if not UniFiGatewayDataUpdateCoordinator._wan_candidate_enabled(wan):
                    continue
                mac = UniFiGatewayDataUpdateCoordinator._normalize_mac(wan.get("mac"))
                if not mac or mac in mapping:
                    continue
                ipv6 = wan.get("ipv6")
                if isinstance(ipv6, str):
                    ipv6_clean = ipv6.strip()
                    if ipv6_clean:
                        mapping[mac] = ipv6_clean
        return mapping

    def _apply_wan_ipv6_updates(
        self,
        data: UniFiGatewayData,
        mapping: dict[str, str],
        now: float,
    ) -> None:
        if not data.wan_links:
            return

        health_lookup = self._build_health_lookup(data.wan_health)

        for link in data.wan_links:
            if not isinstance(link, dict):
                continue

            mac, health_record = self._resolve_wan_mac(link, health_lookup)
            if not mac:
                continue

            cached_value: Optional[str] = None
            cache_entry = self._wan_ipv6_cache.get(mac)
            if cache_entry:
                ts, cached = cache_entry
                if (now - ts) <= self._cloud_cache_ttl:
                    cached_value = cached
                else:
                    self._wan_ipv6_cache.pop(mac, None)

            if mac in mapping:
                ipv6_value = mapping[mac]
                link["last_ipv6"] = ipv6_value
                if not link.get("wan_ipv6"):
                    link["wan_ipv6"] = ipv6_value
                if isinstance(health_record, dict):
                    if not health_record.get("last_ipv6"):
                        health_record["last_ipv6"] = ipv6_value
                    if not health_record.get("wan_ipv6"):
                        health_record["wan_ipv6"] = ipv6_value
                self._wan_ipv6_cache[mac] = (now, ipv6_value)
                continue

            if cached_value and not link.get("last_ipv6"):
                link["last_ipv6"] = cached_value
                if not link.get("wan_ipv6"):
                    link["wan_ipv6"] = cached_value
                if isinstance(health_record, dict):
                    if not health_record.get("last_ipv6"):
                        health_record["last_ipv6"] = cached_value
                    if not health_record.get("wan_ipv6"):
                        health_record["wan_ipv6"] = cached_value

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

        if self._ui_cloud_client is not None and data:
            try:
                await self._merge_wan_ipv6_from_cloud(data)
            except Exception as err:  # pragma: no cover - defensive logging
                _LOGGER.exception(
                    "Unexpected error while merging WAN IPv6 data from UI Cloud API: %s",
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
