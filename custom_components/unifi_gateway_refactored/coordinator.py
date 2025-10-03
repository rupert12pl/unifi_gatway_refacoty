from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed
from homeassistant.util import dt as dt_util

from .const import DOMAIN
from .unifi_client import APIError, AuthError, ConnectivityError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)


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
    vpn_tunnels: list[dict[str, Any]] = field(default_factory=list)


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities with robust error handling."""

    def __init__(
        self,
        hass: HomeAssistant,
        client: UniFiOSClient,
        *,
        speedtest_interval: int | None = None,
    ) -> None:
        self._client = client
        self._speedtest_interval = self._sanitize_speedtest_interval(speedtest_interval)
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=15),
        )

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

    async def _async_update_data(self) -> UniFiGatewayData:
        """Fetch data with improved error handling and retry logic."""
        for attempt in range(3):  # Try up to 3 times
            try:
                # Check connectivity first
                ping_success = await self.hass.async_add_executor_job(self._client.ping)
                if not ping_success:
                    raise ConnectivityError("Controller ping failed")

                return await self.hass.async_add_executor_job(
                    self._fetch_data,
                )
            except AuthError as err:
                _LOGGER.error("Authentication failed during update: %s", err)
                raise UpdateFailed("Authentication error") from err
            except ConnectivityError as err:
                if attempt == 2:  # Last attempt
                    _LOGGER.error("Connection failed after 3 attempts: %s", err)
                    raise UpdateFailed(f"Connection failed: {err}") from err
                _LOGGER.warning("Connection attempt %d failed: %s", attempt + 1, err)
                await asyncio.sleep(2 * (attempt + 1))  # Exponential backoff
            except APIError as err:
                if getattr(err, 'expected', False):
                    _LOGGER.debug("Expected API error: %s", err)
                    raise UpdateFailed(str(err)) from err
                if attempt == 2:  # Last attempt
                    _LOGGER.error("API error after 3 attempts: %s", err)
                    raise UpdateFailed(f"API error: {err}") from err
                _LOGGER.warning("API attempt %d failed: %s", attempt + 1, err)
                await asyncio.sleep(2 * (attempt + 1))
            except Exception as err:
                _LOGGER.error("Unexpected error during update: %s", err)
                raise UpdateFailed(f"Unexpected error: {err}") from err

        raise UpdateFailed("Failed to update UniFi Gateway data after retries")

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
            wan_links.append(normalized)
        _LOGGER.debug("Processed %s WAN link records", len(wan_links))

        wlans = self._client.get_wlans() or []
        _LOGGER.debug("Retrieved %s WLAN configurations", len(wlans))
        clients_all = self._client.get_clients() or []
        _LOGGER.debug("Retrieved %s clients", len(clients_all))

        # VPN tunnel list retained for backward compatibility but populated elsewhere
        vpn_tunnels: List[Dict[str, Any]] = []

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
            vpn_tunnels=vpn_tunnels,
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
