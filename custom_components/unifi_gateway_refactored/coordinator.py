from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import Any, Dict, List, Optional

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .unifi_client import APIError, ConnectivityError, UniFiOSClient, VpnConfigList


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
    vpn_diagnostics: dict[str, Any] = field(default_factory=dict)
    vpn_config_list: VpnConfigList | None = None


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities."""

    def __init__(self, hass: HomeAssistant, client: UniFiOSClient) -> None:
        self._client = client
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=15),
        )

    async def _async_update_data(self) -> UniFiGatewayData:
        client = self._client
        site = client.get_site()

        diagnostics_error: str | None = None
        try:
            vpn_config = await self.hass.async_add_executor_job(
                client.get_vpn_config_list,
                site,
            )
        except Exception as err:  # pragma: no cover - defensive guard
            diagnostics_error = str(err)
            _LOGGER.debug(
                "Fetching VPN configuration failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_config = VpnConfigList(
                remote_users=[],
                s2s_peers=[],
                teleport_servers=[],
                teleport_clients=[],
                attempts=[],
                winner_paths={},
            )

        counts = {
            "remote_users": len(vpn_config.remote_users),
            "s2s_peers": len(vpn_config.s2s_peers),
            "teleport_servers": len(vpn_config.teleport_servers),
            "teleport_clients": len(vpn_config.teleport_clients),
        }

        peers_total = sum(counts.values())
        if peers_total:
            _LOGGER.info(
                "VPN configuration discovered: remote_users=%d site_to_site=%d teleport_clients=%d teleport_servers=%d",
                counts["remote_users"],
                counts["s2s_peers"],
                counts["teleport_clients"],
                counts["teleport_servers"],
            )
        else:
            _LOGGER.info(
                "VPN configuration contains no entries for site %s",
                site,
            )

        diagnostics: Dict[str, Any] = {
            "counts": counts,
            "attempts": [
                {
                    "path": attempt.path,
                    "status": attempt.status,
                    "ok": attempt.ok,
                    "snippet": attempt.snippet,
                }
                for attempt in vpn_config.attempts
            ],
            "winner_paths": dict(vpn_config.winner_paths),
            "site": site,
        }
        if diagnostics_error:
            diagnostics["errors"] = {"config_fetch": diagnostics_error}

        try:
            return await self.hass.async_add_executor_job(
                self._fetch_data,
                vpn_config,
                diagnostics,
            )
        except (ConnectivityError, APIError) as err:
            raise UpdateFailed(str(err)) from err
    def _fetch_data(
        self,
        vpn_config: VpnConfigList,
        diagnostics: Dict[str, Any],
    ) -> UniFiGatewayData:
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
            _LOGGER.warning(
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

        try:
            speedtest = self._client.get_last_speedtest(cache_sec=5)
            if speedtest:
                _LOGGER.debug("Retrieved cached speedtest result")
        except APIError as err:
            _LOGGER.warning("Fetching last speedtest failed: %s", err)
            speedtest = None

        try:
            self._client.maybe_start_speedtest(cooldown_sec=3600)
            _LOGGER.debug("Speedtest trigger evaluated")
        except APIError as err:
            _LOGGER.debug("Speedtest trigger failed: %s", err)

        vpn_diagnostics = dict(diagnostics)

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
            vpn_diagnostics=vpn_diagnostics,
            vpn_config_list=vpn_config,
        )
        _LOGGER.debug(
            "Completed UniFi Gateway data fetch for instance %s",
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
