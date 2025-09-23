from __future__ import annotations

from dataclasses import dataclass, field
from datetime import timedelta
import logging
from typing import Any, Dict, List, Optional

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import DOMAIN
from .unifi_client import APIError, ConnectivityError, UniFiOSClient


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
    vpn_servers: list[dict[str, Any]] = field(default_factory=list)
    vpn_clients: list[dict[str, Any]] = field(default_factory=list)
    vpn_site_to_site: list[dict[str, Any]] = field(default_factory=list)
    vpn_remote_users: list[dict[str, Any]] = field(default_factory=list)
    vpn_summary: dict[str, Any] = field(default_factory=dict)
    speedtest: Optional[dict[str, Any]] = None
    vpn_diagnostics: dict[str, Any] = field(default_factory=dict)
    vpn_errors: dict[str, Any] = field(default_factory=dict)
    vpn: dict[str, Any] = field(default_factory=dict)
    vpn_state: dict[str, Any] = field(default_factory=dict)


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

        try:
            vpn_state = await client.get_vpn_state()
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.debug(
                "Fetching VPN state failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_state = {
                "remote_users": [],
                "s2s_peers": [],
                "teleport": {"servers": [], "clients": []},
                "counts": {},
                "diagnostics": {"errors": {"exception": str(err)}},
            }

        diagnostics = dict(vpn_state.get("diagnostics") or {})
        vpn_counts = dict(vpn_state.get("counts") or {})
        peers_total = sum(vpn_counts.values()) if vpn_counts else 0

        _LOGGER.info(
            "VPN state: remote_users=%d site_to_site=%d teleport_clients=%d teleport_servers=%d",
            vpn_counts.get("remote_users", 0),
            vpn_counts.get("s2s_peers", 0),
            vpn_counts.get("teleport_clients", 0),
            vpn_counts.get("teleport_servers", 0),
        )
        if diagnostics.get("errors"):
            _LOGGER.debug("VPN diagnostics errors: %s", diagnostics.get("errors"))
        if peers_total == 0:
            _LOGGER.warning(
                "VPN state returned no connections for site %s", client.get_site()
            )

        try:
            return await self.hass.async_add_executor_job(
                self._fetch_data,
                vpn_state,
            )
        except (ConnectivityError, APIError) as err:
            raise UpdateFailed(str(err)) from err

    def _fetch_data(self, vpn_state: Dict[str, Any]) -> UniFiGatewayData:
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

        teleport = vpn_state.get("teleport") or {}
        vpn_servers_list: List[Dict[str, Any]] = list(teleport.get("servers") or [])
        vpn_clients_list: List[Dict[str, Any]] = list(teleport.get("clients") or [])
        vpn_site_to_site_list: List[Dict[str, Any]] = list(vpn_state.get("s2s_peers") or [])
        vpn_remote_users_list: List[Dict[str, Any]] = list(vpn_state.get("remote_users") or [])
        vpn_diag_payload: Dict[str, Any] = (
            dict(vpn_state.get("diagnostics") or {})
        )
        vpn_diag_payload.setdefault("controller_api", controller_api_url)
        vpn_diag_payload.setdefault("site", controller_site)
        vpn_summary_payload: Dict[str, Any] = dict(vpn_diag_payload.get("summary") or {})
        vpn_errors_payload: Dict[str, Any] = dict(vpn_diag_payload.get("errors") or {})

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
            vpn_servers=vpn_servers_list,
            vpn_clients=vpn_clients_list,
            vpn_site_to_site=vpn_site_to_site_list,
            vpn_remote_users=vpn_remote_users_list,
            vpn_summary=vpn_summary_payload,
            vpn_errors=vpn_errors_payload,
            vpn=network_map,
            vpn_snapshot=None,
            vpn_state=vpn_state,
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
