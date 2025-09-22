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

    controller: Dict[str, Any]
    health: List[Dict[str, Any]] = field(default_factory=list)
    health_by_subsystem: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    wan_health: List[Dict[str, Any]] = field(default_factory=list)
    alerts: List[Dict[str, Any]] = field(default_factory=list)
    devices: List[Dict[str, Any]] = field(default_factory=list)
    wan_links: List[Dict[str, Any]] = field(default_factory=list)
    networks: List[Dict[str, Any]] = field(default_factory=list)
    lan_networks: List[Dict[str, Any]] = field(default_factory=list)
    network_map: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    wlans: List[Dict[str, Any]] = field(default_factory=list)
    clients: List[Dict[str, Any]] = field(default_factory=list)
    vpn_servers: List[Dict[str, Any]] = field(default_factory=list)
    vpn_clients: List[Dict[str, Any]] = field(default_factory=list)
    vpn_site_to_site: List[Dict[str, Any]] = field(default_factory=list)
    speedtest: Optional[Dict[str, Any]] = None
    vpn_diagnostics: Optional[Dict[str, Any]] = None


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities."""

    def __init__(self, hass: HomeAssistant, client: UniFiOSClient) -> None:
        self.client = client
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=30),
        )

    async def _async_update_data(self) -> UniFiGatewayData:
        try:
            return await self.hass.async_add_executor_job(self._fetch_data)
        except (ConnectivityError, APIError) as err:
            raise UpdateFailed(str(err)) from err

    def _fetch_data(self) -> UniFiGatewayData:
        _LOGGER.debug(
            "Starting UniFi Gateway data fetch for instance %s",
            self.client.instance_key(),
        )
        controller_api_url = self.client.get_controller_api_url()
        controller_site = self.client.get_site()
        controller_info = {
            "url": self.client.get_controller_url(),
            "api_url": controller_api_url,
            "site": controller_site,
        }
        _LOGGER.debug(
            "Controller context: url=%s site=%s",
            controller_info["api_url"],
            controller_info["site"],
        )

        health = self.client.get_healthinfo() or []
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
            # Some controllers omit WAN-specific subsystem entries; keep full
            # health payload as a fallback so sensors can surface something
            # meaningful instead of reporting missing data entirely.
            wan_health = list(health)

        alerts_raw = self.client.get_alerts() or []
        alerts = [alert for alert in alerts_raw if not alert.get("archived")]
        _LOGGER.debug(
            "Retrieved %s active alerts (raw=%s)", len(alerts), len(alerts_raw)
        )
        devices = self.client.get_devices() or []
        _LOGGER.debug("Retrieved %s devices", len(devices))

        networks = self.client.get_networks() or []
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

        wan_links_raw = self.client.get_wan_links() or []
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

        wlans = self.client.get_wlans() or []
        _LOGGER.debug("Retrieved %s WLAN configurations", len(wlans))
        clients_all = self.client.get_clients() or []
        _LOGGER.debug("Retrieved %s clients", len(clients_all))
        vpn_servers: List[Dict[str, Any]] = []
        vpn_clients: List[Dict[str, Any]] = []
        vpn_site_to_site: List[Dict[str, Any]] = []
        vpn_diag: Dict[str, Any] = {
            "controller_api": controller_api_url,
            "site": controller_site,
        }
        vpn_fetch_error: Optional[str] = None

        try:
            vpn_servers = self.client.get_vpn_servers() or []
            vpn_clients = self.client.get_vpn_clients() or []
            vpn_site_to_site = self.client.get_vpn_site_to_site() or []
            vpn_diag.update(
                {
                    "summary": self.client.vpn_probe_summary(),
                    "errors": self.client.vpn_probe_errors(),
                }
            )
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_fetch_error = str(err)
            _LOGGER.warning(
                "VPN discovery failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            try:
                vpn_diag.update(
                    {
                        "summary": self.client.vpn_probe_summary(),
                        "errors": self.client.vpn_probe_errors(),
                    }
                )
            except Exception as diag_err:  # pragma: no cover - defensive guard
                _LOGGER.debug(
                    "Fetching VPN diagnostics failed: %s",
                    diag_err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                errors = vpn_diag.get("errors")
                fallback_error = {
                    "reason": "vpn_diagnostics_fetch_failed",
                    "message": str(diag_err),
                }
                if isinstance(errors, list):
                    errors.append(fallback_error)
                elif errors in (None, "", [], {}):
                    vpn_diag["errors"] = [fallback_error]
                else:
                    vpn_diag["errors"] = [errors, fallback_error]

        vpn_counts = {
            "servers": len(vpn_servers or []),
            "clients": len(vpn_clients or []),
            "site_to_site": len(vpn_site_to_site or []),
        }
        vpn_diag.setdefault("summary", None)
        errors_value = vpn_diag.get("errors")
        if isinstance(errors_value, tuple):
            vpn_diag["errors"] = list(errors_value)
        elif isinstance(errors_value, str):
            stripped = errors_value.strip()
            vpn_diag["errors"] = [stripped] if stripped else []
        elif errors_value in (None, "", {}):
            vpn_diag["errors"] = []
        vpn_diag.setdefault("counts", vpn_counts)
        if vpn_fetch_error:
            fetch_errors = vpn_diag.setdefault("fetch_errors", {})
            if isinstance(fetch_errors, dict):
                fetch_errors.setdefault("exception", vpn_fetch_error)
            else:
                vpn_diag["fetch_errors"] = {"exception": vpn_fetch_error}

        _LOGGER.info(
            "VPN discovery summary for %s (api=%s, site=%s): %s",
            self.client.instance_key(),
            controller_api_url,
            controller_site,
            vpn_counts,
        )

        _LOGGER.debug(
            "VPN records for instance %s: servers=%s clients=%s site_to_site=%s",
            self.client.instance_key(),
            vpn_counts["servers"],
            vpn_counts["clients"],
            vpn_counts["site_to_site"],
        )

        try:
            speedtest = self.client.get_last_speedtest(cache_sec=5)
            if speedtest:
                _LOGGER.debug("Retrieved cached speedtest result")
        except APIError as err:
            _LOGGER.warning("Fetching last speedtest failed: %s", err)
            speedtest = None

        # fire and forget — the method is safe if controller does not support speedtests
        try:
            self.client.maybe_start_speedtest(cooldown_sec=3600)
            _LOGGER.debug("Speedtest trigger evaluated")
        except APIError as err:
            _LOGGER.debug("Speedtest trigger failed: %s", err)

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
            vpn_servers=vpn_servers,
            vpn_clients=vpn_clients,
            vpn_site_to_site=vpn_site_to_site,
            speedtest=speedtest,
            vpn_diagnostics=vpn_diag,
        )
        _LOGGER.debug(
            "Completed data fetch: health=%s alerts=%s devices=%s",
            len(data.health),
            len(data.alerts),
            len(data.devices),
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
