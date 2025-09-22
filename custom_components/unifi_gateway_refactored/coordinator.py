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
            vpn_peers = await self.hass.async_add_executor_job(
                client.get_vpn_peers, 0
            )
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.debug(
                "Forcing VPN peer probe failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_peers = []

        peers_list = list(vpn_peers or [])
        vpn_servers = list(client.get_vpn_servers(peers_list))
        vpn_clients = list(client.get_vpn_clients(peers_list))
        vpn_site_to_site = list(client.get_vpn_site_to_site(peers_list))
        vpn_remote_users = list(client.get_vpn_remote_users(peers_list))

        vpn_summary_raw: Dict[str, Any]
        try:
            vpn_summary_raw = client.vpn_probe_summary()
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.debug(
                "Fetching VPN probe summary failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_summary_raw = {}

        vpn_errors_raw: Dict[str, Any]
        try:
            vpn_errors_raw = client.vpn_probe_errors()
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.debug(
                "Fetching VPN probe errors failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_errors_raw = {}

        vpn_summary = dict(vpn_summary_raw or {})
        vpn_errors = dict(vpn_errors_raw or {})
        vpn_counts = {
            "servers": len(vpn_servers),
            "clients": len(vpn_clients),
            "site_to_site": len(vpn_site_to_site),
            "remote_users": len(vpn_remote_users),
            "peers": len(peers_list),
        }
        api_bases = client.get_vpn_api_bases()
        vpn_diag: Dict[str, Any] = {
            "summary": vpn_summary,
            "errors": vpn_errors,
            "controller_api": client.get_controller_api_url(),
            "site": client.get_site(),
            "api_bases": api_bases,
            "counts": vpn_counts,
        }

        total_peers = vpn_counts["servers"] + vpn_counts["clients"] + vpn_counts["site_to_site"]
        if total_peers == 0:
            _LOGGER.warning(
                "VPN discovery returned no peers. counts=%s, controller_api=%s, site=%s, api_bases=%s, probe_errors=%s",
                vpn_counts,
                vpn_diag["controller_api"],
                vpn_diag["site"],
                api_bases,
                vpn_summary.get("probe_errors"),
            )
        else:
            _LOGGER.info(
                "VPN discovery: servers=%d clients=%d site_to_site=%d summary=%s",
                vpn_counts["servers"],
                vpn_counts["clients"],
                vpn_counts["site_to_site"],
                vpn_summary,
            )

        _LOGGER.debug(
            "VPN probe diagnostics: counts=%s errors=%s summary=%s",
            vpn_counts,
            vpn_errors,
            vpn_summary,
        )

        try:
            return await self.hass.async_add_executor_job(
                self._fetch_data,
                vpn_servers,
                vpn_clients,
                vpn_site_to_site,
                vpn_diag,
                None,
                vpn_remote_users,
                vpn_summary,
                vpn_errors,
            )
        except (ConnectivityError, APIError) as err:
            raise UpdateFailed(str(err)) from err

    def _fetch_data(
        self,
        vpn_servers: Optional[List[Dict[str, Any]]] = None,
        vpn_clients: Optional[List[Dict[str, Any]]] = None,
        vpn_site_to_site: Optional[List[Dict[str, Any]]] = None,
        vpn_diag: Optional[Dict[str, Any]] = None,
        vpn_fetch_error: Optional[str] = None,
        vpn_remote_users: Optional[List[Dict[str, Any]]] = None,
        vpn_summary: Optional[Dict[str, Any]] = None,
        vpn_errors: Optional[Dict[str, Any]] = None,
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
            # Some controllers omit WAN-specific subsystem entries; keep full
            # health payload as a fallback so sensors can surface something
            # meaningful instead of reporting missing data entirely.
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
        vpn_servers_list: List[Dict[str, Any]] = list(vpn_servers or [])
        vpn_clients_list: List[Dict[str, Any]] = list(vpn_clients or [])
        vpn_site_to_site_list: List[Dict[str, Any]] = list(vpn_site_to_site or [])
        vpn_remote_users_list: List[Dict[str, Any]] = list(vpn_remote_users or [])
        vpn_diag_payload: Dict[str, Any] = (
            dict(vpn_diag) if isinstance(vpn_diag, dict) else {}
        )
        vpn_diag_payload.setdefault("controller_api", controller_api_url)
        vpn_diag_payload.setdefault("site", controller_site)
        vpn_fetch_error_value: Optional[str] = vpn_fetch_error
        vpn_summary_payload: Dict[str, Any] = (
            dict(vpn_summary) if isinstance(vpn_summary, dict) else {}
        )
        vpn_errors_payload: Dict[str, Any] = (
            dict(vpn_errors) if isinstance(vpn_errors, dict) else {}
        )
        if vpn_errors_payload and "errors" not in vpn_diag_payload:
            vpn_diag_payload["errors"] = vpn_errors_payload

        if vpn_servers is None:
            try:
                vpn_servers_list = self._client.get_vpn_servers() or []
            except Exception as err:  # pragma: no cover - defensive guard
                message = str(err)
                vpn_fetch_error_value = (
                    f"{vpn_fetch_error_value}; {message}"
                    if vpn_fetch_error_value
                    else message
                )
                _LOGGER.warning(
                    "VPN server discovery failed during fallback fetch: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
        if vpn_clients is None:
            try:
                vpn_clients_list = self._client.get_vpn_clients() or []
            except Exception as err:  # pragma: no cover - defensive guard
                message = str(err)
                vpn_fetch_error_value = (
                    f"{vpn_fetch_error_value}; {message}"
                    if vpn_fetch_error_value
                    else message
                )
                _LOGGER.warning(
                    "VPN client discovery failed during fallback fetch: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
        if vpn_site_to_site is None:
            try:
                vpn_site_to_site_list = self._client.get_vpn_site_to_site() or []
            except Exception as err:  # pragma: no cover - defensive guard
                message = str(err)
                vpn_fetch_error_value = (
                    f"{vpn_fetch_error_value}; {message}"
                    if vpn_fetch_error_value
                    else message
                )
                _LOGGER.warning(
                    "VPN site-to-site discovery failed during fallback fetch: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )

        if vpn_remote_users is None:
            try:
                vpn_remote_users_list = self._client.get_vpn_remote_users() or []
            except Exception as err:  # pragma: no cover - defensive guard
                message = str(err)
                vpn_fetch_error_value = (
                    f"{vpn_fetch_error_value}; {message}"
                    if vpn_fetch_error_value
                    else message
                )
                _LOGGER.warning(
                    "VPN remote user discovery failed during fallback fetch: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )

        if vpn_diag is None or "summary" not in vpn_diag_payload:
            try:
                vpn_diag_payload["summary"] = self._client.vpn_probe_summary()
            except Exception as err:  # pragma: no cover - defensive guard
                _LOGGER.debug(
                    "Fetching VPN probe summary during fallback failed: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                vpn_diag_payload.setdefault("summary", None)
        if vpn_diag is None or "errors" not in vpn_diag_payload:
            try:
                vpn_diag_payload["errors"] = self._client.vpn_probe_errors()
            except Exception as err:  # pragma: no cover - defensive guard
                _LOGGER.debug(
                    "Fetching VPN probe errors during fallback failed: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                errors = vpn_diag_payload.get("errors")
                fallback_error = {
                    "reason": "vpn_diagnostics_fetch_failed",
                    "message": str(err),
                }
                if isinstance(errors, list):
                    errors.append(fallback_error)
                elif errors in (None, "", [], {}):
                    vpn_diag_payload["errors"] = [fallback_error]
                else:
                    vpn_diag_payload["errors"] = [errors, fallback_error]

        vpn_servers = vpn_servers_list
        vpn_clients = vpn_clients_list
        vpn_site_to_site = vpn_site_to_site_list
        vpn_remote_users = vpn_remote_users_list
        vpn_diag = vpn_diag_payload
        vpn_fetch_error = vpn_fetch_error_value
        if not vpn_summary_payload:
            vpn_summary_payload = (
                vpn_diag_payload.get("summary")
                if isinstance(vpn_diag_payload.get("summary"), dict)
                else {}
            )
        else:
            vpn_diag_payload.setdefault("summary", vpn_summary_payload)

        vpn_counts = {
            "servers": len(vpn_servers or []),
            "clients": len(vpn_clients or []),
            "site_to_site": len(vpn_site_to_site or []),
            "remote_users": len(vpn_remote_users or []),
        }
        vpn_diag.setdefault("summary", None)
        errors_value = vpn_diag.get("errors")
        if isinstance(errors_value, tuple):
            vpn_diag["errors"] = list(errors_value)
        elif isinstance(errors_value, str):
            stripped = errors_value.strip()
            vpn_diag["errors"] = [stripped] if stripped else []
        elif isinstance(errors_value, dict):
            if not errors_value:
                vpn_diag["errors"] = {}
        elif errors_value in (None, "", {}):
            vpn_diag["errors"] = []
        counts_value = vpn_diag.get("counts")
        if isinstance(counts_value, dict):
            counts_value.setdefault("servers", vpn_counts["servers"])
            counts_value.setdefault("clients", vpn_counts["clients"])
            counts_value.setdefault("site_to_site", vpn_counts["site_to_site"])
            counts_value.setdefault("remote_users", vpn_counts["remote_users"])
        else:
            vpn_diag["counts"] = vpn_counts
        if vpn_fetch_error:
            fetch_errors = vpn_diag.setdefault("fetch_errors", {})
            if isinstance(fetch_errors, dict):
                fetch_errors.setdefault("exception", vpn_fetch_error)
            else:
                vpn_diag["fetch_errors"] = {"exception": vpn_fetch_error}

        vpn_payload = {
            "servers": list(vpn_servers or []),
            "clients": list(vpn_clients or []),
            "remote_users": list(vpn_remote_users or []),
            "site_to_site": list(vpn_site_to_site or []),
            "summary": dict(vpn_summary_payload or {}),
            "diagnostics": dict(vpn_diag),
            "errors": dict(vpn_errors_payload or {}),
        }

        _LOGGER.debug(
            "VPN discovery summary for %s (api=%s, site=%s): %s",
            self._client.instance_key(),
            controller_api_url,
            controller_site,
            vpn_counts,
        )

        _LOGGER.debug(
            "VPN records for instance %s: servers=%s clients=%s site_to_site=%s",
            self._client.instance_key(),
            vpn_counts["servers"],
            vpn_counts["clients"],
            vpn_counts["site_to_site"],
        )

        try:
            speedtest = self._client.get_last_speedtest(cache_sec=5)
            if speedtest:
                _LOGGER.debug("Retrieved cached speedtest result")
        except APIError as err:
            _LOGGER.warning("Fetching last speedtest failed: %s", err)
            speedtest = None

        # fire and forget — the method is safe if controller does not support speedtests
        try:
            self._client.maybe_start_speedtest(cooldown_sec=3600)
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
            vpn_remote_users=vpn_remote_users,
            vpn_summary=vpn_summary_payload,
            speedtest=speedtest,
            vpn_diagnostics=vpn_summary_payload,
            vpn_errors=vpn_errors_payload,
            vpn=vpn_payload,
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
