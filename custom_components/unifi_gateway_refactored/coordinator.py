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
    vpn_remote_users: List[Dict[str, Any]] = field(default_factory=list)
    vpn_summary: Dict[str, Any] = field(default_factory=dict)
    speedtest: Optional[Dict[str, Any]] = None
    vpn_diagnostics: Dict[str, Any] = field(default_factory=dict)
    vpn: Dict[str, Any] = field(default_factory=dict)


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval for Home Assistant entities."""

    def __init__(self, hass: HomeAssistant, client: UniFiOSClient) -> None:
        self.client = client
        super().__init__(
            hass,
            logger=_LOGGER,
            name=f"{DOMAIN} data",
            update_interval=timedelta(seconds=15),
        )

    async def _async_update_data(self) -> UniFiGatewayData:
        client = self.client
        hass = self.hass

        vpn_servers: List[Dict[str, Any]] = []
        vpn_clients: List[Dict[str, Any]] = []
        vpn_site_to_site: List[Dict[str, Any]] = []
        vpn_remote_users: List[Dict[str, Any]] = []
        vpn_fetch_errors: List[str] = []

        try:
            # --- VPN: wymuś natychmiastowy probe (bez cache) ---
            await hass.async_add_executor_job(client.get_vpn_peers, 0)
        except Exception as err:  # pragma: no cover - defensive guard
            _LOGGER.debug(
                "Forcing VPN peer probe failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )

        try:
            vpn_servers = await hass.async_add_executor_job(client.get_vpn_servers)
            vpn_servers = vpn_servers or []
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_fetch_errors.append(str(err))
            _LOGGER.warning(
                "Fetching VPN servers failed during update: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_servers = []

        try:
            vpn_clients = await hass.async_add_executor_job(client.get_vpn_clients)
            vpn_clients = vpn_clients or []
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_fetch_errors.append(str(err))
            _LOGGER.warning(
                "Fetching VPN clients failed during update: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_clients = []

        try:
            vpn_site_to_site = await hass.async_add_executor_job(
                client.get_vpn_site_to_site
            )
            vpn_site_to_site = vpn_site_to_site or []
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_fetch_errors.append(str(err))
            _LOGGER.warning(
                "Fetching VPN site-to-site records failed during update: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_site_to_site = []

        try:
            vpn_remote_users = await hass.async_add_executor_job(
                client.get_vpn_remote_users
            )
            vpn_remote_users = vpn_remote_users or []
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_fetch_errors.append(str(err))
            _LOGGER.warning(
                "Fetching VPN remote users failed during update: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )
            vpn_remote_users = []

        try:
            vpn_summary = await hass.async_add_executor_job(client.vpn_probe_summary)
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_summary = {}
            _LOGGER.debug(
                "Fetching VPN probe summary failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )

        try:
            vpn_errors = await hass.async_add_executor_job(client.vpn_probe_errors)
        except Exception as err:  # pragma: no cover - defensive guard
            vpn_errors = []
            _LOGGER.debug(
                "Fetching VPN probe errors failed: %s",
                err,
                exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
            )

        vpn_diag = {
            "summary": vpn_summary,
            "errors": vpn_errors,
            "controller_api": client.get_controller_api_url(),
            "site": client.get_site(),
            "counts": {
                "servers": len(vpn_servers),
                "clients": len(vpn_clients),
                "site_to_site": len(vpn_site_to_site),
            },
        }

        _LOGGER.debug(
            "VPN fetched: servers=%d clients=%d s2s=%d diag=%s",
            len(vpn_servers),
            len(vpn_clients),
            len(vpn_site_to_site),
            vpn_diag.get("summary"),
        )

        vpn_fetch_error = "; ".join(e for e in vpn_fetch_errors if e)
        if not vpn_fetch_error:
            vpn_fetch_error = None

        try:
            return await hass.async_add_executor_job(
                self._fetch_data,
                vpn_servers,
                vpn_clients,
                vpn_site_to_site,
                vpn_diag,
                vpn_fetch_error,
                vpn_remote_users,
                vpn_summary,
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
    ) -> UniFiGatewayData:
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

        if vpn_servers is None:
            try:
                vpn_servers_list = self.client.get_vpn_servers() or []
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
                vpn_clients_list = self.client.get_vpn_clients() or []
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
                vpn_site_to_site_list = self.client.get_vpn_site_to_site() or []
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
                vpn_remote_users_list = self.client.get_vpn_remote_users() or []
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
                vpn_diag_payload["summary"] = self.client.vpn_probe_summary()
            except Exception as err:  # pragma: no cover - defensive guard
                _LOGGER.debug(
                    "Fetching VPN probe summary during fallback failed: %s",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                vpn_diag_payload.setdefault("summary", None)
        if vpn_diag is None or "errors" not in vpn_diag_payload:
            try:
                vpn_diag_payload["errors"] = self.client.vpn_probe_errors()
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
        }

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
            vpn_remote_users=vpn_remote_users,
            vpn_summary=vpn_summary_payload,
            speedtest=speedtest,
            vpn_diagnostics=vpn_diag,
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
