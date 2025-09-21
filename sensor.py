
from __future__ import annotations
import logging
from datetime import timedelta
from typing import Any, Dict, List, Optional

from homeassistant.core import HomeAssistant
from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.typing import StateType
from homeassistant.util import Throttle

from .const import (
    CONF_USERNAME, CONF_PASSWORD, CONF_HOST, CONF_PORT, CONF_SITE_ID,
    CONF_VERIFY_SSL, CONF_USE_PROXY_PREFIX, CONF_TIMEOUT
)
from .unifi_client import UniFiOSClient, APIError

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = timedelta(seconds=10)
MIN_TIME_BETWEEN_UPDATES = timedelta(seconds=10)

SENSOR_WAN = "wan"
SENSOR_LAN = "lan"
SENSOR_WLAN = "wlan"
SENSOR_VPN = "vpn"
SENSOR_ALERTS = "alerts"
SENSOR_FIRMWARE = "firmware"

USG_SENSORS: Dict[str, List[str]] = {
    SENSOR_WAN: ["WAN", "mdi:shield-outline"],
    SENSOR_LAN: ["LAN", "mdi:lan"],
    SENSOR_WLAN: ["WLAN", "mdi:wifi"],
    SENSOR_VPN: ["VPN", "mdi:folder-key-network"],
    SENSOR_ALERTS: ["Alerts", "mdi:information-outline"],
    SENSOR_FIRMWARE: ["Firmware Upgradable", "mdi:database-plus"],
}


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    client = await hass.async_add_executor_job(
        UniFiOSClient,
        entry.data[CONF_HOST],
        entry.data[CONF_USERNAME],
        entry.data[CONF_PASSWORD],
        entry.data.get(CONF_PORT, 443),
        entry.data.get(CONF_SITE_ID, "default"),
        entry.data.get(CONF_VERIFY_SSL, False),
        entry.data.get(CONF_USE_PROXY_PREFIX, True),
        entry.data.get(CONF_TIMEOUT, 10),
        "sensor"
    )
    entities: List[SensorEntity] = []
    # Aggregated subsystems
    for key, (label, _) in USG_SENSORS.items():
        entities.append(UnifiGatewaySensor(client, label, key))
    # Dynamic WAN links + WAN IP / ISP sensors
    wan_links = await hass.async_add_executor_job(client.get_wan_links)
    # WAN fallback from networks if controller returns empty
    if not wan_links:
        nets = await hass.async_add_executor_job(client.get_networks)
        for n in nets or []:
            purpose = (n.get('purpose') or n.get('role') or '').lower()
            if 'wan' in purpose or n.get('wan_network') or 'wan' in (n.get('name') or '').lower():
                wan_links.append({'id': n.get('_id') or n.get('id') or (n.get('name') or 'WAN'), 'name': n.get('name') or 'WAN'})

    for w in wan_links or []:
        entities.append(UnifiWanLinkSensor(client, w))
        entities.append(UnifiWanIpSensor(client, w))
        entities.append(UnifiWanIspSensor(client, w))
    # Dynamic LAN (per VLAN)
    networks = await hass.async_add_executor_job(client.get_networks)
    for n in (networks or []):
        name_l = (n.get('name') or '').lower()
        purpose = (n.get('purpose') or n.get('role') or '').lower()
        if 'vpn' in purpose or 'wan' in purpose or n.get('is_vpn') or n.get('wan_network') or 'wan' in name_l:
            continue
        entities.append(UnifiLanNetworkSensor(client, n))
    # Dynamic WLAN (per SSID)
    wlans = await hass.async_add_executor_job(client.get_wlans)
    wlan_created = 0
    for w in wlans or []:
        entities.append(UnifiWlanSensor(client, w))
        wlan_created += 1
    _LOGGER.info("unifi_gateway_refactored: WLAN entities created: %d", wlan_created)
    # Dynamic VPN: servers and clients
    vpn_servers = await hass.async_add_executor_job(client.get_vpn_servers)
    srv_created = 0
    for idx, s_peer in enumerate(vpn_servers or [], start=1):
        entities.append(UnifiVpnServerSensor(client, s_peer, idx))
        srv_created += 1
    _LOGGER.info("unifi_gateway_refactored: VPN server entities created: %d", srv_created)
    vpn_clients = await hass.async_add_executor_job(client.get_vpn_clients)
    cli_created = 0
    for idx, c_peer in enumerate(vpn_clients or [], start=1):
        entities.append(UnifiVpnClientSensor(client, c_peer, idx))
        cli_created += 1
    _LOGGER.info("unifi_gateway_refactored: VPN client entities created: %d", cli_created)
        # Speedtest sensors
    entities.append(UnifiSpeedtestDownloadSensor(client))
    entities.append(UnifiSpeedtestUploadSensor(client))
    entities.append(UnifiSpeedtestPingSensor(client))
    async_add_entities(entities, True)
    _LOGGER.info("unifi_gateway_refactored: total entities added: %d", len(entities))

class UnifiGatewaySensor(SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, client: UniFiOSClient, label: str, subsystem: str):
        self._client = client
        self._label = label
        self._subsystem = subsystem
        self._attr_name = f"{label}"
        self._attr_icon = USG_SENSORS[subsystem][1]
        self._attr_unique_id = f"unifigw_{client.instance_key()}_{subsystem}"
        self._state: StateType = None
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def icon(self) -> str:
        try:
            return 'mdi:check-circle' if int(self._state or 0) > 0 else 'mdi:account-lock'
        except Exception:
            return 'mdi:account-lock'

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        self._attrs['role'] = getattr(self, '_role', None)
        return self._attrs

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        try:
            if self._subsystem == "alerts":
                self._update_alerts()
            elif self._subsystem == "firmware":
                self._update_firmware()
            else:
                self._update_health()
        except APIError as ex:
            _LOGGER.error("Update failed for %s: %s", self._label, ex)

    def _inject_common(self):
        self._attrs["controller_ui"] = self._client.get_controller_url()
        self._attrs["controller_site"] = self._client.get_site()

    def _update_alerts(self):
        alerts = self._client.get_alerts() or []
        self._attrs = {str(i): a for i, a in enumerate(alerts, 1) if not a.get("archived")}
        self._state = len(self._attrs)
        self._inject_common()

    def _update_firmware(self):
        devices = self._client.get_devices() or []
        upg = [d for d in devices if d.get("upgradable")]
        self._state = len(upg)
        self._attrs = {d.get("name") or d.get("mac"): d["upgradable"] for d in upg}
        self._inject_common()

    def _update_health(self):
        subs = self._client.get_healthinfo() or []
        match = next((s for s in subs if s.get("subsystem") == self._subsystem), None)
        self._state = (match or {}).get("status", "UNKNOWN")
        self._attrs = match or {}
        self._inject_common()


import ipaddress

class UnifiWanLinkSensor(SensorEntity):
    _attr_icon = "mdi:shield-outline"
    def __init__(self, client: UniFiOSClient, link: Dict[str, Any]):
        self._last_ip = None
        self._last_isp = None
        self._client = client
        self._link = link
        self._name = link.get("name") or link.get("display_name") or link.get("id") or "WAN"
        self._id = link.get("id") or self._name
        self._attr_name = f"WAN {self._name}"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_wan_{self._id}_status"
        self._state: StateType = None
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def icon(self) -> str:
        try:
            return 'mdi:check-circle' if int(self._state or 0) > 0 else 'mdi:account-lock'
        except Exception:
            return 'mdi:account-lock'

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        links = self._client.get_wan_links() or []
        me = None
        for l in links:
            lid = l.get("id") or l.get("name") or self._id
            if str(lid) == str(self._id) or (l.get("name") == self._name):
                me = l; break
        status = (me or {}).get("status") or (me or {}).get("state") or "UNKNOWN"
        self._state = str(status).upper()
                # health fallback for WAN
        hi = []
        try:
            hi = self._client.get_healthinfo() or []
        except Exception:
            hi = []
        isp_h = None; ip_h = None
        for sub in hi:
            if (sub.get("subsystem") in ("wan","www","internet")):
                isp_h = isp_h or sub.get("isp") or sub.get("provider") or sub.get("isp_name")
                ip_h = ip_h or sub.get("wan_ip") or sub.get("internet_ip") or sub.get("ip")
        self._attrs = {
            "name": self._name,
            "type": (me or {}).get("type") or (me or {}).get("kind"),
            "isp": (me or {}).get("isp") or (me or {}).get("provider") or isp_h,
            "ip": (me or {}).get("ip") or (me or {}).get("wan_ip") or (me or {}).get("ipv4") or ip_h,
        }

class UnifiWanIpSensor(SensorEntity):
    _attr_icon = "mdi:ip"
    def __init__(self, client: UniFiOSClient, link: Dict[str, Any]):
        self._last_ip = None
        self._client = client
        self._name = link.get("name") or link.get("display_name") or link.get("id") or "WAN"
        self._id = link.get("id") or self._name
        self._attr_name = f"WAN {self._name} IP"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_wan_{self._id}_ip"
        self._state: StateType = None
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        links = self._client.get_wan_links() or []
        me = None
        for l in links:
            lid = l.get("id") or l.get("name") or self._id
            if str(lid) == str(self._id) or (l.get("name") == self._name):
                me = l; break
        ip = (me or {}).get("ip") or (me or {}).get("wan_ip") or (me or {}).get("ipv4")
        if ip and ip != getattr(self, "_last_ip", None):
            self._last_ip = ip
        self._attrs = {"last_ip": getattr(self, "_last_ip", None)}
        self._state = ip

        me = None
        for l in links:
            lid = l.get("id") or l.get("name") or self._id
            if str(lid) == str(self._id) or (l.get("name") == self._name):
                me = l; break
        ip = (me or {}).get("ip") or (me or {}).get("wan_ip") or (me or {}).get("ipv4")
        self._state = ip

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

class UnifiWanIspSensor(SensorEntity):
    _attr_icon = "mdi:domain"
    def __init__(self, client: UniFiOSClient, link: Dict[str, Any]):
        self._last_isp = None
        self._client = client
        self._name = link.get("name") or link.get("display_name") or link.get("id") or "WAN"
        self._id = link.get("id") or self._name
        self._attr_name = f"WAN {self._name} ISP"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_wan_{self._id}_isp"
        self._state: StateType = None
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        links = self._client.get_wan_links() or []
        me = None
        for l in links:
            lid = l.get("id") or l.get("name") or self._id
            if str(lid) == str(self._id) or (l.get("name") == self._name):
                me = l; break
        isp = (me or {}).get("isp") or (me or {}).get("provider")
        if isp and isp != getattr(self, "_last_isp", None):
            self._last_isp = isp
        self._attrs = {"last_isp": getattr(self, "_last_isp", None), "isp_organization": (me or {}).get("isp_name") or (me or {}).get("isp_organization") or (me or {}).get("organization")}
        self._state = isp

        me = None
        for l in links:
            lid = l.get("id") or l.get("name") or self._id
            if str(lid) == str(self._id) or (l.get("name") == self._name):
                me = l; break
        isp = (me or {}).get("isp") or (me or {}).get("provider")
        self._state = isp

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

class UnifiLanNetworkSensor(SensorEntity):
    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT
    def __init__(self, client: UniFiOSClient, net: Dict[str, Any]):
        self._client = client
        self._net = net
        self._net_id = net.get("_id") or net.get("id")
        self._name = net.get("name") or f"VLAN-{net.get('vlan')}"
        self._subnet = net.get("subnet") or net.get("ip_subnet") or net.get("cidr")
        self._ipnet = None
        if self._subnet:
            try:
                self._ipnet = ipaddress.ip_network(self._subnet, strict=False)
            except Exception:
                self._ipnet = None
        self._attr_name = f"LAN {self._name}"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_lan_{self._net_id or self._name}_clients"
        self._state: StateType = 0
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        cnt = 0
        clients = self._client.get_clients() or []
        for c in clients:
            if self._net_id and c.get("network_id") == self._net_id:
                cnt += 1; continue
            if c.get("network") == self._name:
                cnt += 1; continue
            if self._ipnet and c.get("ip"):
                try:
                    if ipaddress.ip_address(c["ip"]) in self._ipnet:
                        cnt += 1; continue
                except Exception:
                    pass
        self._state = cnt
        # Build attributes
        leases = 0
        clients = self._client.get_clients() or []
        if getattr(self, "_ipnet", None):
            import ipaddress
            for c in clients:
                ip = c.get("ip")
                if not ip:
                    continue
                try:
                    if ipaddress.ip_address(ip) in self._ipnet:
                        leases += 1
                except Exception:
                    continue
        self._attrs = {
            "network_id": getattr(self, "_net_id", None),
            "name": getattr(self, "_name", None),
            "vlan_id": getattr(self, "_net", {}).get("vlan") if hasattr(self, "_net") else None,
            "subnet": getattr(self, "_subnet", None) if hasattr(self, "_subnet") else getattr(self, "_subnet_str", None),
            "ip_leases": leases,
        }

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

class UnifiWlanSensor(SensorEntity):
    _attr_icon = "mdi:wifi"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT
    def __init__(self, client: UniFiOSClient, wlan: Dict[str, Any]):
        self._client = client
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        self._attr_name = f"WLAN {self._ssid}"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_wlan_{self._ssid}_clients"
        self._state: StateType = 0
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        cnt = 0
        clients = self._client.get_clients() or []
        for c in clients:
            ssid = c.get("essid") or c.get("wifi_network") or c.get("ap_essid")
            if ssid == self._ssid:
                cnt += 1
        self._state = cnt
        netmap = {};
        try:
            if hasattr(self._client, 'get_network_map'):
                netmap = self._client.get_network_map()
            else:
                nets = self._client.get_networks() or []
                netmap = {str(n.get('_id') or n.get('id')): n for n in nets}
        except Exception:
            netmap = {}
        net_name = self._wlan.get("network") or (self._wlan.get("networkconf_id") and (netmap.get(str(self._wlan.get("networkconf_id"))) or {}).get("name"))
        vlan_id = (netmap.get(str(self._wlan.get("networkconf_id"))) or {}).get("vlan")
        security = self._wlan.get("security") or self._wlan.get("x_security") or self._wlan.get("wpa_mode")
        self._attrs = {"network": net_name, "vlan_id": vlan_id, "security": security}

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

class UnifiVpnServerSensor(SensorEntity):
    _attr_icon = "mdi:account-lock"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT
    def __init__(self, client: UniFiOSClient, peer: Dict[str, Any], idx: int):
        self._client = client
        self._peer = peer
        name = peer.get("name") or peer.get("peer_name") or peer.get("description") or f"VPN-Server-{idx}"
        self._name = name
        self._attr_name = f"VPN {name}"
        self._role = 'server'
        self._attr_unique_id = f"unifigw_{client.instance_key()}_vpn_server_{peer.get('_id') or peer.get('id') or idx}"
        self._state: StateType = 0
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def icon(self) -> str:
        try:
            return 'mdi:check-circle' if int(self._state or 0) > 0 else 'mdi:account-lock'
        except Exception:
            return 'mdi:account-lock'

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        self._attrs['role'] = getattr(self, '_role', None)
        return self._attrs

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        peers = self._client.get_vpn_servers() or []
        me = None
        for p in peers:
            pname = p.get("name") or p.get("peer_name") or p.get("description")
            if pname == self._name:
                me = p; break
        cnt = 0
        if me is not None:
            raw = me.get("num_clients") or me.get("clients") or me.get("connected_clients")
            if isinstance(raw, list):
                cnt = len(raw)
                self._attrs["clients"] = raw
            elif raw is not None:
                cnt = int(raw)
            # include some typical fields
            self._attrs.update({k: me.get(k) for k in ("vpn_type","interface","local_ip","status","state") if k in me})
        self._state = cnt


class UnifiVpnClientSensor(SensorEntity):
    _attr_icon = "mdi:lock"

    def __init__(self, client: UniFiOSClient, peer: Dict[str, Any], idx: int):
        self._client = client
        self._peer = peer
        name = peer.get("name") or peer.get("peer_name") or peer.get("description") or f"VPN-Client-{idx}"
        self._name = name
        self._attr_name = f"VPN {name}"
        self._role = "client"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_vpn_client_{peer.get('_id') or peer.get('id') or idx}"
        self._state: StateType = "UNKNOWN"
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def icon(self) -> str:
        s = (self._state or "").upper()
        if s in ("CONNECTED","UP","OK","ONLINE"):
            return "mdi:check-circle"
        if s in ("ERROR","DOWN","DISCONNECTED","FAIL"):
            return "mdi:alert-circle"
        return "mdi:lock"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        self._attrs["role"] = "client"
        return self._attrs

    def update(self) -> None:
        me = self._peer
        status = "UNKNOWN"
        if me is not None:
            if isinstance(me.get("connected"), bool):
                status = "CONNECTED" if me.get("connected") else "DISCONNECTED"
            status = (me.get("status") or me.get("state") or status) or status
            status = str(status).upper()
            # attributes
            self._attrs.update({k: me.get(k) for k in ("name","server_addr","remote_ip","peer_addr","tunnel_ip","vpn_type","interface") if k in me})
            for k in ("subnet","tunnel_network","client_subnet"):
                if me.get(k):
                    self._attrs["subnet"] = me.get(k)
                    break
        self._state = status

class UnifiSpeedtestBase(SensorEntity):
    async def async_added_to_hass(self) -> None:
        # trigger first measurement schedule (no more than once per hour)
        if hasattr(self._client, 'maybe_start_speedtest'):
            try:
                await self.hass.async_add_executor_job(self._client.maybe_start_speedtest, 3600)
            except Exception:
                pass

    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(self, client: UniFiOSClient, kind: str):
        self._client = client
        self._kind = kind  # 'down'|'up'|'ping'
        self._attr_name = f"Speedtest {'Download' if kind=='down' else ('Upload' if kind=='up' else 'Ping')}"
        self._attr_unique_id = f"unifigw_{client.instance_key()}_speedtest_{kind}"
        self._state: StateType = None
        self._attrs: Dict[str, Any] = {}

    @property
    def native_value(self) -> StateType:
        return self._state

    @property
    def icon(self) -> str:
        return "mdi:progress-download" if self._kind=='down' else ("mdi:progress-upload" if self._kind=='up' else "mdi:progress-clock")

    @property
    def native_unit_of_measurement(self) -> Optional[str]:
        return "Mbps" if self._kind in ("down","up") else "ms"

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        return self._attrs

    @Throttle(MIN_TIME_BETWEEN_UPDATES)
    def update(self) -> None:
        # Guard if client doesn't have speedtest helpers yet
        if not hasattr(self._client, 'get_last_speedtest') or not hasattr(self._client, 'maybe_start_speedtest') or not hasattr(self._client, 'now'):
            self._state = None
            self._attrs = {}
            return
        rec = self._client.get_last_speedtest(cache_sec=20)
        now = self._client.now()
        if rec is None:
            try:
                self._client.maybe_start_speedtest(3600)
                rec = self._client.get_last_speedtest(cache_sec=1)
            except Exception:
                rec = None
        stale = True
        if rec and isinstance(rec, dict) and rec.get('rundate'):
            stale = (now - (rec['rundate']/1000.0)) > 3600  # > 1h
        # autorun no more than hourly
        if stale:
            self._client.maybe_start_speedtest(cooldown_sec=3600)
            rec = self._client.get_last_speedtest(cache_sec=20)

        # fill state
        self._attrs = {
            "source": rec.get("source") if rec else None,
            "rundate": rec.get("rundate") if rec else None,
            "server": rec.get("server") if rec else None,
            "status": rec.get("status") if rec else None,
        }
        if not rec:
            self._state = None
            return
        if self._kind == "down":
            val = rec.get("download_mbps")
        elif self._kind == "up":
            val = rec.get("upload_mbps")
        else:
            val = rec.get("latency_ms")
        self._state = None if val is None else (round(float(val), 2) if self._kind!="ping" else round(float(val),1))


class UnifiSpeedtestDownloadSensor(UnifiSpeedtestBase):
    def __init__(self, client: UniFiOSClient):
        super().__init__(client, "down")


class UnifiSpeedtestUploadSensor(UnifiSpeedtestBase):
    def __init__(self, client: UniFiOSClient):
        super().__init__(client, "up")


class UnifiSpeedtestPingSensor(UnifiSpeedtestBase):
    def __init__(self, client: UniFiOSClient):
        super().__init__(client, "ping")
