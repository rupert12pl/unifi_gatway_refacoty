from __future__ import annotations

import ipaddress
from typing import Any, Dict, Iterable, List, Optional

from homeassistant.components.sensor import SensorEntity, SensorStateClass
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN
from .coordinator import UniFiGatewayData, UniFiGatewayDataUpdateCoordinator
from .unifi_client import UniFiOSClient


SUBSYSTEM_SENSORS: Dict[str, tuple[str, str]] = {
    "wan": ("WAN", "mdi:shield-outline"),
    "lan": ("LAN", "mdi:lan"),
    "wlan": ("WLAN", "mdi:wifi"),
    "vpn": ("VPN", "mdi:folder-key-network"),
}


async def async_setup_entry(
    hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback
) -> None:
    data = hass.data[DOMAIN][entry.entry_id]
    client: UniFiOSClient = data["client"]
    coordinator: UniFiGatewayDataUpdateCoordinator = data["coordinator"]

    static_entities: List[SensorEntity] = []
    for subsystem, (label, icon) in SUBSYSTEM_SENSORS.items():
        static_entities.append(
            UniFiGatewaySubsystemSensor(coordinator, client, subsystem, label, icon)
        )
    static_entities.append(UniFiGatewayAlertsSensor(coordinator, client))
    static_entities.append(UniFiGatewayFirmwareSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestDownloadSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestUploadSensor(coordinator, client))
    static_entities.append(UniFiGatewaySpeedtestPingSensor(coordinator, client))

    async_add_entities(static_entities)

    known_wan: set[str] = set()
    known_lan: set[str] = set()
    known_wlan: set[str] = set()
    known_vpn_servers: set[str] = set()
    known_vpn_clients: set[str] = set()

    def _sync_dynamic() -> None:
        coordinator_data: Optional[UniFiGatewayData] = coordinator.data
        if coordinator_data is None:
            return

        new_entities: List[SensorEntity] = []

        for link in coordinator_data.wan_links:
            link_id = str(link.get("id"))
            if link_id in known_wan:
                continue
            known_wan.add(link_id)
            new_entities.extend(
                [
                    UniFiGatewayWanStatusSensor(coordinator, client, link),
                    UniFiGatewayWanIpSensor(coordinator, client, link),
                    UniFiGatewayWanIspSensor(coordinator, client, link),
                ]
            )

        for network in coordinator_data.lan_networks:
            net_id = str(network.get("_id") or network.get("id") or network.get("name"))
            if net_id in known_lan:
                continue
            known_lan.add(net_id)
            new_entities.append(
                UniFiGatewayLanClientsSensor(coordinator, client, network)
            )

        for wlan in coordinator_data.wlans:
            ssid = wlan.get("name") or wlan.get("ssid")
            if not ssid:
                continue
            if ssid in known_wlan:
                continue
            known_wlan.add(ssid)
            new_entities.append(UniFiGatewayWlanClientsSensor(coordinator, client, wlan))

        for peer in coordinator_data.vpn_servers:
            peer_id = _vpn_peer_id(peer)
            if peer_id in known_vpn_servers:
                continue
            known_vpn_servers.add(peer_id)
            new_entities.append(
                UniFiGatewayVpnServerSensor(coordinator, client, peer)
            )

        for peer in coordinator_data.vpn_clients:
            peer_id = _vpn_peer_id(peer)
            if peer_id in known_vpn_clients:
                continue
            known_vpn_clients.add(peer_id)
            new_entities.append(
                UniFiGatewayVpnClientSensor(coordinator, client, peer)
            )

        if new_entities:
            async_add_entities(new_entities)

    _sync_dynamic()
    entry.async_on_unload(coordinator.async_add_listener(_sync_dynamic))


def _vpn_peer_id(peer: Dict[str, Any]) -> str:
    return str(
        peer.get("_id")
        or peer.get("id")
        or peer.get("name")
        or peer.get("peer_name")
        or peer.get("description")
        or "peer"
    )


class UniFiGatewaySensorBase(
    CoordinatorEntity[UniFiGatewayDataUpdateCoordinator], SensorEntity
):
    """Base entity for UniFi Gateway sensors."""

    _attr_should_poll = False

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        unique_id: str,
        name: str,
    ) -> None:
        super().__init__(coordinator)
        self._client = client
        self._attr_unique_id = unique_id
        self._attr_name = name
        self._default_icon = getattr(self, "_attr_icon", None)

    def _controller_attrs(self) -> Dict[str, Any]:
        data = self.coordinator.data
        if not data:
            return {}
        return {
            "controller_ui": data.controller.get("url"),
            "controller_site": data.controller.get("site"),
        }


class UniFiGatewaySubsystemSensor(UniFiGatewaySensorBase):
    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        subsystem: str,
        label: str,
        icon: str,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_{subsystem}"
        super().__init__(coordinator, client, unique_id, label)
        self._subsystem = subsystem
        self._attr_icon = icon
        self._default_icon = icon

    @property
    def native_value(self) -> Optional[Any]:
        data = self.coordinator.data
        if not data:
            return None
        record = data.health_by_subsystem.get(self._subsystem)
        if not record:
            return None
        status = record.get("status") or record.get("state")
        if isinstance(status, str):
            return status.upper()
        return status

    @property
    def icon(self) -> Optional[str]:
        status = str(self.native_value or "").lower()
        if status in {"ok", "online", "up", "healthy", "connected"}:
            return "mdi:check-circle"
        if status in {"warning", "notice", "degraded"}:
            return "mdi:alert"
        if status in {"error", "critical", "down", "offline", "disconnected"}:
            return "mdi:alert-circle"
        return self._default_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        record = data.health_by_subsystem.get(self._subsystem) if data else None
        attrs: Dict[str, Any] = {}
        if record:
            attrs.update({k: v for k, v in record.items() if k != "subsystem"})
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayAlertsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:information-outline"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_alerts"
        super().__init__(coordinator, client, unique_id, "Alerts")

    @property
    def native_value(self) -> Optional[int]:
        data = self.coordinator.data
        if not data:
            return None
        return len(data.alerts)

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        attrs = {"alerts": data.alerts if data else []}
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayFirmwareSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:database-plus"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_firmware"
        super().__init__(coordinator, client, unique_id, "Firmware Upgradable")

    @property
    def native_value(self) -> Optional[int]:
        data = self.coordinator.data
        if not data:
            return None
        return len([dev for dev in data.devices if dev.get("upgradable")])

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        upgradable = [
            {
                "name": dev.get("name") or dev.get("mac"),
                "model": dev.get("model"),
                "version": dev.get("version"),
            }
            for dev in (data.devices if data else [])
            if dev.get("upgradable")
        ]
        attrs = {"devices": upgradable}
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanStatusSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:shield-outline"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        self._link_id = str(link.get("id"))
        self._link_name = link.get("name") or self._link_id
        unique_id = f"unifigw_{client.instance_key()}_wan_{self._link_id}_status"
        super().__init__(coordinator, client, unique_id, f"WAN {self._link_name}")
        self._default_icon = "mdi:shield-outline"

    def _link(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for link in data.wan_links:
            if str(link.get("id")) == self._link_id:
                return link
        return None

    @property
    def native_value(self) -> Optional[Any]:
        link = self._link()
        if not link:
            return None
        status = link.get("status") or link.get("state")
        if isinstance(status, str):
            return status.upper()
        return status

    @property
    def icon(self) -> Optional[str]:
        status = str(self.native_value or "").lower()
        if status in {"up", "ok", "connected", "online"}:
            return "mdi:check-circle"
        if status in {"down", "error", "fail", "disconnected", "offline"}:
            return "mdi:alert-circle"
        return self._default_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link() or {}
        data = self.coordinator.data
        attrs = {
            "name": self._link_name,
            "type": link.get("type") or link.get("kind"),
            "isp": link.get("isp") or link.get("provider"),
            "ip": link.get("ip") or link.get("wan_ip") or link.get("ipv4"),
        }
        if data:
            for record in data.wan_health:
                attrs.setdefault(
                    "isp",
                    record.get("isp")
                    or record.get("provider")
                    or record.get("isp_name"),
                )
                attrs.setdefault(
                    "ip",
                    record.get("wan_ip")
                    or record.get("internet_ip")
                    or record.get("ip"),
                )
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIpSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:ip"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        self._link_id = str(link.get("id"))
        self._link_name = link.get("name") or self._link_id
        self._last_ip: Optional[str] = None
        unique_id = f"unifigw_{client.instance_key()}_wan_{self._link_id}_ip"
        super().__init__(coordinator, client, unique_id, f"WAN {self._link_name} IP")

    def _link(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for link in data.wan_links:
            if str(link.get("id")) == self._link_id:
                return link
        return None

    @property
    def native_value(self) -> Optional[str]:
        link = self._link()
        ip = (
            link.get("ip")
            or link.get("wan_ip")
            or link.get("ipv4")
            if link
            else None
        )
        if ip:
            self._last_ip = ip
        return ip

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        attrs = {"last_ip": self._last_ip}
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWanIspSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:domain"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        link: Dict[str, Any],
    ) -> None:
        self._link_id = str(link.get("id"))
        self._link_name = link.get("name") or self._link_id
        self._last_isp: Optional[str] = None
        unique_id = f"unifigw_{client.instance_key()}_wan_{self._link_id}_isp"
        super().__init__(coordinator, client, unique_id, f"WAN {self._link_name} ISP")

    def _link(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for link in data.wan_links:
            if str(link.get("id")) == self._link_id:
                return link
        return None

    @property
    def native_value(self) -> Optional[str]:
        link = self._link()
        isp = link.get("isp") or link.get("provider") if link else None
        if isp:
            self._last_isp = isp
        return isp

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        link = self._link() or {}
        attrs = {
            "last_isp": self._last_isp,
            "organization": link.get("isp_name")
            or link.get("isp_organization")
            or link.get("organization"),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayLanClientsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:lan"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        network: Dict[str, Any],
    ) -> None:
        self._network = network
        self._network_id = str(network.get("_id") or network.get("id") or network.get("name"))
        self._network_name = network.get("name") or f"VLAN {network.get('vlan')}"
        self._subnet = (
            network.get("subnet")
            or network.get("ip_subnet")
            or network.get("cidr")
        )
        self._ip_network = _to_ip_network(self._subnet)
        unique_id = (
            f"unifigw_{client.instance_key()}_lan_{self._network_id}_clients"
        )
        super().__init__(
            coordinator,
            client,
            unique_id,
            f"LAN {self._network_name}",
        )

    def _matches_client(self, client: Dict[str, Any]) -> bool:
        if str(client.get("network_id")) == self._network_id:
            return True
        if (
            client.get("network")
            and client.get("network").lower() == self._network_name.lower()
        ):
            return True
        if self._ip_network and client.get("ip"):
            try:
                if ipaddress.ip_address(client["ip"]) in self._ip_network:
                    return True
            except ValueError:
                return False
        return False

    def _clients(self) -> Iterable[Dict[str, Any]]:
        data = self.coordinator.data
        return data.clients if data else []

    @property
    def native_value(self) -> Optional[int]:
        return sum(1 for client in self._clients() if self._matches_client(client))

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        leases = sum(
            1
            for client in self._clients()
            if self._matches_client(client) and client.get("ip")
        )
        attrs = {
            "network_id": self._network_id,
            "subnet": self._subnet,
            "vlan_id": self._network.get("vlan"),
            "ip_leases": leases,
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayWlanClientsSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:wifi"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        wlan: Dict[str, Any],
    ) -> None:
        self._wlan = wlan
        self._ssid = wlan.get("name") or wlan.get("ssid") or "WLAN"
        unique_id = f"unifigw_{client.instance_key()}_wlan_{self._ssid}_clients"
        super().__init__(coordinator, client, unique_id, f"WLAN {self._ssid}")

    def _clients(self) -> Iterable[Dict[str, Any]]:
        data = self.coordinator.data
        return data.clients if data else []

    @property
    def native_value(self) -> Optional[int]:
        count = 0
        for client in self._clients():
            ssid = (
                client.get("essid")
                or client.get("wifi_network")
                or client.get("ap_essid")
            )
            if ssid == self._ssid:
                count += 1
        return count

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        net_id = self._wlan.get("networkconf_id")
        netmap = data.network_map if data else {}
        network = netmap.get(str(net_id)) if net_id else None
        attrs = {
            "network": network.get("name") if network else self._wlan.get("network"),
            "vlan_id": network.get("vlan") if network else None,
            "security": self._wlan.get("security")
            or self._wlan.get("x_security")
            or self._wlan.get("wpa_mode"),
            "enabled": self._wlan.get("enabled", True),
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayVpnServerSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:account-lock"
    _attr_native_unit_of_measurement = "clients"
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        peer: Dict[str, Any],
    ) -> None:
        self._peer_name = (
            peer.get("name") or peer.get("peer_name") or peer.get("description")
        )
        self._peer_id = _vpn_peer_id(peer)
        name = self._peer_name or f"VPN Server {self._peer_id}"
        unique_id = f"unifigw_{client.instance_key()}_vpn_server_{self._peer_id}"
        super().__init__(coordinator, client, unique_id, f"VPN {name}")

    def _record(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for record in data.vpn_servers:
            if _vpn_peer_id(record) == self._peer_id:
                return record
        return None

    @property
    def native_value(self) -> Optional[int]:
        record = self._record()
        if not record:
            return None
        raw = (
            record.get("num_clients")
            or record.get("clients")
            or record.get("connected_clients")
        )
        if isinstance(raw, list):
            return len(raw)
        if raw is not None:
            try:
                return int(raw)
            except (TypeError, ValueError):
                return None
        return 0

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        record = self._record() or {}
        attrs = {
            "role": "server",
            "vpn_type": record.get("vpn_type"),
            "interface": record.get("interface"),
            "local_ip": record.get("local_ip"),
            "status": record.get("status") or record.get("state"),
        }
        if isinstance(record.get("clients"), list):
            attrs["clients"] = record["clients"]
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewayVpnClientSensor(UniFiGatewaySensorBase):
    _attr_icon = "mdi:lock"

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        peer: Dict[str, Any],
    ) -> None:
        self._peer_id = _vpn_peer_id(peer)
        self._peer_name = (
            peer.get("name") or peer.get("peer_name") or peer.get("description")
        )
        name = self._peer_name or f"VPN Client {self._peer_id}"
        unique_id = f"unifigw_{client.instance_key()}_vpn_client_{self._peer_id}"
        super().__init__(coordinator, client, unique_id, f"VPN {name}")

    def _record(self) -> Optional[Dict[str, Any]]:
        data = self.coordinator.data
        if not data:
            return None
        for record in data.vpn_clients:
            if _vpn_peer_id(record) == self._peer_id:
                return record
        return None

    @property
    def native_value(self) -> Optional[str]:
        record = self._record()
        if not record:
            return None
        if isinstance(record.get("connected"), bool):
            return "CONNECTED" if record.get("connected") else "DISCONNECTED"
        status = record.get("status") or record.get("state")
        return status.upper() if isinstance(status, str) else status

    @property
    def icon(self) -> Optional[str]:
        status = str(self.native_value or "").upper()
        if status in {"CONNECTED", "UP", "ONLINE", "OK"}:
            return "mdi:check-circle"
        if status in {"DOWN", "DISCONNECTED", "ERROR", "FAIL"}:
            return "mdi:alert-circle"
        return self._attr_icon

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        record = self._record() or {}
        attrs = {
            "role": "client",
            "server_addr": record.get("server_addr"),
            "remote_ip": record.get("remote_ip"),
            "peer_addr": record.get("peer_addr"),
            "tunnel_ip": record.get("tunnel_ip"),
            "vpn_type": record.get("vpn_type"),
            "interface": record.get("interface"),
        }
        for key in ("subnet", "tunnel_network", "client_subnet"):
            if record.get(key):
                attrs["subnet"] = record.get(key)
                break
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewaySpeedtestSensor(UniFiGatewaySensorBase):
    _attr_state_class = SensorStateClass.MEASUREMENT

    def __init__(
        self,
        coordinator: UniFiGatewayDataUpdateCoordinator,
        client: UniFiOSClient,
        kind: str,
        label: str,
    ) -> None:
        unique_id = f"unifigw_{client.instance_key()}_speedtest_{kind}"
        super().__init__(coordinator, client, unique_id, label)
        self._kind = kind

    @property
    def extra_state_attributes(self) -> Dict[str, Any]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        attrs = {
            "source": record.get("source") if record else None,
            "rundate": record.get("rundate") if record else None,
            "server": record.get("server") if record else None,
            "status": record.get("status") if record else None,
        }
        attrs.update(self._controller_attrs())
        return attrs


class UniFiGatewaySpeedtestDownloadSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-download"
    _attr_native_unit_of_measurement = "Mbps"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "down", "Speedtest Download")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("download_mbps") is not None:
            return round(float(record["download_mbps"]), 2)
        return None


class UniFiGatewaySpeedtestUploadSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-upload"
    _attr_native_unit_of_measurement = "Mbps"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "up", "Speedtest Upload")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("upload_mbps") is not None:
            return round(float(record["upload_mbps"]), 2)
        return None


class UniFiGatewaySpeedtestPingSensor(UniFiGatewaySpeedtestSensor):
    _attr_icon = "mdi:progress-clock"
    _attr_native_unit_of_measurement = "ms"

    def __init__(
        self, coordinator: UniFiGatewayDataUpdateCoordinator, client: UniFiOSClient
    ) -> None:
        super().__init__(coordinator, client, "ping", "Speedtest Ping")

    @property
    def native_value(self) -> Optional[float]:
        data = self.coordinator.data
        record = data.speedtest if data else None
        if record and record.get("latency_ms") is not None:
            return round(float(record["latency_ms"]), 1)
        return None


def _to_ip_network(value: Optional[str]):
    if not value:
        return None
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
