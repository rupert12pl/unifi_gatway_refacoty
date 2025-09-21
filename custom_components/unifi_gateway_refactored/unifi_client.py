
from __future__ import annotations

import hashlib
import logging
import socket
import time
from typing import Any, Dict, List, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlsplit


def _normalize_peer_field(peer: Dict[str, Any], *keys: str) -> Optional[str]:
    for key in keys:
        value = peer.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
            continue
        return str(value)
    return None


def vpn_peer_identity(peer: Dict[str, Any]) -> str:
    """Return a stable identifier for a VPN peer/server/client record."""

    direct = _normalize_peer_field(peer, "_id", "id")
    if direct:
        return direct

    uuid = _normalize_peer_field(
        peer, "uuid", "peer_uuid", "peer_id", "server_id", "client_id"
    )
    name = _normalize_peer_field(
        peer, "name", "peer_name", "description", "display_name"
    )
    interface = _normalize_peer_field(peer, "interface", "ifname")
    address = _normalize_peer_field(
        peer,
        "server_addr",
        "server_address",
        "local_ip",
        "remote_ip",
        "peer_addr",
        "gateway",
        "tunnel_ip",
        "tunnel_network",
    )

    if uuid and name:
        return f"{name}_{uuid}"
    if uuid:
        return uuid
    if name and interface:
        return f"{name}_{interface}"
    if name and address:
        return f"{name}_{address}"
    if interface and address:
        return f"{interface}_{address}"
    if name:
        return name
    if interface:
        return interface
    if address:
        return address
    return "peer"

_LOGGER = logging.getLogger(__name__)


class APIError(Exception):
    """Base exception raised when the UniFi controller returns an error."""


class AuthError(APIError):
    """Authentication against the UniFi OS API failed."""


class ConnectivityError(APIError):
    """The controller could not be reached."""


class UniFiOSClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        site_id: str = "default",
        ssl_verify: bool = False,
        use_proxy_prefix: bool = True,
        timeout: int = 10,
        instance_hint: str | None = None,
    ):
        self._host = host
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._site = site_id
        self._username = username
        self._password = password
        self._port = port

        self._session = requests.Session()
        retries = Retry(
            total=5,
            connect=5,
            read=3,
            backoff_factor=0.4,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
        )
        self._session.mount("https://", HTTPAdapter(max_retries=retries))
        self._session.headers.update({"Accept": "application/json"})

        try:
            socket.getaddrinfo(host, None)
        except socket.gaierror as ex:
            raise ConnectivityError(f"DNS resolution failed for {host}: {ex}") from ex

        prefix = "/proxy/network" if use_proxy_prefix else ""
        self._base = f"https://{host}:{port}{prefix}/api/s/{site_id}"

        basis = f"{self._base}|{host}|{site_id}|{instance_hint or ''}"
        self._iid = hashlib.sha1(basis.encode()).hexdigest()[:12]

        self._csrf: Optional[str] = None
        self._login(host, port, ssl_verify, timeout)
        self._ensure_connected()

    # ----------- auth / base detection -----------
    def _login(self, host: str, port: int, ssl_verify: bool, timeout: int):
        roots = [f"https://{host}:{port}", f"https://{host}"]
        for root in roots:
            for ep in ("/api/auth/login", "/api/login", "/auth/login"):
                url = f"{root}{ep}"
                try:
                    r = self._session.post(
                        url,
                        json={"username": self._username, "password": self._password, "rememberMe": True},
                        verify=ssl_verify, timeout=timeout
                    )
                    if 200 <= r.status_code < 300:
                        csrf = (
                            r.headers.get("x-csrf-token")
                            or r.headers.get("X-CSRF-Token")
                            or r.cookies.get("csrf_token")
                        )
                        if csrf:
                            self._session.headers["x-csrf-token"] = csrf
                        _LOGGER.info("Logged into UniFi OS via %s", url)
                        return
                except requests.RequestException:
                    continue
        raise AuthError("Failed to authenticate with provided username/password")

    def _ensure_connected(self):
        try:
            self._request("GET", f"{self._base}/stat/health")
            return
        except APIError:
            pass
        prefixes = ["/proxy/network", "/network", ""]
        ports = [443, 8443]
        for pr in prefixes:
            for po in ports:
                base_api = f"https://{self._host}:{po}{pr}/api/s/{self._site}"
                try:
                    self._request("GET", f"{base_api}/stat/health")
                    self._base = base_api
                    self._port = po
                    _LOGGER.info("Autodetected base: %s", self._base)
                    return
                except APIError:
                    continue
        for pr in prefixes:
            for po in ports:
                root_api = f"https://{self._host}:{po}{pr}/api"
                try:
                    sites = self._request("GET", f"{root_api}/self/sites")
                    names = [s.get("name") for s in sites if isinstance(s, dict)]
                except APIError:
                    continue
                for candidate in [self._site] + [n for n in names if n and n != self._site]:
                    base_api = f"{root_api}/s/{candidate}"
                    try:
                        self._request("GET", f"{base_api}/stat/health")
                        self._site = candidate
                        self._base = base_api
                        self._port = po
                        _LOGGER.info("Autodetected via sites: %s (site=%s)", self._base, self._site)
                        return
                    except APIError:
                        continue

    # ----------- http helpers -----------
    def _request(
        self,
        method: str,
        url: str,
        payload: Optional[Dict[str, Any]] = None,
    ) -> Any:
        try:
            r = self._session.request(
                method,
                url,
                json=payload,
                verify=self._ssl_verify,
                timeout=self._timeout,
            )
        except requests.RequestException as ex:
            raise ConnectivityError(f"Request error: {ex}") from ex
        if r.status_code in (401, 403):
            raise AuthError(f"Auth failed at {url}")
        if r.status_code >= 400:
            raise APIError(f"HTTP {r.status_code}: {r.text[:200]} at {url}")
        if not r.content:
            return None
        try:
            data = r.json()
        except ValueError:
            raise APIError(f"Invalid JSON from {url}")
        return data.get("data") if isinstance(data, dict) and "data" in data else data

    def _get(self, path: str):
        return self._request("GET", f"{self._base}/{path.lstrip('/')}")

    def _post(self, path: str, payload: Optional[Dict[str, Any]] = None):
        return self._request("POST", f"{self._base}/{path.lstrip('/')}", payload)

    # ----------- public helpers used by sensors / diagnostics -----------
    def ping(self) -> Dict[str, Any]:
        health = self._get("stat/health") or []
        return {"ok": True, "health_count": len(health), "base": self._base, "site": self._site}

    def get_healthinfo(self):
        return self._get("stat/health")

    def get_devices(self):
        return self._get("stat/device")

    def get_alerts(self):
        try:
            return self._get("list/alert")
        except APIError:
            return self._get("list/alarm")

    def list_sites(self):
        root = self._base.split("/api/s/")[0] + "/api"
        return self._request("GET", f"{root}/self/sites")

    def get_networks(self) -> List[Dict[str, Any]]:
        for path in ("rest/networkconf", "list/networkconf"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    return data
            except APIError:
                continue
        return []

    def get_wlans(self) -> List[Dict[str, Any]]:
        for path in ("list/wlanconf", "rest/wlanconf"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    return data
            except APIError:
                continue
        return []

    def get_clients(self) -> List[Dict[str, Any]]:
        for path in ("stat/sta", "stat/user", "list/user", "stat/clients", "stat/alluser"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    return data
            except APIError:
                continue
        return []

    def get_wan_links(self) -> List[Dict[str, Any]]:
        """Return list of WAN links. Robust to various controller versions."""
        paths = [
            "internet/wan",
            "internet",
            "list/wan",
            "stat/wan",
        ]
        for path in paths:
            try:
                data = self._get(path)
            except Exception:
                continue
            # dict with nested lists
            if isinstance(data, dict):
                for k in ("wans", "wan_links", "links", "interfaces"):
                    v = data.get(k)
                    if isinstance(v, list) and v:
                        return [x for x in v if isinstance(x, dict)]
            # direct list
            if isinstance(data, list) and data:
                return [x for x in data if isinstance(x, dict)]
        # fallback: derive from networks marked as WAN
        nets = []
        try:
            nets = self.get_networks() or []
        except Exception:
            nets = []
        out = []
        for n in nets:
            purpose = (n.get("purpose") or n.get("role") or "").lower()
            name = n.get("name") or n.get("display_name") or ""
            if "wan" in purpose or n.get("wan_network") or "wan" in (name or "").lower():
                out.append({"id": n.get("_id") or n.get("id") or name, "name": name, "type": "wan"})
        return out

    def _extract_dict_records(self, data: Any) -> List[Dict[str, Any]]:
        """Flatten arbitrarily nested mappings/lists into a list of dict records."""

        out: List[Dict[str, Any]] = []
        stack: List[Any] = [data]
        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                if any(
                    key in current
                    for key in (
                        "vpn_type",
                        "peer_name",
                        "name",
                        "interface",
                        "server_addr",
                        "local_ip",
                        "tunnel_ip",
                    )
                ):
                    # keep dict-like records while still traversing nested structures
                    out.append(current)
                for value in current.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(current, list):
                for item in current:
                    if isinstance(item, (dict, list)):
                        stack.append(item)
        return out

    def get_vpn_servers(self) -> List[Dict[str, Any]]:
        """Return configured VPN servers (WireGuard/OpenVPN Remote User)."""
        probes = [
            "internet/vpn/peers",
            "internet/vpn/servers",
            "internet/vpn/server",
            "stat/vpn",
            "list/remoteuser",
            "list/vpn",
        ]
        servers: List[Dict[str, Any]] = []
        for path in probes:
            try:
                data = self._get(path)
            except Exception:
                continue
            if isinstance(data, list):
                servers.extend([d for d in data if isinstance(d, dict)])
            elif isinstance(data, dict):
                servers.extend(self._extract_dict_records(data))
        uniq: Dict[str, Dict[str, Any]] = {}
        for d in servers:
            if not isinstance(d, dict):
                continue
            peer_id = vpn_peer_identity(d)
            normalized = dict(d)
            normalized["_ha_peer_id"] = peer_id
            uniq[peer_id] = normalized
        return list(uniq.values())

    def get_vpn_clients(self) -> List[Dict[str, Any]]:
        """Return configured VPN client tunnels (policy-based/route-based)."""
        probes = [
            "internet/vpn/clients",
            "internet/vpn/client",
            "stat/vpn",
            "list/vpn",
        ]
        out: List[Dict[str, Any]] = []
        for path in probes:
            try:
                data = self._get(path)
            except Exception:
                continue
            if isinstance(data, list):
                out.extend([d for d in data if isinstance(d, dict)])
            elif isinstance(data, dict):
                out.extend(self._extract_dict_records(data))
        uniq: Dict[str, Dict[str, Any]] = {}
        for d in out:
            if not isinstance(d, dict):
                continue
            peer_id = vpn_peer_identity(d)
            normalized = dict(d)
            normalized["_ha_peer_id"] = peer_id
            uniq[peer_id] = normalized
        return list(uniq.values())

    def instance_key(self) -> str:
        return self._iid

    def get_controller_url(self):
        parts = urlsplit(self._base)
        hostname = parts.hostname or self._host
        port = parts.port or self._port
        netloc = hostname
        if port and port not in (443, None):
            netloc = f"{hostname}:{port}"
        return f"{parts.scheme}://{netloc}/login?redirect=%2Fdashboard"

    def get_controller_api_url(self):
        return self._base.split("/api", 1)[0].rstrip("/")

    def get_site(self) -> str:
        return self._site

    def get_network_map(self) -> Dict[str, Dict[str, Any]]:
        """Map networkconf_id -> metadata for quick lookups from WLANs/clients."""

        nets = self.get_networks() or []
        out: Dict[str, Dict[str, Any]] = {}
        for n in nets:
            nid = n.get("_id") or n.get("id")
            if not nid:
                continue
            out[str(nid)] = {
                "id": nid,
                "name": n.get("name"),
                "vlan": n.get("vlan"),
                "subnet": n.get("subnet") or n.get("ip_subnet") or n.get("cidr"),
                "purpose": n.get("purpose") or n.get("role"),
            }
        return out

    def now(self) -> float:
        return time.time()

    # ---- Speedtest helpers (base-relative) ----
    def get_gateway_mac(self) -> Optional[str]:
        try:
            devs = self.get_devices()
        except Exception:
            devs = None
        for d in devs or []:
            t = (d.get("type") or "").lower()
            m = (d.get("model") or "").lower()
            if t in ("ugw","udm") or m.startswith("udm") or "gateway" in (d.get("name") or "").lower():
                mac = d.get("mac") or d.get("device_mac")
                if mac:
                    return mac
        try:
            hi = self.get_healthinfo()
            for sub in hi or []:
                if sub.get("subsystem") == "www":
                    mac = sub.get("gw_mac") or sub.get("gw-mac") or sub.get("wan_ip_gw_mac")
                    if mac:
                        return mac
        except Exception:
            pass
        return None

    def start_speedtest(self, mac: Optional[str] = None):
        if mac is None:
            mac = self.get_gateway_mac()
        payload = {"cmd": "speedtest"}
        if mac:
            payload["mac"] = mac
        try:
            return self._post("cmd/devmgr", payload)
        except Exception:
            return self._post("internet/speedtest/run", {})

    def get_speedtest_status(self, mac: Optional[str] = None):
        if mac is None:
            mac = self.get_gateway_mac()
        payload = {"cmd": "speedtest-status"}
        if mac:
            payload["mac"] = mac
        try:
            return self._post("cmd/devmgr", payload)
        except Exception:
            try:
                return self._get("internet/speedtest/status")
            except Exception:
                return self._post("internet/speedtest/status", {})

    def get_speedtest_history(self, start_ms: Optional[int] = None, end_ms: Optional[int] = None):
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - 7 * 24 * 60 * 60 * 1000
        try:
            return self._post(
                "stat/report/archive.speedtest",
                {
                    "attrs": [
                        "xput_download",
                        "xput_upload",
                        "latency",
                        "rundate",
                        "server",
                    ],
                    "start": start_ms,
                    "end": end_ms,
                },
            )
        except Exception:
            data = self._get("internet/speedtest/results")
            return data if isinstance(data, list) else []

    def _normalize_speedtest_record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        dl = rec.get("xput_download", rec.get("download", rec.get("xput_down")))
        ul = rec.get("xput_upload", rec.get("upload", rec.get("xput_up")))
        ping = rec.get("latency", rec.get("ping", rec.get("speedtest_ping")))
        if dl is not None:
            out["download_mbps"] = float(dl)
        if ul is not None:
            out["upload_mbps"] = float(ul)
        if ping is not None:
            out["latency_ms"] = float(ping)
        if "rundate" in rec:
            out["rundate"] = rec["rundate"]
        if "server" in rec:
            out["server"] = rec["server"]
        if "status" in rec:
            out["status"] = rec["status"]
        return out

    def get_last_speedtest(self, cache_sec: int = 20) -> Optional[Dict[str, Any]]:
        now = time.time()
        if getattr(self, "_st_cache", None) and (now - self._st_cache[0]) < cache_sec:
            return self._st_cache[1]
        rec = None
        try:
            st = self.get_speedtest_status()
            rec = st[0] if isinstance(st, list) and st else (st if isinstance(st, dict) else None)
            if rec:
                out = self._normalize_speedtest_record(rec)
                out["source"] = "status"
                self._st_cache = (now, out)
                return out
        except Exception:
            pass
        try:
            hist = self.get_speedtest_history()
            if isinstance(hist, list) and hist:
                latest = sorted(
                    [r for r in hist if isinstance(r, dict)],
                    key=lambda r: r.get("rundate", 0),
                    reverse=True,
                )
                if latest:
                    out = self._normalize_speedtest_record(latest[0])
                    out["source"] = "history"
                    self._st_cache = (now, out)
                    return out
        except Exception:
            pass
        self._st_cache = (now, None)
        return None

    def maybe_start_speedtest(self, cooldown_sec: int = 3600) -> None:
        now = time.time()
        last = getattr(self, "_st_last_trigger", 0.0)
        if now - last < cooldown_sec:
            return
        try:
            self.start_speedtest(self.get_gateway_mac())
            self._st_last_trigger = now
        except Exception:
            return
