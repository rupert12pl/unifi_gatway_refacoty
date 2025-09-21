
from __future__ import annotations

import hashlib
import logging
import re
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from urllib.parse import urlsplit
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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
        peer,
        "uuid",
        "peer_uuid",
        "peer_id",
        "server_id",
        "client_id",
        "remote_user_id",
        "remoteuser_id",
        "user_id",
        "userid",
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
    fingerprint_sources: List[str] = []
    for key in sorted(peer):
        if not isinstance(key, str) or key.startswith("_"):
            continue
        value = peer[key]
        if value in (None, "", [], {}):
            continue
        if isinstance(value, (int, float, bool)):
            fingerprint_sources.append(f"{key}={value}")
        elif isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                fingerprint_sources.append(f"{key}={cleaned}")
        elif isinstance(value, list):
            fingerprint_sources.append(f"{key}#len={len(value)}")
    if fingerprint_sources:
        basis = "|".join(fingerprint_sources)
        return f"peer_{hashlib.sha1(basis.encode()).hexdigest()[:12]}"
    return f"peer_{hashlib.sha1(str(sorted(peer.items())).encode()).hexdigest()[:12]}"

_LOGGER = logging.getLogger(__name__)

_SERVER_FIELD_RE = re.compile(r"([A-Za-z0-9_]+)\s*:")

_VPN_RECORD_KEYS = {
    "_id",
    "id",
    "uuid",
    "peer_uuid",
    "peer_id",
    "peerid",
    "server_id",
    "client_id",
    "remote_user_id",
    "remoteuser_id",
    "user_id",
    "userid",
    "name",
    "peer_name",
    "display_name",
    "description",
    "vpn_name",
    "vpn_type",
    "type",
    "role",
    "interface",
    "ifname",
    "server_addr",
    "server_address",
    "local_ip",
    "remote_ip",
    "peer_addr",
    "gateway",
    "tunnel_ip",
    "tunnel_network",
    "subnet",
    "client_subnet",
    "client_networks",
    "allowed_ips",
    "peer_config",
    "endpoint",
    "endpoints",
    "peer_endpoint",
    "peer_host",
    "peer_ip",
    "listen_port",
    "port",
    "server_port",
    "remote_port",
    "public_ip",
    "profile",
    "profile_name",
    "remote_user",
    "remote_user_vpn",
    "connection_name",
    "via_vpn",
    "network",
    "networks",
}


def _normalize_token(value: Any) -> Optional[str]:
    """Return a slug-like lower-case token for matching categories."""

    if value in (None, "", [], {}):
        return None
    text = str(value).strip().lower()
    if not text:
        return None
    token = "".join(ch if ch.isalnum() else "_" for ch in text)
    # collapse multiple separators
    while "__" in token:
        token = token.replace("__", "_")
    return token.strip("_") or None

_SERVER_ROLE_KEYS = {
    "server",
    "servers",
    "remote_user",
    "remote_users",
    "remoteuser",
    "remoteusers",
    "wgserver",
    "wgservers",
    "peer",
    "peers",
}

_CLIENT_ROLE_KEYS = {
    "client",
    "clients",
    "vpnclient",
    "vpnclients",
    "wgclient",
    "wgclients",
    "tunnel",
    "tunnels",
    "connection",
    "connections",
}


def _classify_vpn_record(
    record: Dict[str, Any], role_hint: Optional[str] = None
) -> Tuple[str, str, Optional[str]]:
    """Return the detected Home Assistant role/category/template tuple for VPN records."""

    template_token = None
    for key in (
        "template",
        "vpn_template",
        "profile",
        "profile_name",
        "group",
        "category",
    ):
        token = _normalize_token(record.get(key))
        if token:
            template_token = token
            break

    tokens: List[str] = []
    if template_token:
        tokens.append(template_token)
    for key in ("role", "type", "vpn_type", "mode", "purpose"):
        token = _normalize_token(record.get(key))
        if token:
            tokens.append(token)
    if role_hint:
        token = _normalize_token(role_hint)
        if token:
            tokens.append(token)

    role: Optional[str] = None
    category: Optional[str] = None

    for token in tokens:
        if not token:
            continue
        if any(
            candidate in token
            for candidate in (
                "site_to_site",
                "site-to-site",
                "site_to-site",
                "site2site",
                "s2s",
                "vpn_s2s",
                "uid_vpn",
                "uidvpn",
            )
        ):
            category = "site_to_site"
            role = "site_to_site"
            break

    if category is None:
        for token in tokens:
            if token and "teleport" in token:
                category = "teleport"
                role = "client"
                break

    if category is None:
        for token in tokens:
            if token and "uid" in token:
                category = "uid"
                role = "site_to_site"
                break

    if category is None:
        for token in tokens:
            if token and any(candidate in token for candidate in ("client", "policy", "pbr", "route")):
                category = "client"
                role = "client"
                break

    if category is None:
        for token in tokens:
            if token and any(candidate in token for candidate in ("server", "remote", "user")):
                category = "server"
                role = "server"
                break

    if category is None:
        # fallback to hint if we still did not classify the record
        token = _normalize_token(role_hint)
        if token:
            if token in {"server", "client", "site_to_site"}:
                category = token
                role = token
            elif token == "site":
                category = "site_to_site"
                role = "site_to_site"

    if category is None:
        category = "client" if role_hint == "client" else "server"

    if role is None:
        role = "client" if category in {"client", "teleport"} else category

    return role, category, template_token


def _parse_speedtest_server_details(server: Any) -> Dict[str, Any]:
    """Convert the server representation returned by the controller to a dict."""

    if isinstance(server, dict):
        details: Dict[str, Any] = {}
        for key, value in server.items():
            if not isinstance(key, str):
                continue
            if value in (None, ""):
                continue
            details[key.lower()] = value
        return details

    if isinstance(server, str):
        matches = list(_SERVER_FIELD_RE.finditer(server))
        if not matches:
            return {}
        details = {}
        for idx, match in enumerate(matches):
            key = match.group(1).lower()
            start = match.end()
            end = matches[idx + 1].start() if idx + 1 < len(matches) else len(server)
            value = server[start:end].strip(" ,")
            if value:
                details[key] = value
        return details

    return {}


def _coerce_float(value: Any) -> Optional[float]:
    """Best-effort conversion of a value to float."""

    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().replace(",", ".")
        if not cleaned:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _format_speedtest_rundate(value: Any) -> Optional[str]:
    """Convert the rundate to a human readable 24h datetime string."""

    if value is None:
        return None

    timestamp: Optional[float] = None

    if isinstance(value, (int, float)):
        timestamp = float(value)
    elif isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        iso_candidate = cleaned.replace("Z", "+00:00") if cleaned.endswith("Z") else cleaned
        try:
            dt_value = datetime.fromisoformat(iso_candidate)
        except ValueError:
            digits_only = cleaned.replace(" ", "").replace(",", "")
            try:
                timestamp = float(digits_only)
            except ValueError:
                return cleaned
        else:
            if dt_value.tzinfo is not None:
                dt_value = dt_value.astimezone(timezone.utc)
            return dt_value.strftime("%Y-%m-%d %H:%M:%S")

    if timestamp is None:
        return None

    if timestamp > 1e12:
        timestamp /= 1000.0

    try:
        dt_value = datetime.fromtimestamp(timestamp, tz=timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt_value.strftime("%Y-%m-%d %H:%M:%S")


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
        username: str | None = None,
        password: str | None = None,
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
        if not self._username or not self._password:
            raise AuthError("Provide username and password for UniFi controller")

        self._login(host, port, ssl_verify, timeout)
        self._ensure_connected()

    # ----------- auth / base detection -----------
    def _login(self, host: str, port: int, ssl_verify: bool, timeout: int):
        roots = [f"https://{host}:{port}", f"https://{host}"]
        for root in roots:
            for ep in ("/api/auth/login", "/api/login", "/auth/login"):
                url = f"{root}{ep}"
                try:
                    _LOGGER.debug("Attempting UniFi OS login via endpoint %s", url)
                    r = self._session.post(
                        url,
                        json={
                            "username": self._username,
                            "password": self._password,
                            "rememberMe": True,
                        },
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
                except requests.RequestException as err:
                    _LOGGER.debug(
                        "Login attempt against %s raised a transport error: %s",
                        url,
                        err,
                        exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                    )
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
        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "UniFi request %s %s (payload=%s)",
                method,
                url,
                "yes" if payload else "no",
            )
        try:
            r = self._session.request(
                method,
                url,
                json=payload,
                verify=self._ssl_verify,
                timeout=self._timeout,
            )
        except requests.RequestException as ex:
            _LOGGER.error("Transport error during UniFi request %s %s: %s", method, url, ex)
            raise ConnectivityError(f"Request error: {ex}") from ex
        _LOGGER.debug(
            "UniFi response for %s %s: HTTP %s", method, url, r.status_code
        )
        if r.status_code in (401, 403):
            _LOGGER.error("Authentication failed for UniFi request %s %s", method, url)
            raise AuthError(f"Auth failed at {url}")
        if r.status_code >= 400:
            _LOGGER.error(
                "HTTP error %s for UniFi request %s %s: %s",
                r.status_code,
                method,
                url,
                r.text[:200],
            )
            raise APIError(f"HTTP {r.status_code}: {r.text[:200]} at {url}")
        if not r.content:
            return None
        try:
            data = r.json()
        except ValueError:
            _LOGGER.error("Invalid JSON received from UniFi request %s %s", method, url)
            raise APIError(f"Invalid JSON from {url}")
        return data.get("data") if isinstance(data, dict) and "data" in data else data

    def _get(self, path: str):
        _LOGGER.debug("GET %s", path)
        return self._request("GET", f"{self._base}/{path.lstrip('/')}")

    def _post(self, path: str, payload: Optional[Dict[str, Any]] = None):
        _LOGGER.debug("POST %s", path)
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
            alerts = self._get("list/alert")
            _LOGGER.debug(
                "Fetched %s alert records from list/alert",
                len(alerts) if isinstance(alerts, list) else "unknown",
            )
            return alerts
        except APIError as err:
            _LOGGER.warning(
                "Fetching list/alert failed (%s); attempting legacy list/alarm endpoint",
                err,
            )
            legacy_alerts = self._get("list/alarm")
            _LOGGER.debug(
                "Fetched %s alert records from list/alarm",
                len(legacy_alerts)
                if isinstance(legacy_alerts, list)
                else "unknown",
            )
            return legacy_alerts

    def list_sites(self):
        root = self._base.split("/api/s/")[0] + "/api"
        sites = self._request("GET", f"{root}/self/sites")
        _LOGGER.debug(
            "Controller returned %s sites", len(sites) if isinstance(sites, list) else "unknown"
        )
        return sites

    def get_networks(self) -> List[Dict[str, Any]]:
        for path in ("rest/networkconf", "list/networkconf"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    _LOGGER.debug(
                        "Fetched %s networks via %s", len(data), path
                    )
                    return data
                _LOGGER.debug(
                    "Endpoint %s returned %s instead of list for networks",
                    path,
                    type(data).__name__,
                )
            except APIError as err:
                _LOGGER.debug(
                    "Network fetch via %s failed: %s",
                    path,
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                continue
        _LOGGER.warning("No network configuration data returned by controller")
        return []

    def get_wlans(self) -> List[Dict[str, Any]]:
        for path in ("list/wlanconf", "rest/wlanconf"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    _LOGGER.debug(
                        "Fetched %s WLAN configurations via %s", len(data), path
                    )
                    return data
                _LOGGER.debug(
                    "Endpoint %s returned %s instead of list for WLANs",
                    path,
                    type(data).__name__,
                )
            except APIError as err:
                _LOGGER.debug(
                    "WLAN fetch via %s failed: %s",
                    path,
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                continue
        _LOGGER.warning("No WLAN configuration data returned by controller")
        return []

    def get_clients(self) -> List[Dict[str, Any]]:
        for path in ("stat/sta", "stat/user", "list/user", "stat/clients", "stat/alluser"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    _LOGGER.debug(
                        "Fetched %s clients via %s", len(data), path
                    )
                    return data
                _LOGGER.debug(
                    "Endpoint %s returned %s instead of list for clients",
                    path,
                    type(data).__name__,
                )
            except APIError as err:
                _LOGGER.debug(
                    "Client fetch via %s failed: %s",
                    path,
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                continue
        _LOGGER.warning("No client data returned by controller")
        return []

    def get_wan_links(self) -> List[Dict[str, Any]]:
        """Return list of WAN links. Robust to various controller versions."""
        paths = [
            "internet/wan",
            "internet",
            "list/wan",
            "stat/wan",
        ]
        _LOGGER.debug("Attempting WAN link discovery via endpoints: %s", ", ".join(paths))
        for path in paths:
            try:
                data = self._get(path)
            except Exception as err:
                _LOGGER.debug(
                    "WAN link fetch via %s failed: %s",
                    path,
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                continue
            # dict with nested lists
            if isinstance(data, dict):
                for k in ("wans", "wan_links", "links", "interfaces"):
                    v = data.get(k)
                    if isinstance(v, list) and v:
                        _LOGGER.debug(
                            "WAN link data discovered via %s.%s (%s entries)",
                            path,
                            k,
                            len(v),
                        )
                        return [x for x in v if isinstance(x, dict)]
            # direct list
            if isinstance(data, list) and data:
                _LOGGER.debug(
                    "WAN link data discovered via %s (%s entries)",
                    path,
                    len(data),
                )
                return [x for x in data if isinstance(x, dict)]
        # fallback: derive from networks marked as WAN
        nets = []
        try:
            nets = self.get_networks() or []
        except Exception as err:
            _LOGGER.warning(
                "Falling back to deriving WAN links from networks due to error: %s",
                err,
            )
            nets = []
        out = []
        for n in nets:
            purpose = (n.get("purpose") or n.get("role") or "").lower()
            name = n.get("name") or n.get("display_name") or ""
            if "wan" in purpose or n.get("wan_network") or "wan" in (name or "").lower():
                out.append({"id": n.get("_id") or n.get("id") or name, "name": name, "type": "wan"})
        if out:
            _LOGGER.debug(
                "Derived %s WAN links from network configuration fallback", len(out)
            )
        else:
            _LOGGER.error("Unable to determine WAN links from controller data")
        return out

    def _flatten_vpn_records(
        self, data: Any, role_hint: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Flatten nested VPN API responses into a list of peer dicts."""

        records: List[Dict[str, Any]] = []
        stack: List[Tuple[Any, Optional[str]]] = [(data, role_hint)]
        while stack:
            current, current_role = stack.pop()
            if isinstance(current, dict):
                normalized_role = current_role
                raw_role = current.get("role")
                if isinstance(raw_role, str) and raw_role.strip():
                    normalized_role = raw_role.strip().lower()
                elif isinstance(current.get("type"), str):
                    type_hint = current["type"].strip().lower()
                    if "client" in type_hint and not normalized_role:
                        normalized_role = "client"
                    elif any(token in type_hint for token in ("server", "remote", "user")) and not normalized_role:
                        normalized_role = "server"
                elif isinstance(current.get("vpn_type"), str):
                    vpn_type = current["vpn_type"].strip().lower()
                    if "client" in vpn_type and not normalized_role:
                        normalized_role = "client"
                    elif any(token in vpn_type for token in ("server", "remote")) and not normalized_role:
                        normalized_role = "server"

                has_scalar = any(
                    not isinstance(value, (dict, list))
                    and value not in (None, "", [], {})
                    for value in current.values()
                )
                has_vpn_keys = any(
                    key in current and current[key] not in (None, "", [], {})
                    for key in _VPN_RECORD_KEYS
                )
                if has_vpn_keys and has_scalar:
                    normalized = dict(current)
                    if normalized_role and not normalized.get("role"):
                        normalized["role"] = normalized_role
                    records.append(normalized)

                for key, value in current.items():
                    if not isinstance(value, (dict, list)):
                        continue
                    next_role = normalized_role
                    if isinstance(key, str):
                        lowered = key.strip().lower()
                        if lowered in _SERVER_ROLE_KEYS:
                            next_role = "server"
                        elif lowered in _CLIENT_ROLE_KEYS:
                            next_role = "client"
                    stack.append((value, next_role))
            elif isinstance(current, list):
                for item in current:
                    stack.append((item, current_role))
        return records

    def _collect_vpn_records(
        self,
        probes: List[str],
        role_hint: Optional[str],
        role_filter: Optional[set[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Collect VPN records from multiple API probes with optional role hint."""

        found: List[Dict[str, Any]] = []
        errors: Dict[str, Exception] = {}
        for path in probes:
            try:
                data = self._get(path)
            except Exception as err:  # broad: controller versions vary widely
                _LOGGER.debug(
                    "VPN probe %s failed during %s fetch: %s",
                    path,
                    role_hint or "vpn",
                    err,
                    exc_info=_LOGGER.isEnabledFor(logging.DEBUG),
                )
                errors[path] = err
                continue

            flattened = self._flatten_vpn_records(data, role_hint)
            fallback_used = False
            if not flattened:
                legacy_records = self._legacy_vpn_records(data)
                if legacy_records:
                    flattened = legacy_records
                    fallback_used = True

            if flattened:
                _LOGGER.debug(
                    "VPN probe %s returned %s candidate records for %s%s",
                    path,
                    len(flattened),
                    role_hint or "vpn",
                    " via legacy parser" if fallback_used else "",
                )
                if fallback_used:
                    _LOGGER.warning(
                        "VPN probe %s required legacy parser fallback for %s records",
                        path,
                        role_hint or "vpn",
                    )
            else:
                _LOGGER.debug(
                    "VPN probe %s returned no candidate records for %s (raw type=%s)",
                    path,
                    role_hint or "vpn",
                    type(data).__name__,
                )
            found.extend(flattened)

        uniq: Dict[str, Dict[str, Any]] = {}
        filtered_out = 0
        for record in found:
            if not isinstance(record, dict):
                continue
            normalized = dict(record)
            if role_hint and not normalized.get("role"):
                normalized["role"] = role_hint
            peer_id = vpn_peer_identity(normalized)
            role, category, template = _classify_vpn_record(normalized, role_hint)
            normalized_role = role or normalized.get("role")
            if normalized_role:
                normalized["role"] = normalized_role
            normalized["_ha_role"] = normalized_role
            normalized["_ha_category"] = category
            normalized["_ha_template"] = template or category
            normalized["_ha_legacy_peer_id"] = peer_id
            suffix = _normalize_token(category) or _normalize_token(normalized_role) or "vpn"
            identity = f"{peer_id}::{suffix}" if suffix else peer_id
            normalized["_ha_peer_id"] = identity
            if role_filter:
                allowed = {value for value in role_filter if value}
                if normalized_role not in allowed and category not in allowed and suffix not in allowed:
                    filtered_out += 1
                    continue
            uniq[identity] = normalized

        if _LOGGER.isEnabledFor(logging.DEBUG):
            category_counts: Dict[str, int] = {}
            for record in uniq.values():
                category = record.get("_ha_category") or record.get("role") or "unknown"
                category_counts[category] = category_counts.get(category, 0) + 1
            stats = ", ".join(
                f"{category}={count}" for category, count in sorted(category_counts.items())
            ) or "none"
            _LOGGER.debug(
                "Collected %s VPN %s records (filtered_out=%s): %s",
                len(uniq),
                role_hint or "records",
                filtered_out,
                stats,
            )
        elif not uniq:
            if errors:
                error_summary = ", ".join(
                    f"{path} ({err})" for path, err in sorted(errors.items())
                )
                _LOGGER.warning(
                    "No VPN %s records discovered; probe errors: %s",
                    role_hint or "records",
                    error_summary,
                )
            else:
                _LOGGER.info(
                    "No VPN %s records discovered from controller probes",
                    role_hint or "records",
                )

        return list(uniq.values())

    def _legacy_vpn_records(self, data: Any) -> List[Dict[str, Any]]:
        """Fallback parser for VPN records when the structured parser finds none."""

        if data in (None, "", [], {}):
            return []

        records: List[Dict[str, Any]] = []
        seen: set[int] = set()
        stack: List[Any] = [data]

        while stack:
            current = stack.pop()
            if isinstance(current, dict):
                obj_id = id(current)
                if obj_id in seen:
                    continue
                seen.add(obj_id)
                has_vpn_key = any(
                    key in current and current.get(key) not in (None, "", [], {})
                    for key in _VPN_RECORD_KEYS
                )
                if has_vpn_key:
                    records.append(current)
                for value in current.values():
                    if isinstance(value, (dict, list)):
                        stack.append(value)
            elif isinstance(current, list):
                obj_id = id(current)
                if obj_id in seen:
                    continue
                seen.add(obj_id)
                for item in current:
                    if isinstance(item, (dict, list)):
                        stack.append(item)

        if _LOGGER.isEnabledFor(logging.DEBUG):
            _LOGGER.debug(
                "Legacy VPN parser extracted %s records", len(records)
            )

        return records

    def get_vpn_servers(self) -> List[Dict[str, Any]]:
        """Return configured VPN servers (WireGuard/OpenVPN Remote User)."""
        probes = [
            "internet/vpn/peers",
            "internet/vpn/servers",
            "internet/vpn/server",
            "internet/vpn/site-to-site",
            "stat/vpn",
            "list/remoteuser",
            "list/vpn",
            "rest/vpnserver",
            "rest/vpnservers",
            "rest/wgserver",
            "rest/wgservers",
            "rest/wireguard/server",
        ]
        servers = self._collect_vpn_records(probes, "server", {"server"})
        _LOGGER.debug("Returning %s VPN server records", len(servers))
        if not servers:
            _LOGGER.warning("Controller returned no VPN server records")
        return servers

    def get_vpn_clients(self) -> List[Dict[str, Any]]:
        """Return configured VPN client tunnels (policy-based/route-based)."""
        probes = [
            "internet/vpn/clients",
            "internet/vpn/client",
            "internet/vpn/site-to-site",
            "stat/vpn",
            "list/vpn",
            "rest/vpnclient",
            "rest/vpnclients",
            "rest/wgclient",
            "rest/wgclients",
            "rest/wireguard/client",
        ]
        clients = self._collect_vpn_records(probes, "client", {"client", "teleport"})
        _LOGGER.debug("Returning %s VPN client records", len(clients))
        if not clients:
            _LOGGER.warning("Controller returned no VPN client records")
        return clients

    def get_vpn_site_to_site(self) -> List[Dict[str, Any]]:
        """Return configured Site-to-Site tunnels (IPSec/UID)."""

        probes = [
            "internet/vpn/clients",
            "internet/vpn/client",
            "internet/vpn/site-to-site",
            "stat/vpn",
            "list/vpn",
            "rest/vpnclient",
            "rest/vpnclients",
            "rest/wgclient",
            "rest/wgclients",
            "rest/wireguard/client",
        ]
        tunnels = self._collect_vpn_records(
            probes, "site_to_site", {"site_to_site", "uid"}
        )
        _LOGGER.debug("Returning %s VPN site-to-site records", len(tunnels))
        if not tunnels:
            _LOGGER.warning("Controller returned no site-to-site VPN records")
        return tunnels

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
            formatted_rundate = _format_speedtest_rundate(rec["rundate"])
            out["rundate"] = (
                formatted_rundate if formatted_rundate is not None else rec["rundate"]
            )
        if "server" in rec:
            server_raw = rec["server"]
            out["server"] = server_raw
            server_details = _parse_speedtest_server_details(server_raw)

            def _assign(detail_key: str, source_keys: List[str], *, converter=None) -> None:
                for key in source_keys:
                    if key not in server_details:
                        continue
                    value = server_details[key]
                    if isinstance(value, str):
                        value = value.strip()
                    if value in (None, ""):
                        continue
                    if converter is not None:
                        converted = converter(value)
                        if converted is not None:
                            out[detail_key] = converted
                        else:
                            out[detail_key] = value
                    else:
                        out[detail_key] = value
                    return

            _assign("server_cc", ["cc"])
            _assign("server_city", ["city", "name"])
            _assign("server_country", ["country"])
            _assign("server_lat", ["lat", "latitude"], converter=_coerce_float)
            _assign("server_long", ["long", "lon", "lng"], converter=_coerce_float)
            _assign("server_provider", ["provider", "sponsor"])
            _assign("server_provider_url", ["provider_url", "url"])
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
