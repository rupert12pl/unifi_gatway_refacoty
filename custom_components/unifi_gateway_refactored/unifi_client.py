
from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
import asyncio
from dataclasses import dataclass, field
from typing import Any, Collection, Dict, Iterable, List, Optional, Tuple

import requests
from urllib.parse import urlsplit
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .const import DEFAULT_SITE

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
        digest = hashlib.sha256(basis.encode()).hexdigest()
        return f"peer_{digest[:12]}"
    digest = hashlib.sha256(str(sorted(peer.items())).encode()).hexdigest()
    return f"peer_{digest[:12]}"

LOGGER = logging.getLogger(__name__)
_LOGGER = LOGGER


@dataclass(slots=True)
class VpnAttempt:
    """Record describing a VPN configuration fetch attempt."""

    path: str
    status: int
    ok: bool
    snippet: str


@dataclass(slots=True)
class VpnConfigList:
    """Aggregated VPN configuration payload for a UniFi site."""

    remote_users: List[Dict[str, Any]]
    s2s_peers: List[Dict[str, Any]]
    teleport_servers: List[Dict[str, Any]]
    teleport_clients: List[Dict[str, Any]]
    attempts: List[VpnAttempt] = field(default_factory=list)
    winner_paths: Dict[str, str] = field(default_factory=dict)


_REDACT_KEYS = (
    "password",
    "token",
    "cookie",
    "secret",
    "psk",
    "passphrase",
    "private_key",
    "key",
)

_REDACT_PATTERNS = [
    re.compile(rf"(\"?{key}\"?\s*[:=]\s*)(\"[^\"]*\"|[^,;\s]+)", re.IGNORECASE)
    for key in _REDACT_KEYS
]


def _redact_text(text: str) -> str:
    """Redact common secret tokens from log/output snippets."""

    if not text:
        return ""
    redacted = text
    for pattern in _REDACT_PATTERNS:
        redacted = pattern.sub(r"\1***", redacted)
    return redacted


def _enabled_flag(record: Dict[str, Any]) -> bool:
    """Return True if the record appears enabled."""

    for key in ("enabled", "is_enabled", "active", "up"):
        value = record.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, bool):
            return value
        if isinstance(value, (int, float)):
            return bool(value)
        if isinstance(value, str):
            token = value.strip().lower()
            if not token:
                continue
            if token in {"on", "enabled", "enable", "active", "up", "true", "1"}:
                return True
            if token in {"off", "disabled", "disable", "inactive", "down", "false", "0"}:
                return False
    for key in ("disabled", "is_disabled"):
        value = record.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, bool):
            return not value
        if isinstance(value, (int, float)):
            return not bool(value)
        if isinstance(value, str):
            token = value.strip().lower()
            if token:
                return token not in {"1", "true", "yes", "on"}
    return True


def _pick_type(record: Dict[str, Any]) -> Optional[str]:
    """Return a normalized VPN type token if available."""

    for key in ("vpn_type", "type", "protocol", "mode"):
        value = record.get(key)
        if isinstance(value, str) and value.strip():
            token = value.strip().lower()
            if "wireguard" in token:
                return "wireguard"
            if token in {"l2tp", "pptp", "openvpn"}:
                return token
            if "ipsec" in token:
                return "ipsec"
            if "teleport" in token:
                return "teleport"
            return token
    return None


def _compose_identifier(record: Dict[str, Any]) -> str:
    """Return a stable identifier for a normalized VPN record."""

    direct = _normalize_peer_field(record, "_id", "id")
    if direct:
        return direct
    return vpn_peer_identity(record)


def _normalize_remote_user(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return sanitized remote access VPN user metadata."""

    normalized: Dict[str, Any] = {
        "id": _compose_identifier(record),
        "enabled": _enabled_flag(record),
    }

    name = _normalize_peer_field(
        record, "name", "user", "username", "display_name", "description"
    )
    if name:
        normalized["name"] = name

    type_token = _pick_type(record)
    if type_token:
        normalized["type"] = type_token

    profile = _normalize_peer_field(record, "profile", "profile_name")
    if profile:
        normalized["profile"] = profile

    return normalized


def _normalize_s2s_peer(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return sanitized site-to-site VPN peer metadata."""

    normalized: Dict[str, Any] = {
        "id": _compose_identifier(record),
        "enabled": _enabled_flag(record),
    }

    name = _normalize_peer_field(
        record, "name", "peer_name", "description", "display_name"
    )
    if name:
        normalized["name"] = name

    type_token = _pick_type(record)
    if type_token:
        normalized["type"] = type_token

    remote_addr = _normalize_peer_field(
        record,
        "peer_addr",
        "peer_ip",
        "remote_ip",
        "remote",
        "remote_address",
        "remote_host",
    )
    if remote_addr:
        normalized["remote"] = remote_addr

    local_addr = _normalize_peer_field(
        record,
        "server_addr",
        "server_address",
        "local_ip",
        "local",
        "gateway",
    )
    if local_addr:
        normalized["local"] = local_addr

    networks: List[str] = []
    for key in ("client_subnet", "client_networks", "allowed_ips", "network", "networks"):
        networks.extend(_vpn_network_strings(record.get(key)))
    if networks:
        normalized["networks"] = sorted({net for net in networks if net})

    return normalized


def _normalize_teleport_server(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return sanitized Teleport server metadata."""

    normalized: Dict[str, Any] = {
        "id": _compose_identifier(record),
        "enabled": _enabled_flag(record),
    }

    name = _normalize_peer_field(
        record, "name", "server_name", "display_name", "description"
    )
    if name:
        normalized["name"] = name

    address = _normalize_peer_field(record, "server_addr", "server_address", "public_ip")
    if address:
        normalized["remote"] = address

    type_token = _pick_type(record)
    if type_token:
        normalized["type"] = type_token

    return normalized


def _normalize_teleport_client(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return sanitized Teleport client metadata."""

    normalized: Dict[str, Any] = {
        "id": _compose_identifier(record),
        "enabled": _enabled_flag(record),
    }

    name = _normalize_peer_field(
        record, "name", "client_name", "display_name", "description"
    )
    if name:
        normalized["name"] = name

    remote_addr = _normalize_peer_field(record, "client_addr", "client_ip", "remote_ip")
    if remote_addr:
        normalized["remote"] = remote_addr

    type_token = _pick_type(record)
    if type_token:
        normalized["type"] = type_token

    return normalized


_VPN_EXPECTED_ERROR_CODES: Tuple[int, ...] = (400, 404)

_VPN_CONTAINER_KEYS = {
    "items",
    "item",
    "data",
    "records",
    "results",
    "list",
    "entries",
    "groups",
}

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


def _flatten_vpn_records(payload: Any) -> List[Dict[str, Any]]:
    """Extract dictionaries representing VPN records from arbitrary payloads."""

    if payload in (None, "", [], {}):
        return []

    results: List[Dict[str, Any]] = []
    stack: List[Any] = [payload]
    seen: set[int] = set()

    while stack:
        current = stack.pop()
        if isinstance(current, dict):
            obj_id = id(current)
            if obj_id in seen:
                continue
            seen.add(obj_id)
            if any(key in current for key in _VPN_RECORD_KEYS):
                results.append(current)
            for key in _VPN_CONTAINER_KEYS:
                value = current.get(key)
                if isinstance(value, (list, tuple)):
                    stack.extend(value)
                elif isinstance(value, dict):
                    stack.append(value)
            for value in current.values():
                if isinstance(value, (list, dict)):
                    stack.append(value)
        elif isinstance(current, (list, tuple, set)):
            for item in current:
                if isinstance(item, (dict, list, tuple, set)):
                    stack.append(item)
    return [record for record in results if isinstance(record, dict)]


def _vpn_network_strings(value: Any) -> List[str]:
    """Return flattened network/subnet strings from controller payloads."""

    if value in (None, "", [], {}):
        return []
    if isinstance(value, str):
        raw = value.replace(";", ",").replace("|", ",")
        parts = [part.strip() for part in raw.split(",") if part.strip()]
        if len(parts) == 1:
            parts = [part.strip() for part in raw.split() if part.strip()]
        return parts
    if isinstance(value, (list, tuple, set)):
        out: List[str] = []
        for item in value:
            out.extend(_vpn_network_strings(item))
        return out
    if isinstance(value, dict):
        out: List[str] = []
        for item in value.values():
            out.extend(_vpn_network_strings(item))
        return out
    return [str(value)]

_SERVER_ROLE_KEYS = {
    "server",
    "servers",
    "remote_user",
    "remote_users",
    "remoteuser",
    "remoteusers",
    "remote_access",
    "remoteaccess",
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
    "teleport",
    "tunnel",
    "tunnels",
    "connection",
    "connections",
}


def _coerce_int(value: Any) -> Optional[int]:
    """Best-effort conversion of controller payload values to int."""

    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return 1 if value else 0
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return int(float(cleaned))
        except ValueError:
            return None
    return None


def _extract_count(value: Any) -> Optional[int]:
    """Return the numeric count for client/session containers."""

    if value in (None, ""):
        return None
    if isinstance(value, list):
        return len(value)
    if isinstance(value, dict):
        for key in (
            "client_count",
            "connected_clients",
            "connected_count",
            "connected",
            "active",
            "num_clients",
            "num_client",
            "num_users",
            "num_active",
            "count",
            "value",
        ):
            count = _coerce_int(value.get(key))
            if count is not None:
                return count
        return None
    return _coerce_int(value)


def _first_value(data: Dict[str, Any], *keys: str) -> Optional[Any]:
    """Return the first non-empty value from ``data`` for ``keys``."""

    for key in keys:
        value = data.get(key)
        if value in (None, "", [], {}):
            continue
        if isinstance(value, str):
            cleaned = value.strip()
            if cleaned:
                return cleaned
            continue
        if isinstance(value, list):
            flattened = [
                str(item).strip()
                for item in value
                if item not in (None, "", [], {})
            ]
            if flattened:
                return ", ".join(flattened)
            continue
        return value
    return None


def _normalize_state_value(value: Any) -> Optional[str]:
    """Convert controller state fields to CONNECTED/DISCONNECTED/ERROR tokens."""

    if value in (None, "", [], {}):
        return None
    if isinstance(value, bool):
        return "CONNECTED" if value else "DISCONNECTED"
    if isinstance(value, (int, float)):
        return "CONNECTED" if value else "DISCONNECTED"
    if isinstance(value, str):
        token = value.strip().lower()
        if not token:
            return None
        mapping = {
            "connected": "CONNECTED",
            "up": "CONNECTED",
            "online": "CONNECTED",
            "ok": "CONNECTED",
            "established": "CONNECTED",
            "ready": "CONNECTED",
            "disconnected": "DISCONNECTED",
            "down": "DISCONNECTED",
            "offline": "DISCONNECTED",
            "inactive": "DISCONNECTED",
            "not_connected": "DISCONNECTED",
            "error": "ERROR",
            "failed": "ERROR",
            "fail": "ERROR",
            "critical": "ERROR",
        }
        if token in mapping:
            return mapping[token]
        if any(part in token for part in ("error", "fail", "fault")):
            return "ERROR"
        if any(part in token for part in ("connect", "online", "establish", "up")):
            return "CONNECTED"
        if any(part in token for part in ("discon", "down", "offline", "inactive")):
            return "DISCONNECTED"
        return token.upper()
    return str(value).upper()


def _peer_clients(record: Dict[str, Any]) -> Optional[List[Dict[str, Any]]]:
    """Return embedded client/session payloads if present."""

    for key in (
        "clients",
        "sessions",
        "active_sessions",
        "connected_clients",
        "users",
        "connected_users",
    ):
        value = record.get(key)
        if isinstance(value, list):
            return value
        if isinstance(value, dict):
            nested = value.get("data") or value.get("items") or value.get("list")
            if isinstance(nested, list):
                return nested
    return None


def _derive_peer_state(record: Dict[str, Any], client_count: Optional[int]) -> Optional[str]:
    """Determine the normalized connection state for a VPN peer."""

    for key in (
        "_ha_state",
        "state",
        "status",
        "connection_state",
        "connection_status",
    ):
        state = _normalize_state_value(record.get(key))
        if state:
            return state

    for key in ("connected", "is_connected", "up", "enabled_state"):
        normalized = _normalize_state_value(record.get(key))
        if normalized:
            return normalized

    if record.get("error") or record.get("error_code") or record.get("last_error"):
        return "ERROR"

    if client_count is not None:
        return "CONNECTED" if client_count > 0 else "DISCONNECTED"

    return None

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

    def __init__(
        self,
        message: str,
        *,
        status_code: Optional[int] = None,
        url: Optional[str] = None,
        expected: bool = False,
        body: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.url = url
        self.expected = expected
        self.body = body


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
        site_id: str = DEFAULT_SITE,
        ssl_verify: bool = False,
        use_proxy_prefix: bool = True,
        timeout: int = 10,
        vpn_family_override: str | None = None,
        instance_hint: str | None = None,
    ):
        self._scheme = "https"
        self._host = host
        self._port = port
        self._ssl_verify = ssl_verify
        self._timeout = timeout
        self._use_proxy_prefix = use_proxy_prefix
        self._path_prefix = "/proxy/network" if use_proxy_prefix else ""
        self._site_name = site_id
        self._site = site_id
        self._site_id: Optional[str] = None
        self._username = username
        self._password = password

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

        self._base = self._join(self._site_path())

        # Stable instance identifier – must NOT depend on autodetected _base so that
        # Home Assistant keeps existing entities when the controller path changes
        # between /proxy/network, /network and /v2 variants.
        basis = f"{self._net_base()}|{host}|{site_id}|{instance_hint or ''}"
        self._iid = hashlib.sha256(basis.encode()).hexdigest()[:12]

        self._csrf: Optional[str] = None
        if not self._username or not self._password:
            raise AuthError("Provide username and password for UniFi controller")

        self._login(host, port, ssl_verify, timeout)
        self._ensure_connected()
        self._vpn_family_override = vpn_family_override  # retained for option compatibility

    def _net_base(self) -> str:
        """Return the normalized base URL for UniFi Network requests."""

        base = f"{self._scheme}://{self._host}:{self._port}"
        prefix = self._path_prefix.strip("/")
        if prefix:
            return f"{base}/{prefix}"
        return base

    def _join(self, path: str) -> str:
        """Join ``path`` onto the normalized UniFi Network base."""

        base = self._net_base().rstrip("/")
        cleaned = str(path or "").lstrip("/")
        if cleaned.startswith("proxy/network/"):
            cleaned = cleaned[len("proxy/network/") :]
        if cleaned.startswith("network/") and self._path_prefix.strip("/") == "network":
            cleaned = cleaned[len("network/") :]
        prefix = self._path_prefix.strip("/")
        if prefix and cleaned.startswith(f"{prefix}/"):
            cleaned = cleaned[len(prefix) + 1 :]
        return f"{base}/{cleaned}" if cleaned else base

    def _site_path(self, path: str = "") -> str:
        """Return the controller API path for the configured site."""

        base = f"api/s/{self._site_name}".rstrip("/")
        if path:
            return f"{base}/{path.lstrip('/')}"
        return base

    def site_name(self) -> str:
        """Return the textual site name used for API requests."""

        return self._site_name

    def site_id(self) -> Optional[str]:
        """Return the cached GUID-style site identifier if known."""

        return self._site_id

    async def _async_ensure_site_id(self) -> Optional[str]:
        """Fetch and cache the GUID-style site identifier."""

        if self._site_id:
            return self._site_id

        candidates = [
            f"/v1/sites",
            f"/v2/api/site/{self._site_name}/info",
        ]

        for path in candidates:
            try:
                resp, text = await self._request("GET", path, timeout=6)
            except Exception as err:  # pragma: no cover - network guard
                LOGGER.debug("Site-id probe %s failed: %s", path, err)
                continue

            if resp.status_code >= 400:
                continue

            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:  # pragma: no cover - defensive
                LOGGER.debug("Invalid JSON while probing site id from %s", path)
                continue

            records: List[dict[str, Any]] = []
            if isinstance(payload, list):
                records = [item for item in payload if isinstance(item, dict)]
            elif isinstance(payload, dict):
                data = payload.get("data") or payload.get("sites") or payload.get("items")
                if isinstance(data, list):
                    records = [item for item in data if isinstance(item, dict)]
                elif isinstance(payload.get("site"), dict):
                    records = [payload["site"]]

            for record in records:
                name = record.get("name") or record.get("shortname")
                if isinstance(name, str) and name == self._site_name:
                    site_id = record.get("id") or record.get("_id") or record.get("uuid")
                    if isinstance(site_id, str) and site_id:
                        self._site_id = site_id
                        LOGGER.debug("Resolved site id %s for site %s", site_id, self._site_name)
                        return self._site_id

        LOGGER.debug("Falling back to site name for site-id lookups: %s", self._site_name)
        return None

    def _site_path_for(self, site: Optional[str], path: str = "") -> str:
        """Return the API path for a specific site without duplicate prefixes."""

        site_name = str(site or self._site_name or DEFAULT_SITE).strip() or DEFAULT_SITE
        base = f"api/s/{site_name}".rstrip("/")
        if path:
            return f"{base}/{path.lstrip('/')}"
        return base

    def _fetch_json(self, path: str) -> tuple[int, Any, str]:
        """Perform a UniFi GET request returning status, payload, and snippet."""

        url = self._join(path)
        try:
            response = self._session.get(
                url,
                verify=self._ssl_verify,
                timeout=self._timeout,
            )
        except requests.RequestException as err:
            snippet = _redact_text(str(err))
            _LOGGER.debug("VPN fetch error %s: %s", path, snippet)
            return 0, None, snippet

        text = response.text or ""
        snippet = _redact_text(text[:200])
        status = getattr(response, "status_code", 0)
        if 200 <= status < 300:
            _LOGGER.debug("VPN fetch %s -> %s", path, status)
        else:
            _LOGGER.debug("VPN fetch %s -> %s (snippet=%s)", path, status, snippet)

        data: Any = None
        if text:
            try:
                data = response.json()
            except ValueError:
                _LOGGER.debug("Invalid JSON for %s: %s", path, snippet)
                data = None

        return status, data, snippet

    @staticmethod
    def _collect_setting_lists(
        payload: Any,
        *,
        include: Iterable[str],
        require: Iterable[str] | None = None,
    ) -> List[Dict[str, Any]]:
        """Extract list entries from nested controller settings payloads."""

        include_tokens = [token.lower() for token in include]
        require_tokens = [token.lower() for token in (require or ())]
        effective_include = [
            token for token in include_tokens if token not in require_tokens
        ]
        results: List[Dict[str, Any]] = []
        seen: set[int] = set()

        def _walk(value: Any, context: tuple[str, ...] = ()) -> None:
            if isinstance(value, dict):
                for key, val in value.items():
                    next_context = context + (str(key).lower(),)
                    if isinstance(val, list):
                        joined = " ".join(next_context)
                        if effective_include and not any(
                            token in joined for token in effective_include
                        ):
                            pass
                        else:
                            if require_tokens and not all(
                                token in joined for token in require_tokens
                            ):
                                pass
                            else:
                                for item in val:
                                    if isinstance(item, dict):
                                        marker = id(item)
                                        if marker not in seen:
                                            seen.add(marker)
                                            results.append(item)
                    if isinstance(val, (dict, list)):
                        _walk(val, next_context)
            elif isinstance(value, list):
                for item in value:
                    _walk(item, context)

        _walk(payload)
        return results

    def _try_remote_users(
        self, site: str
    ) -> Tuple[List[Dict[str, Any]], List[VpnAttempt], Optional[str]]:
        attempts: List[VpnAttempt] = []
        winner: Optional[str] = None
        records: List[Dict[str, Any]] = []

        for relative in ("list/remoteuser", "stat/remote-user"):
            path = self._site_path_for(site, relative)
            status, payload, snippet = self._fetch_json(path)
            ok = 200 <= status < 300 and isinstance(payload, list)
            attempts.append(
                VpnAttempt(path=path, status=status, ok=ok, snippet=snippet)
            )
            if ok:
                records = [item for item in payload if isinstance(item, dict)]
                winner = path
                break

        if not records:
            path = f"v2/api/site/{site}/setting"
            status, payload, snippet = self._fetch_json(path)
            ok = 200 <= status < 300 and payload not in (None, "")
            attempts.append(
                VpnAttempt(path=path, status=status, ok=ok, snippet=snippet)
            )
            if ok:
                records = self._collect_setting_lists(
                    payload,
                    include=("remote_access", "remoteuser", "remote_user", "remote"),
                )
                if records:
                    winner = f"{path}#remote_access"

        normalized = [
            _normalize_remote_user(item)
            for item in records
            if isinstance(item, dict)
        ]
        return normalized, attempts, winner

    def _try_s2s_peers(
        self, site: str
    ) -> Tuple[List[Dict[str, Any]], List[VpnAttempt], Optional[str]]:
        attempts: List[VpnAttempt] = []
        winner: Optional[str] = None
        records: List[Dict[str, Any]] = []

        for relative in ("stat/s2speer", "stat/s2s"):
            path = self._site_path_for(site, relative)
            status, payload, snippet = self._fetch_json(path)
            ok = 200 <= status < 300 and isinstance(payload, list)
            attempts.append(
                VpnAttempt(path=path, status=status, ok=ok, snippet=snippet)
            )
            if ok:
                records = [item for item in payload if isinstance(item, dict)]
                winner = path
                break

        if not records:
            path = f"v2/api/site/{site}/setting"
            status, payload, snippet = self._fetch_json(path)
            ok = 200 <= status < 300 and payload not in (None, "")
            attempts.append(
                VpnAttempt(path=path, status=status, ok=ok, snippet=snippet)
            )
            if ok:
                records = self._collect_setting_lists(
                    payload,
                    include=("site_to_site", "s2s", "peer"),
                )
                if records:
                    winner = f"{path}#site_to_site"

        normalized = [
            _normalize_s2s_peer(item)
            for item in records
            if isinstance(item, dict)
        ]
        return normalized, attempts, winner

    def _try_teleport(
        self, site: str
    ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[VpnAttempt], Dict[str, str]]:
        attempts: List[VpnAttempt] = []
        winners: Dict[str, str] = {}
        server_records: List[Dict[str, Any]] = []
        client_records: List[Dict[str, Any]] = []

        server_path = self._site_path_for(site, "stat/teleport/servers")
        status, payload, snippet = self._fetch_json(server_path)
        ok = 200 <= status < 300 and isinstance(payload, list)
        attempts.append(
            VpnAttempt(path=server_path, status=status, ok=ok, snippet=snippet)
        )
        if ok:
            server_records = [item for item in payload if isinstance(item, dict)]
            winners["teleport_servers"] = server_path

        client_path = self._site_path_for(site, "stat/teleport/clients")
        status, payload, snippet = self._fetch_json(client_path)
        ok = 200 <= status < 300 and isinstance(payload, list)
        attempts.append(
            VpnAttempt(path=client_path, status=status, ok=ok, snippet=snippet)
        )
        if ok:
            client_records = [item for item in payload if isinstance(item, dict)]
            winners["teleport_clients"] = client_path

        if not server_records or not client_records:
            path = f"v2/api/site/{site}/setting"
            status, payload, snippet = self._fetch_json(path)
            ok = 200 <= status < 300 and payload not in (None, "")
            attempts.append(
                VpnAttempt(path=path, status=status, ok=ok, snippet=snippet)
            )
            if ok:
                if not server_records:
                    server_records = self._collect_setting_lists(
                        payload,
                        include=("teleport", "server"),
                        require=("teleport",),
                    )
                    if server_records:
                        winners["teleport_servers"] = f"{path}#teleport_servers"
                if not client_records:
                    client_records = self._collect_setting_lists(
                        payload,
                        include=("teleport", "client"),
                        require=("teleport",),
                    )
                    if client_records:
                        winners["teleport_clients"] = f"{path}#teleport_clients"

        servers = [
            _normalize_teleport_server(item)
            for item in server_records
            if isinstance(item, dict)
        ]
        clients = [
            _normalize_teleport_client(item)
            for item in client_records
            if isinstance(item, dict)
        ]
        return servers, clients, attempts, winners

    def get_vpn_config_list(self, site: Optional[str] = None) -> VpnConfigList:
        """Return configured VPN metadata for the provided site."""

        site_name = str(site or self._site_name or DEFAULT_SITE).strip() or DEFAULT_SITE

        remote_users, remote_attempts, remote_winner = self._try_remote_users(site_name)
        s2s_peers, s2s_attempts, s2s_winner = self._try_s2s_peers(site_name)
        teleport_servers, teleport_clients, teleport_attempts, teleport_winners = self._try_teleport(site_name)

        attempts = remote_attempts + s2s_attempts + teleport_attempts
        winners: Dict[str, str] = {}
        if remote_winner:
            winners["remote_users"] = remote_winner
        if s2s_winner:
            winners["s2s_peers"] = s2s_winner
        winners.update(teleport_winners)

        return VpnConfigList(
            remote_users=remote_users,
            s2s_peers=s2s_peers,
            teleport_servers=teleport_servers,
            teleport_clients=teleport_clients,
            attempts=attempts,
            winner_paths=winners,
        )
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
            self._sync_request("GET", f"{self._base}/stat/health")
            return
        except APIError:
            pass
        prefixes = ["/proxy/network", "/network", ""]
        ports = [443, 8443]
        for pr in prefixes:
            for po in ports:
                base_api = f"https://{self._host}:{po}{pr}/api/s/{self._site_name}"
                try:
                    self._sync_request("GET", f"{base_api}/stat/health")
                    self._base = base_api
                    self._port = po
                    self._path_prefix = pr or ""
                    self._use_proxy_prefix = self._path_prefix == "/proxy/network"
                    self._site_name = self._site
                    _LOGGER.info("Autodetected base: %s", self._base)
                    return
                except APIError:
                    continue
        for pr in prefixes:
            for po in ports:
                root_api = f"https://{self._host}:{po}{pr}/api"
                try:
                    sites = self._sync_request("GET", f"{root_api}/self/sites")
                    names = [s.get("name") for s in sites if isinstance(s, dict)]
                except APIError:
                    continue
                for candidate in [self._site_name] + [
                    n for n in names if n and n != self._site_name
                ]:
                    base_api = f"{root_api}/s/{candidate}"
                    try:
                        self._sync_request("GET", f"{base_api}/stat/health")
                        self._site = candidate
                        self._site_name = candidate
                        self._base = base_api
                        self._port = po
                        self._path_prefix = pr or ""
                        self._use_proxy_prefix = self._path_prefix == "/proxy/network"
                        _LOGGER.info(
                            "Autodetected via sites: %s (site=%s)",
                            self._base,
                            self._site_name,
                        )
                        return
                    except APIError:
                        continue

    # ----------- http helpers -----------
    def _sync_request(
        self,
        method: str,
        path_or_url: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        expected_errors: Optional[Collection[int]] = None,
    ) -> Any:
        candidate = str(path_or_url)
        if candidate.startswith("http"):
            url = candidate
        else:
            url = self._join(candidate)
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
            path = urlsplit(url).path
            query = urlsplit(url).query
            if query:
                path = f"{path}?{query}"
            _LOGGER.warning(
                "VPN probe failed: %s %s – %s",
                method,
                path,
                ex,
            )
            raise ConnectivityError(f"Request error: {ex}") from ex

        path = urlsplit(url).path
        query = urlsplit(url).query
        if query:
            path = f"{path}?{query}"
        body_preview = (r.text or "")[:400]
        length = len(r.content or b"")
        if r.status_code >= 400:
            _LOGGER.debug(
                "HTTP %s %s -> %s len=%s body=%s",
                method,
                path,
                r.status_code,
                length,
                body_preview,
            )
        else:
            _LOGGER.debug(
                "HTTP %s %s -> %s len=%s",
                method,
                path,
                r.status_code,
                length,
            )
        if r.status_code in (401, 403):
            _LOGGER.error("Authentication failed for UniFi request %s %s", method, url)
            raise AuthError(f"Auth failed at {url}")
        status_code = r.status_code
        expected = set(expected_errors or ())
        if status_code in expected:
            _LOGGER.debug(
                "Expected HTTP %s for UniFi request %s %s", status_code, method, url
            )
            snippet = (r.text or "")[:200]
            raise APIError(
                f"HTTP {status_code}: {snippet} at {url}",
                status_code=status_code,
                url=url,
                expected=True,
                body=snippet,
            )
        if status_code >= 400:
            snippet = (r.text or "")[:200]
            _LOGGER.error(
                "HTTP error %s for UniFi request %s %s: %s",
                status_code,
                method,
                url,
                snippet,
            )
            raise APIError(
                f"HTTP {status_code}: {snippet} at {url}",
                status_code=status_code,
                url=url,
                body=snippet,
            )
        if not r.content:
            return None
        try:
            data = r.json()
        except ValueError:
            _LOGGER.error("Invalid JSON received from UniFi request %s %s", method, url)
            raise APIError(f"Invalid JSON from {url}", url=url)
        return data.get("data") if isinstance(data, dict) and "data" in data else data

    async def _request(self, method: str, path: str, **kwargs) -> Tuple[Any, str]:
        """Perform an asynchronous HTTP request against the UniFi Network API."""

        url = self._join(path)
        timeout = kwargs.pop("timeout", self._timeout)

        def _do_request() -> Tuple[Any, str]:
            response = self._session.request(
                method,
                url,
                verify=self._ssl_verify,
                timeout=timeout,
                **kwargs,
            )
            try:
                text = response.text or ""
            except Exception:  # pragma: no cover - defensive
                text = ""
            return response, text

        loop = asyncio.get_running_loop()
        try:
            resp, text = await loop.run_in_executor(None, _do_request)
        except Exception as exc:  # pragma: no cover - network failure guard
            LOGGER.error("HTTP %s %s failed: %r", method, url, exc)
            raise

        status = getattr(resp, "status_code", None)
        if status is None:
            status = getattr(resp, "status", None)

        if status is not None and status >= 400:
            LOGGER.warning(
                "HTTP %s %s -> %s ; body[0..1024]=%r",
                method,
                url,
                status,
                text[:1024],
            )
        else:
            LOGGER.debug("HTTP %s %s -> %s", method, url, status)

        return resp, text

    def _api_bases(self) -> List[str]:
        """Return primary and v2 API base URLs for the configured site."""

        primary = self._base.rstrip("/")
        candidates: List[str] = [primary]
        marker = "/api/s/"
        if marker in primary:
            prefix, suffix = primary.split(marker, 1)
            v2_candidate = f"{prefix}/v2/api/site/{suffix}".rstrip("/")
            if v2_candidate not in candidates:
                candidates.append(v2_candidate)
        return candidates

    def _api_site_base(self, site: str) -> str:
        """Return the API base URL for a specific site."""

        base = self._base.rstrip("/")
        marker = "/api/s/"
        if marker in base:
            prefix, _ = base.split(marker, 1)
            return f"{prefix}{marker}{site}".rstrip("/")
        return base

    def _vpn_api_bases(self) -> List[str]:
        """Return API base URLs for VPN endpoint probing."""

        return self._api_bases()

    @staticmethod
    def _vpn_is_internet_path(path: str) -> bool:
        """Return True if the path targets the internet/vpn namespace."""

        normalized = path.lstrip("/")
        return normalized == "internet/vpn" or normalized.startswith("internet/vpn/")

    @staticmethod
    def _vpn_should_retry_with_alternate_base(err: APIError) -> bool:
        """Return True if the VPN error indicates an alternate endpoint is needed."""

        if err.status_code not in (400, 404):
            return False

        # Some controllers reply with a variety of 400/404 errors when a VPN
        # endpoint is only exposed via the alternate API base. The response body
        # differs between versions (e.g. api.err.Invalid, api.err.InvalidObject,
        # api.err.NotFound), so rely on the status code itself instead of the
        # message payload to decide whether to try the next base.
        return True

    def _get(
        self,
        path: str,
        *,
        expected_errors: Optional[Collection[int]] = None,
    ):
        _LOGGER.debug("GET %s", path)
        site_path = self._site_path(path)
        return self._sync_request(
            "GET",
            site_path,
            expected_errors=expected_errors,
        )

    def _post(
        self,
        path: str,
        payload: Optional[Dict[str, Any]] = None,
        *,
        expected_errors: Optional[Collection[int]] = None,
    ):
        _LOGGER.debug("POST %s", path)
        site_path = self._site_path(path)
        return self._sync_request(
            "POST",
            site_path,
            payload,
            expected_errors=expected_errors,
        )

    # ----------- public helpers used by sensors / diagnostics -----------
    def ping(self) -> Dict[str, Any]:
        health = self._get("stat/health") or []
        return {
            "ok": True,
            "health_count": len(health),
            "base": self._base,
            "site": self._site_name,
        }

    def get_healthinfo(self):
        return self._get("stat/health")

    def get_devices(self):
        return self._get("stat/device")

    def get_alerts(self):
        """Fetch controller alerts, handling both legacy and v2 endpoints."""

        legacy_path = "list/alert"
        v2_path = "alerts"
        bases = self._api_bases()
        last_error: Optional[APIError] = None
        last_path: str = legacy_path

        def _path_for_base(base: str) -> str:
            return v2_path if "/v2/api/" in base else legacy_path

        for index, base in enumerate(bases):
            path = _path_for_base(base)
            url = f"{base}/{path}"
            try:
                alerts = self._sync_request(
                    "GET",
                    url,
                    expected_errors=(400, 404),
                )
            except APIError as err:
                last_error = err
                last_path = path
                has_alternate = index < (len(bases) - 1)
                if has_alternate and err.status_code in (400, 404):
                    _LOGGER.debug(
                        "Fetching %s via %s failed (%s); trying alternate API base",
                        path,
                        base,
                        err,
                    )
                    continue
                break
            else:
                _LOGGER.debug(
                    "Fetched %s alert records from %s",
                    len(alerts) if isinstance(alerts, list) else "unknown",
                    path,
                )
                return alerts

        if last_error is not None:
            _LOGGER.debug(
                "Fetching %s failed (%s); attempting legacy list/alarm endpoint",
                last_path,
                last_error,
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
        sites = self._sync_request("GET", f"{root}/self/sites")
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
                data = self._get(
                    path,
                    expected_errors=_VPN_EXPECTED_ERROR_CODES,
                )
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

    def _iter_vpn_payload(
        self, payload: Any, key_hint: Optional[str] = None
    ) -> Iterable[Tuple[Optional[str], List[Dict[str, Any]]]]:
        """Iterate over VPN payload segments that look like peer lists."""

        if payload in (None, "", [], {}):
            return

        if isinstance(payload, list):
            peers = [item for item in payload if isinstance(item, dict)]
            if peers:
                yield key_hint, peers
            return

        if isinstance(payload, dict):
            has_peer_fields = any(
                key in payload and payload.get(key) not in (None, "", [], {})
                for key in _VPN_RECORD_KEYS
            )
            if has_peer_fields and all(
                not isinstance(value, list) for value in payload.values()
            ):
                yield key_hint, [payload]

            for key, value in payload.items():
                if not isinstance(value, (dict, list)):
                    continue
                next_hint = key_hint
                if isinstance(key, str):
                    lowered = key.strip().lower()
                    if lowered not in _VPN_CONTAINER_KEYS:
                        next_hint = lowered
                yield from self._iter_vpn_payload(value, next_hint)

    def _prepare_vpn_peer(
        self,
        peer: Dict[str, Any],
        *,
        category_hint: Optional[str],
        source_path: str,
    ) -> Dict[str, Any]:
        normalized = dict(peer)
        if source_path:
            normalized.setdefault("_ha_source", source_path)
        if category_hint:
            normalized.setdefault("_ha_category_hint", category_hint)

        role, category, template = _classify_vpn_record(normalized, category_hint)
        normalized_role = role or normalized.get("role")
        if normalized_role and not normalized.get("role"):
            normalized["role"] = normalized_role
        if normalized_role:
            normalized["_ha_role"] = normalized_role
        if category:
            normalized["_ha_category"] = category
        if template:
            normalized["_ha_template"] = template

        legacy_identity = vpn_peer_identity(normalized)
        suffix = (
            _normalize_token(category)
            or _normalize_token(normalized_role)
            or _normalize_token(category_hint)
            or "vpn"
        )
        normalized["_ha_legacy_peer_id"] = legacy_identity
        normalized["_ha_peer_id"] = (
            f"{legacy_identity}::{suffix}" if suffix else legacy_identity
        )
        return normalized

    def _normalize_vpn_payload(
        self, payload: Any, *, path: str, default_category: Optional[str]
    ) -> List[Dict[str, Any]]:
        normalized: List[Dict[str, Any]] = []
        for key_hint, peers in self._iter_vpn_payload(payload, default_category):
            category_hint = key_hint or default_category
            for peer in peers:
                normalized.append(
                    self._prepare_vpn_peer(
                        peer, category_hint=category_hint, source_path=path
                    )
                )
        return normalized

    @staticmethod
    def _merge_vpn_peer(
        existing: Dict[str, Any], incoming: Dict[str, Any]
    ) -> Dict[str, Any]:
        sources: List[str] = existing.setdefault("_ha_sources", [])
        for key in ("_ha_source", "_ha_category_hint"):
            for value in (existing.get(key), incoming.get(key)):
                if isinstance(value, str) and value and value not in sources:
                    sources.append(value)

        for key, value in incoming.items():
            if key == "_ha_peer_id":
                continue
            if value in (None, "", [], {}):
                continue
            if key not in existing or existing.get(key) in (None, "", [], {}):
                existing[key] = value

        if "_ha_source" not in existing and incoming.get("_ha_source"):
            existing["_ha_source"] = incoming["_ha_source"]
        if incoming.get("_ha_category"):
            existing["_ha_category"] = incoming["_ha_category"]
        if incoming.get("_ha_role"):
            existing["_ha_role"] = incoming["_ha_role"]
        if incoming.get("_ha_template") and not existing.get("_ha_template"):
            existing["_ha_template"] = incoming["_ha_template"]

        return existing

    @staticmethod
    def _filter_vpn_peers(
        peers: List[Dict[str, Any]], allowed_categories: Iterable[str]
    ) -> List[Dict[str, Any]]:
        allowed = {
            _normalize_token(category)
            for category in allowed_categories
            if category is not None
        }
        if not allowed:
            return list(peers)

        filtered: List[Dict[str, Any]] = []
        for peer in peers:
            tokens = [
                _normalize_token(peer.get("_ha_category")),
                _normalize_token(peer.get("_ha_role")),
                _normalize_token(peer.get("role")),
                _normalize_token(peer.get("vpn_type")),
                _normalize_token(peer.get("type")),
                _normalize_token(peer.get("_ha_category_hint")),
            ]
            tokens = [token for token in tokens if token]
            if any(
                candidate in token or token in candidate
                for token in tokens
                for candidate in allowed
            ):
                filtered.append(peer)
        return filtered

    @staticmethod
    def _finalize_vpn_peer(peer: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich peer metadata with normalized attributes and derived values."""

        normalized = dict(peer)

        name = _first_value(
            normalized,
            "vpn_name",
            "name",
            "peer_name",
            "display_name",
            "description",
            "remote_user",
            "user",
            "username",
            "connection_name",
            "profile_name",
            "profile",
        )
        if name:
            normalized.setdefault("vpn_name", name)
            normalized.setdefault("name", name)

        interface = _first_value(normalized, "interface", "ifname")
        if interface:
            normalized.setdefault("interface", interface)

        public_ip = _first_value(
            normalized,
            "public_ip",
            "wan_ip",
            "gateway",
            "server_addr",
            "server_address",
            "peer_addr",
            "peer_ip",
            "remote_ip",
        )
        if public_ip:
            normalized.setdefault("public_ip", public_ip)

        tunnel = _first_value(
            normalized,
            "tunnel_subnet",
            "tunnel_network",
            "client_subnet",
            "ip_subnet",
            "subnet",
            "network",
        )
        if not tunnel:
            allowed = normalized.get("allowed_ips")
            if isinstance(allowed, list):
                flattened = [
                    str(item).strip()
                    for item in allowed
                    if item not in (None, "", [], {})
                ]
                if flattened:
                    tunnel = ", ".join(flattened)
        if not tunnel:
            client_networks = normalized.get("client_networks")
            if isinstance(client_networks, list):
                flattened = [
                    str(item).strip()
                    for item in client_networks
                    if item not in (None, "", [], {})
                ]
                if flattened:
                    tunnel = ", ".join(flattened)
        if tunnel:
            normalized.setdefault("tunnel_subnet", tunnel)

        clients = _peer_clients(normalized)
        if clients is not None and not normalized.get("clients"):
            normalized["clients"] = clients

        client_count: Optional[int] = None
        for key in (
            "client_count",
            "connected_clients",
            "sessions",
            "active_sessions",
            "clients",
            "users",
            "num_clients",
            "num_users",
        ):
            candidate = normalized.get(key)
            client_count = _extract_count(candidate)
            if client_count is not None:
                break
        if client_count is None:
            client_count = 0
        normalized["client_count"] = client_count

        state = _derive_peer_state(normalized, client_count)
        if state:
            normalized["_ha_state"] = state
            normalized.setdefault("state", state)

        last_change = _first_value(
            normalized,
            "last_state_change",
            "last_connected",
            "last_connection",
            "last_activity",
            "last_contact",
            "last_handshake",
            "connected_since",
            "connected_at",
            "last_seen",
        )
        if last_change:
            normalized.setdefault("last_state_change", last_change)

        for key in (
            "rx_bytes",
            "bytes_rx",
            "bytes_in",
            "rx",
            "received_bytes",
            "receive_bytes",
        ):
            value = _coerce_int(normalized.get(key))
            if value is not None:
                normalized.setdefault("rx_bytes", value)
                break

        for key in (
            "tx_bytes",
            "bytes_tx",
            "bytes_out",
            "tx",
            "sent_bytes",
            "transmit_bytes",
        ):
            value = _coerce_int(normalized.get(key))
            if value is not None:
                normalized.setdefault("tx_bytes", value)
                break

        return normalized

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
        return self._site_name

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
