from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import socket
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import (
    TYPE_CHECKING,
    Any,
    Collection,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
)
from urllib.parse import urlsplit

import requests  # type: ignore[import-untyped]
from requests.adapters import HTTPAdapter  # type: ignore[import-untyped]
from urllib3.util.retry import Retry  # type: ignore[import-untyped]

from .const import DEFAULT_SITE, DEFAULT_TIMEOUT

if TYPE_CHECKING:
    from requests import Response  # type: ignore[import-untyped]
else:  # pragma: no cover - fallback for environments without requests.Response typing
    Response = Any

LOGGER = logging.getLogger(__name__)
_LOGGER = LOGGER

DEFAULT_CONNECT_TIMEOUT = 8
DEFAULT_READ_TIMEOUT = 12

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


def build_path(*segments: str) -> str:
    """Return a normalized path from the provided segments."""

    cleaned: List[str] = []
    for segment in segments:
        if not segment:
            continue
        token = str(segment).strip("/")
        if token:
            cleaned.append(token)
    return "/".join(cleaned)


@dataclass(slots=True)
class JsonRequestResult:
    """Result returned by ``request_json`` including metadata for logging."""

    data: Any
    status: int
    ok: bool
    snippet: str
    url: str


@dataclass(slots=True)
class VpnAttempt:
    """Record describing a VPN diagnostics fetch attempt."""

    path: str
    status: int
    ok: bool
    snippet: str


@dataclass(slots=True)
class VpnState:
    """Aggregated VPN state derived from UniFi gateway overview stats."""

    remote_users: List[dict[str, Any]] = field(default_factory=list)
    site_to_site_peers: List[dict[str, Any]] = field(default_factory=list)
    teleport_servers: List[dict[str, Any]] = field(default_factory=list)
    teleport_clients: List[dict[str, Any]] = field(default_factory=list)
    attempts: List[VpnAttempt] = field(default_factory=list)
    errors: dict[str, Any] = field(default_factory=dict)


def _unique_dicts(records: Iterable[dict[str, Any]]) -> List[dict[str, Any]]:
    """Return ``records`` without duplicates based on JSON fingerprints."""

    unique: List[dict[str, Any]] = []
    seen: set[str] = set()
    for record in records:
        try:
            fingerprint = json.dumps(record, sort_keys=True, default=str)
        except (TypeError, ValueError):
            fingerprint = repr(record)
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        unique.append(record)
    return unique


def _normalize_vpn_entry(value: Any) -> dict[str, Any]:
    """Convert controller payload fragments into dictionaries."""

    if isinstance(value, dict):
        return {k: v for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return {"items": list(value)}
    return {"value": value}


def _extract_vpn_entries(payload: Any, tokens: Sequence[str]) -> List[dict[str, Any]]:
    """Extract dictionaries matching any of ``tokens`` from ``payload``."""

    matches: List[dict[str, Any]] = []

    def _walk(candidate: Any, *, parent_key: Optional[str] = None) -> None:
        if isinstance(candidate, dict):
            for key, value in candidate.items():
                lowered = str(key).lower()
                if any(token in lowered for token in tokens):
                    matches.append(_normalize_vpn_entry(value))
                if isinstance(value, (dict, list, tuple)):
                    _walk(value, parent_key=lowered)
        elif isinstance(candidate, list):
            for item in candidate:
                _walk(item, parent_key=parent_key)

    _walk(payload)
    return _unique_dicts(matches)


_VPN_REMOTE_TOKENS = (
    "remote_user",
    "remote_users",
    "remoteuser",
    "remoteusers",
    "remote_access",
)

_VPN_S2S_TOKENS = (
    "site_to_site",
    "site-to-site",
    "s2s",
)

_VPN_TELEPORT_SERVER_TOKENS = (
    "teleport_servers",
    "teleport_server",
)

_VPN_TELEPORT_CLIENT_TOKENS = (
    "teleport_clients",
    "teleport_client",
)

_WAN_EXPECTED_ERROR_CODES: Tuple[int, ...] = (400, 404)


_SERVER_FIELD_RE = re.compile(r"([A-Za-z0-9_]+)\s*:")


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
        iso_candidate = (
            cleaned.replace("Z", "+00:00") if cleaned.endswith("Z") else cleaned
        )
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
        connect_timeout = max(5, min(int(timeout or DEFAULT_TIMEOUT), 10))
        read_timeout = max(connect_timeout + 4, 12)
        read_timeout = min(read_timeout, 15)
        self._timeout = (float(connect_timeout), float(read_timeout))
        self._use_proxy_prefix = use_proxy_prefix
        self._path_prefix = "/proxy/network" if use_proxy_prefix else ""
        self._site_name = site_id
        self._site = site_id
        self._site_id: Optional[str] = None
        self._username = username
        self._password = password

        self._session = requests.Session()
        retries = Retry(
            total=2,
            connect=2,
            read=2,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("GET", "POST"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retries)
        self._session.mount("https://", adapter)
        self._session.mount("http://", adapter)
        self._session.headers.update({"Accept": "application/json"})
        self._session.verify = True
        if not ssl_verify:
            self._session.verify = False
            _LOGGER.warning(
                "SSL verification disabled for UniFi Gateway session; use with caution",
            )

        self._st_cache: tuple[float, Optional[Dict[str, Any]]] | None = None
        self._st_last_trigger: float = 0.0

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

        self._login(host, port, bool(self._session.verify), int(self._timeout[1]))
        self._ensure_connected()
        self._vpn_family_override = (
            vpn_family_override  # retained for option compatibility
        )

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
            "/v1/sites",
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
                data = (
                    payload.get("data") or payload.get("sites") or payload.get("items")
                )
                if isinstance(data, list):
                    records = [item for item in data if isinstance(item, dict)]
                elif isinstance(payload.get("site"), dict):
                    records = [payload["site"]]

            for record in records:
                name = record.get("name") or record.get("shortname")
                if isinstance(name, str) and name == self._site_name:
                    site_id = (
                        record.get("id") or record.get("_id") or record.get("uuid")
                    )
                    if isinstance(site_id, str) and site_id:
                        self._site_id = site_id
                        LOGGER.debug(
                            "Resolved site id %s for site %s", site_id, self._site_name
                        )
                        return self._site_id

        LOGGER.debug(
            "Falling back to site name for site-id lookups: %s", self._site_name
        )
        return None

    def _site_path_for(self, site: Optional[str], path: str = "") -> str:
        """Return the API path for a specific site without duplicate prefixes."""

        site_name = str(site or self._site_name or DEFAULT_SITE).strip() or DEFAULT_SITE
        base = f"api/s/{site_name}".rstrip("/")
        if path:
            return f"{base}/{path.lstrip('/')}"
        return base

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
                        verify=ssl_verify,
                        timeout=timeout,
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
            self.request_json(f"{self._base}/stat/health", absolute=True)
            return
        except APIError:
            pass
        prefixes = ["/proxy/network", "/network", ""]
        ports = [443, 8443]
        for pr in prefixes:
            for po in ports:
                base_api = f"https://{self._host}:{po}{pr}/api/s/{self._site_name}"
                try:
                    self.request_json(f"{base_api}/stat/health", absolute=True)
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
                    sites = self.request_json(f"{root_api}/self/sites", absolute=True)
                    names = [s.get("name") for s in sites if isinstance(s, dict)]
                except APIError:
                    continue
                for candidate in [self._site_name] + [
                    n for n in names if n and n != self._site_name
                ]:
                    base_api = f"{root_api}/s/{candidate}"
                    try:
                        self.request_json(f"{base_api}/stat/health", absolute=True)
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
    def request_json(
        self,
        path: str,
        *,
        method: str = "GET",
        expected: Collection[int] | None = None,
        expected_errors: Collection[int] | None = None,
        json: Any | None = None,
        data: Any | None = None,
        params: Mapping[str, Any] | None = None,
        timeout: Tuple[float, float] | None = None,
        absolute: bool = False,
        with_meta: bool = False,
    ) -> Any | JsonRequestResult:
        """Perform a synchronous HTTP request returning JSON payloads."""

        expected_codes = tuple(expected or (200,))
        expected_error_codes = tuple(expected_errors or ())

        candidate = str(path)
        if absolute or candidate.startswith("http"):
            url = candidate
        else:
            url = self._join(candidate)

        request_timeout = timeout or self._timeout
        reauth_attempted = False

        while True:
            try:
                response: Response = self._session.request(
                    method,
                    url,
                    json=json,
                    data=data,
                    params=params,
                    timeout=request_timeout,
                )
            except requests.RequestException as err:
                snippet = _redact_text(str(err))
                _LOGGER.debug(
                    "HTTP %s %s failed: %s",
                    method,
                    urlsplit(url).path or url,
                    snippet,
                )
                raise ConnectivityError(f"Request error: {err}") from err

            status = response.status_code or 0
            snippet = _redact_text((response.text or "")[:200])
            ok = status in expected_codes
            log_path = urlsplit(url).path or url
            _LOGGER.debug(
                "HTTP %s %s -> %s ok=%s body=%s",
                method,
                log_path,
                status,
                ok,
                snippet,
            )

            if status in (401, 403):
                if not reauth_attempted:
                    reauth_attempted = True
                    self._login(
                        self._host,
                        self._port,
                        bool(self._session.verify),
                        int(request_timeout[1]),
                    )
                    continue
                raise AuthError(f"Auth failed at {url}")

            if status in expected_error_codes:
                raise APIError(
                    f"HTTP {status}: {snippet} at {url}",
                    status_code=status,
                    url=url,
                    expected=True,
                    body=snippet,
                )

            if not ok:
                raise APIError(
                    f"HTTP {status}: {snippet} at {url}",
                    status_code=status,
                    url=url,
                    body=snippet,
                )

            if not response.content:
                payload: Any = None
            else:
                try:
                    decoded = response.json()
                except ValueError as err:  # pragma: no cover - defensive
                    raise APIError(f"Invalid JSON from {url}", url=url) from err
                else:
                    if isinstance(decoded, dict) and "data" in decoded:
                        payload = decoded.get("data")
                    else:
                        payload = decoded

            if with_meta:
                return JsonRequestResult(payload, status, ok, snippet, url)
            return payload

    async def _request(self, method: str, path: str, **kwargs) -> Tuple[Any, str]:
        """Perform an asynchronous HTTP request against the UniFi Network API."""

        url = self._join(path)
        timeout = kwargs.pop("timeout", self._timeout)

        def _do_request() -> Tuple[Any, str]:
            response = self._session.request(
                method,
                url,
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
        return self.request_json(
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
        return self.request_json(
            site_path,
            method="POST",
            json=payload,
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
                alerts = self.request_json(
                    url,
                    expected_errors=(400, 404),
                    absolute=True,
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
            len(legacy_alerts) if isinstance(legacy_alerts, list) else "unknown",
        )
        return legacy_alerts

    def list_sites(self):
        root = self._base.split("/api/s/")[0] + "/api"
        sites = self.request_json(f"{root}/self/sites", absolute=True)
        _LOGGER.debug(
            "Controller returned %s sites",
            len(sites) if isinstance(sites, list) else "unknown",
        )
        return sites

    def get_networks(self) -> List[Dict[str, Any]]:
        for path in ("rest/networkconf", "list/networkconf"):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    _LOGGER.debug("Fetched %s networks via %s", len(data), path)
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
        for path in (
            "stat/sta",
            "stat/user",
            "list/user",
            "stat/clients",
            "stat/alluser",
        ):
            try:
                data = self._get(path)
                if isinstance(data, list):
                    _LOGGER.debug("Fetched %s clients via %s", len(data), path)
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
        _LOGGER.debug(
            "Attempting WAN link discovery via endpoints: %s", ", ".join(paths)
        )
        for path in paths:
            try:
                data = self._get(
                    path,
                    expected_errors=_WAN_EXPECTED_ERROR_CODES,
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
            if (
                "wan" in purpose
                or n.get("wan_network")
                or "wan" in (name or "").lower()
            ):
                out.append(
                    {
                        "id": n.get("_id") or n.get("id") or name,
                        "name": name,
                        "type": "wan",
                    }
                )
        if out:
            _LOGGER.debug(
                "Derived %s WAN links from network configuration fallback", len(out)
            )
        else:
            _LOGGER.error("Unable to determine WAN links from controller data")
        return out

    def get_vpn_summary(self, site: Optional[str] = None) -> VpnState:
        """Return aggregated VPN diagnostics using gateway overview statistics."""

        site_name = str(site or self._site_name or DEFAULT_SITE).strip() or DEFAULT_SITE
        _LOGGER.debug("using LAN/WAN-style gateway stats for VPN summary")

        relative_paths = [
            self._site_path_for(site_name, "gateway/health/overview"),
            self._site_path_for(site_name, "gateway/health/overview/stats"),
        ]

        attempts: List[VpnAttempt] = []
        errors: dict[str, Any] = {}
        remote_records: List[dict[str, Any]] = []
        s2s_records: List[dict[str, Any]] = []
        teleport_servers: List[dict[str, Any]] = []
        teleport_clients: List[dict[str, Any]] = []

        for path in relative_paths:
            try:
                result = self.request_json(path, with_meta=True)
            except APIError as err:
                snippet = _redact_text(
                    (err.body or "")[:200] if getattr(err, "body", None) else str(err)
                )
                attempts.append(
                    VpnAttempt(
                        path=path,
                        status=err.status_code or 0,
                        ok=False,
                        snippet=snippet,
                    )
                )
                errors.setdefault("http", {})[path] = snippet or str(err)
                continue
            except ConnectivityError as err:
                snippet = _redact_text(str(err))
                attempts.append(
                    VpnAttempt(path=path, status=0, ok=False, snippet=snippet)
                )
                errors.setdefault("connectivity", {})[path] = snippet
                continue
            else:
                assert isinstance(result, JsonRequestResult)
                attempts.append(
                    VpnAttempt(
                        path=path,
                        status=result.status,
                        ok=result.ok,
                        snippet=result.snippet,
                    )
                )
                if not result.ok or result.data in (None, "", [], {}):
                    continue
                payload = result.data
                remote_records.extend(_extract_vpn_entries(payload, _VPN_REMOTE_TOKENS))
                s2s_records.extend(_extract_vpn_entries(payload, _VPN_S2S_TOKENS))
                teleport_servers.extend(
                    _extract_vpn_entries(payload, _VPN_TELEPORT_SERVER_TOKENS)
                )
                teleport_clients.extend(
                    _extract_vpn_entries(payload, _VPN_TELEPORT_CLIENT_TOKENS)
                )

        errors = {key: value for key, value in errors.items() if value}

        return VpnState(
            remote_users=_unique_dicts(remote_records),
            site_to_site_peers=_unique_dicts(s2s_records),
            teleport_servers=_unique_dicts(teleport_servers),
            teleport_clients=_unique_dicts(teleport_clients),
            attempts=attempts,
            errors=errors,
        )

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
            if (
                t in ("ugw", "udm")
                or m.startswith("udm")
                or "gateway" in (d.get("name") or "").lower()
            ):
                mac = d.get("mac") or d.get("device_mac")
                if mac:
                    return mac
        try:
            hi = self.get_healthinfo()
            for sub in hi or []:
                if sub.get("subsystem") == "www":
                    mac = (
                        sub.get("gw_mac")
                        or sub.get("gw-mac")
                        or sub.get("wan_ip_gw_mac")
                    )
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

    def get_speedtest_history(
        self, start_ms: Optional[int] = None, end_ms: Optional[int] = None
    ):
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
        out: Dict[str, Any] = {}
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

            def _assign(
                detail_key: str, source_keys: List[str], *, converter=None
            ) -> None:
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
        cache = self._st_cache
        if cache is not None and (now - cache[0]) < cache_sec:
            return cache[1]
        rec = None
        try:
            st = self.get_speedtest_status()
            rec = (
                st[0]
                if isinstance(st, list) and st
                else (st if isinstance(st, dict) else None)
            )
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
