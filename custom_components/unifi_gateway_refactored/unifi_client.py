
from __future__ import annotations

import hashlib
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

import requests
from urllib.parse import urlsplit
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .const import DEFAULT_SITE


LOGGER = logging.getLogger(__name__)
_LOGGER = LOGGER


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

    def _ensure_site_id_sync(self) -> Optional[str]:
        """Fetch and cache the GUID-style site identifier (synchronous path)."""

        if self._site_id:
            return self._site_id

        candidates = [
            "/v1/sites",
            f"/v2/api/site/{self._site_name}/info",
        ]

        for path in candidates:
            try:
                resp, text = self._request("GET", path, timeout=6)
            except Exception as err:  # pragma: no cover - defensive network guard
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
                        LOGGER.debug(
                            "Resolved site id %s for site %s", site_id, self._site_name
                        )
                        return self._site_id

        LOGGER.debug("Falling back to site name for site-id lookups: %s", self._site_name)
        return None

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

    @staticmethod
    def _shorten(text: Optional[str], limit: int = 1024) -> Optional[str]:
        if text is None:
            return None
        cleaned = text.strip()
        if len(cleaned) <= limit:
            return cleaned
        return f"{cleaned[:limit]}…"

    @staticmethod
    def _login_endpoint_label(url: str) -> str:
        """Return a sanitized label for login endpoint logging."""

        parts = urlsplit(url)
        path = parts.path or "/"
        host = parts.hostname or parts.netloc
        if host:
            return f"{host}{path}"
        return path

    def _update_csrf_token(self, response: requests.Response) -> None:
        token: Optional[str] = None
        header_token = response.headers.get("X-CSRF-Token")
        if isinstance(header_token, str) and header_token:
            token = header_token
        else:
            for cookie_name in ("TOKEN", "csrf_token", "X-CSRF-Token"):
                cookie_token = response.cookies.get(cookie_name)
                if isinstance(cookie_token, str) and cookie_token:
                    token = cookie_token
                    break
        if token and token != self._csrf:
            self._csrf = token
            self._session.headers.update({"X-CSRF-Token": token})

    def _refresh_csrf_token(self, base_url: str, timeout: int) -> None:
        for path in ("/api/auth/csrf", "/api/csrf"):
            url = f"{base_url}{path}"
            try:
                response = self._session.get(url, timeout=timeout, allow_redirects=False)
            except requests.exceptions.RequestException as err:  # pragma: no cover - network guard
                LOGGER.debug("Fetching CSRF token from %s failed: %s", url, err)
                continue
            if response.status_code >= 400:
                LOGGER.debug(
                    "CSRF probe %s returned HTTP %s", url, response.status_code
                )
                continue
            self._update_csrf_token(response)
            if self._csrf:
                LOGGER.debug("CSRF token refreshed from %s", url)
                return

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_payload: Any = None,
        data: Any = None,
        timeout: Optional[int] = None,
    ) -> tuple[requests.Response, str]:
        url = self._join(path)
        req_timeout = timeout or self._timeout
        kwargs: Dict[str, Any] = {"timeout": req_timeout, "allow_redirects": False}
        if params:
            kwargs["params"] = params
        if json_payload is not None:
            kwargs["json"] = json_payload
        if data is not None:
            kwargs["data"] = data
        LOGGER.debug("UniFi request %s %s", method, url)
        try:
            response = self._session.request(method, url, **kwargs)
        except requests.exceptions.SSLError as err:
            raise ConnectivityError(
                f"SSL error while connecting to {url}: {err}", url=url
            ) from err
        except requests.exceptions.ConnectTimeout as err:
            raise ConnectivityError(
                f"Timeout while connecting to {url}: {err}", url=url
            ) from err
        except requests.exceptions.ConnectionError as err:
            raise ConnectivityError(
                f"Connection error while reaching {url}: {err}", url=url
            ) from err
        except requests.exceptions.RequestException as err:
            raise ConnectivityError(
                f"Request {method} {url} failed: {err}", url=url
            ) from err

        self._update_csrf_token(response)

        status = response.status_code
        body_preview = self._shorten(response.text)
        if status in (401, 403):
            raise AuthError(
                "Authentication with UniFi controller failed",
                status_code=status,
                url=url,
                body=body_preview,
            )
        if status >= 400:
            raise APIError(
                f"UniFi API call {method} {url} failed with HTTP {status}",
                status_code=status,
                url=url,
                expected=status == 404,
                body=body_preview,
            )
        return response, response.text or ""

    def _process_payload(self, payload: Any, url: str) -> Any:
        if isinstance(payload, dict):
            meta = payload.get("meta")
            if isinstance(meta, dict):
                rc = meta.get("rc")
                if rc and rc not in {"ok", "success"}:
                    message = meta.get("msg") or rc
                    raise APIError(
                        f"UniFi controller returned error for {url}: {message}",
                        url=url,
                        expected=rc in {"error"},
                        body=self._shorten(json.dumps(payload)[:1024]),
                    )
        return payload

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        json_payload: Any = None,
        data: Any = None,
        timeout: Optional[int] = None,
    ) -> Any:
        response, text = self._request(
            method,
            path,
            params=params,
            json_payload=json_payload,
            data=data,
            timeout=timeout,
        )
        if not text:
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError:
            LOGGER.debug("Non-JSON response from %s", response.url)
            return text
        return self._process_payload(payload, response.url)

    @staticmethod
    def _extract_list(payload: Any) -> List[Dict[str, Any]]:
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("data", "items", "sites", "list", "records"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            # Some APIs return a dict keyed by identifiers
            if all(isinstance(v, dict) for v in payload.values()):
                return [dict(v) for v in payload.values()]  # type: ignore[arg-type]
        return []

    def _get_list(self, path: str, *, timeout: Optional[int] = None) -> List[Dict[str, Any]]:
        try:
            payload = self._request_json("GET", path, timeout=timeout)
        except APIError as err:
            if err.expected:
                LOGGER.debug("UniFi endpoint %s unavailable: %s", path, err)
                return []
            raise
        return self._extract_list(payload)

    def _post(self, path: str, payload: Dict[str, Any], *, timeout: Optional[int] = None) -> Any:
        return self._request_json("POST", path, json_payload=payload, timeout=timeout)

    def _get(self, path: str, *, timeout: Optional[int] = None) -> Any:
        return self._request_json("GET", path, timeout=timeout)

    def _login(self, host: str, port: int, ssl_verify: bool, timeout: int) -> None:
        base = f"{self._scheme}://{host}:{port}"
        self._session.verify = ssl_verify
        self._session.cookies.clear()
        self._session.headers.update({"Referer": base})

        attempts = [
            ("/api/auth/login", {"username": self._username, "password": self._password, "rememberMe": True}, True),
            ("/api/login", {"username": self._username, "password": self._password, "remember": True}, True),
            ("/login", {"username": self._username, "password": self._password}, False),
        ]

        last_error: Optional[Exception] = None
        for path, payload, use_json in attempts:
            url = f"{base}{path}"
            endpoint = self._login_endpoint_label(url)
            LOGGER.debug("Attempting UniFi login via %s", endpoint)
            try:
                if use_json:
                    response = self._session.post(
                        url,
                        json=payload,
                        timeout=timeout,
                        allow_redirects=False,
                    )
                else:
                    response = self._session.post(
                        url,
                        data=payload,
                        timeout=timeout,
                        allow_redirects=False,
                    )
            except requests.exceptions.RequestException as err:
                LOGGER.debug("Login attempt via %s failed: %s", endpoint, err)
                last_error = ConnectivityError(
                    f"Error connecting to {url}: {err}", url=url
                )
                continue

            self._update_csrf_token(response)

            status = response.status_code
            body_preview = self._shorten(response.text)
            if status in (401, 403):
                raise AuthError(
                    "Invalid UniFi controller credentials",
                    status_code=status,
                    url=url,
                    body=body_preview,
                )
            if status == 404:
                LOGGER.debug("Login endpoint %s not found", endpoint)
                last_error = APIError(
                    f"Login endpoint {url} not found",
                    status_code=status,
                    url=url,
                    expected=True,
                    body=body_preview,
                )
                continue
            if status >= 400:
                LOGGER.debug(
                    "Login attempt via %s returned HTTP %s", endpoint, status
                )
                last_error = APIError(
                    f"Login attempt failed with HTTP {status}",
                    status_code=status,
                    url=url,
                    body=body_preview,
                )
                continue

            LOGGER.debug("Login via %s succeeded", endpoint)
            if not self._csrf:
                self._refresh_csrf_token(base, timeout)
            return

        if last_error:
            raise last_error
        raise ConnectivityError("Unable to log in to UniFi controller", url=base)

    def _ensure_connected(self) -> None:
        prefixes: List[str] = []
        if self._use_proxy_prefix:
            prefixes.append("/proxy/network")
        prefixes.extend(["/network", ""])

        last_error: Optional[Exception] = None
        for prefix in prefixes:
            self._path_prefix = prefix
            probe_path = self._site_path("stat/health")
            candidate_base = self._join(self._site_path())
            LOGGER.debug(
                "Probing UniFi Network API base %s using %s", candidate_base, probe_path
            )
            try:
                payload = self._request_json("GET", probe_path, timeout=6)
            except AuthError:
                raise
            except ConnectivityError as err:
                LOGGER.debug("Connectivity error probing %s: %s", candidate_base, err)
                last_error = err
                continue
            except APIError as err:
                LOGGER.debug("API error probing %s: %s", candidate_base, err)
                if err.status_code == 404 or err.expected:
                    last_error = err
                    continue
                raise

            if isinstance(payload, dict):
                payload = self._process_payload(payload, candidate_base)
            LOGGER.debug("Selected UniFi Network API base %s", candidate_base)
            self._base = candidate_base
            return

        if last_error:
            raise last_error
        raise ConnectivityError("Unable to determine UniFi Network API base path")

    def ping(self) -> bool:
        self.get_healthinfo()
        return True

    def list_sites(self) -> List[Dict[str, Any]]:
        for path in ("api/self/sites", "api/stat/sites"):
            sites = self._get_list(path)
            if sites:
                return sites
        return []

    def get_healthinfo(self) -> List[Dict[str, Any]]:
        return self._get_list(self._site_path("stat/health"))

    def get_alerts(self) -> List[Dict[str, Any]]:
        for path in ("stat/alert", "list/alarm", "stat/alarm"):
            alerts = self._get_list(self._site_path(path))
            if alerts:
                return alerts
        return []

    def get_devices(self) -> List[Dict[str, Any]]:
        for path in ("stat/device", "stat/device-basic"):
            devices = self._get_list(self._site_path(path))
            if devices:
                return devices
        return []

    def get_networks(self) -> List[Dict[str, Any]]:
        for path in (
            "rest/networkconf",
            "stat/networkconf",
            "stat/network",
        ):
            networks = self._get_list(self._site_path(path))
            if networks:
                return networks
        return []

    def get_wlans(self) -> List[Dict[str, Any]]:
        for path in ("rest/wlanconf", "list/wlanconf"):
            wlans = self._get_list(self._site_path(path))
            if wlans:
                return wlans
        return []

    def get_clients(self) -> List[Dict[str, Any]]:
        for path in ("stat/sta", "stat/associated", "stat/user"):
            clients = self._get_list(self._site_path(path))
            if clients:
                return clients
        return self._get_list(self._site_path("stat/alluser"))

    def get_wan_links(self) -> List[Dict[str, Any]]:
        for path in (
            "internet/wan",
            "stat/waninfo",
            "stat/wan",
            "rest/internet",
        ):
            try:
                links = self._get_list(self._site_path(path))
            except APIError as err:
                if err.status_code == 400:
                    LOGGER.debug(
                        "UniFi endpoint %s unavailable (HTTP 400): %s", path, err
                    )
                    continue
                raise
            if links:
                return links
        return []

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

    # ---- VPN helpers (generic, multi-endpoint discovery) ----
    def _iter_vpn_paths(self, endpoint: str) -> List[str]:
        """Return candidate API paths for a VPN endpoint (mirrors site variants)."""

        # Reuse the speedtest path normalizer for site-aware permutations
        return self._iter_speedtest_paths(endpoint)

    def _call_vpn_endpoint(
        self,
        method: str,
        endpoint: str,
        *,
        payload: Any = None,
        timeout: Optional[int] = None,
    ) -> Tuple[Any, str]:
        """Invoke a VPN endpoint trying multiple path variations."""

        last_error: Optional[Exception] = None
        for path in self._iter_vpn_paths(endpoint):
            try:
                if method.upper() == "GET":
                    response = self._request_json("GET", path, timeout=timeout)
                else:
                    response = self._request_json(
                        method.upper(), path, json_payload=payload, timeout=timeout
                    )
                return response, path
            except APIError as err:
                last_error = err
                if err.status_code in (404, 405) or err.expected:
                    continue
                if err.status_code == 400 and method.upper() == "GET":
                    continue
                raise
            except ConnectivityError as err:
                last_error = err
                continue

        if last_error:
            raise last_error
        raise APIError(
            f"UniFi VPN endpoint {endpoint} unavailable",
            expected=True,
        )

    @staticmethod
    def _normalize_status_text(value: Any) -> Optional[str]:
        if value in (None, ""):
            return None
        if isinstance(value, (int, float)):
            return "UP" if float(value) > 0 else "DOWN"
        if isinstance(value, bool):
            return "UP" if value else "DOWN"
        text = str(value).strip()
        if not text:
            return None
        lowered = text.lower()
        mapping = {
            "ok": "UP",
            "up": "UP",
            "connected": "UP",
            "established": "UP",
            "active": "UP",
            "running": "UP",
            "down": "DOWN",
            "disconnected": "DOWN",
            "error": "DOWN",
            "failed": "DOWN",
            "inactive": "DOWN",
        }
        if lowered in mapping:
            return mapping[lowered]
        return text.upper()

    @staticmethod
    def _normalize_vpn_type(value: Any) -> str:
        text = str(value or "").strip().lower()
        if not text:
            return "vpn"
        # heuristic mapping
        if any(k in text for k in ("client", "roadwarrior", "remote_user", "rw")):
            return "client"
        if any(k in text for k in ("server",)):
            return "server"
        if any(k in text for k in ("s2s", "site-to-site", "site_to_site", "ipsec")):
            return "s2s"
        return text

    def _normalize_vpn_tunnel(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        # identifiers
        tid = (
            rec.get("id")
            or rec.get("_id")
            or rec.get("uuid")
            or rec.get("tunnel_id")
            or rec.get("peer_id")
            or rec.get("name")
            or rec.get("peer")
        )
        if isinstance(tid, (int, float)):
            tid = str(tid)
        out["id"] = str(tid) if tid else None

        name = (
            rec.get("name")
            or rec.get("label")
            or rec.get("peer")
            or rec.get("remote")
            or rec.get("endpoint")
        )
        if not isinstance(name, str) or not name.strip():
            name = out["id"] or "VPN"
        out["name"] = str(name)

        vtype = (
            rec.get("type")
            or rec.get("mode")
            or rec.get("role")
            or rec.get("category")
            or rec.get("kind")
        )
        out["type"] = self._normalize_vpn_type(vtype)

        # status heuristics
        status_candidates = [
            rec.get("status"),
            rec.get("state"),
            rec.get("connected"),
            rec.get("is_connected"),
            rec.get("up"),
            rec.get("established"),
        ]
        status: Optional[str] = None
        for candidate in status_candidates:
            status = self._normalize_status_text(candidate)
            if status:
                break
        out["status"] = status

        # addressing / peer
        out["remote"] = (
            rec.get("remote")
            or rec.get("peer")
            or rec.get("peer_addr")
            or rec.get("peer_ip")
            or rec.get("endpoint")
            or rec.get("public_ip")
        )
        out["local"] = (
            rec.get("local")
            or rec.get("local_ip")
            or rec.get("tunnel_ip")
            or rec.get("interface_ip")
        )

        # stats
        rx = rec.get("rx_bytes") or rec.get("rx") or rec.get("bytes_rx")
        tx = rec.get("tx_bytes") or rec.get("tx") or rec.get("bytes_tx")
        if isinstance(rec.get("stats"), dict):
            rx = rx or rec["stats"].get("rx") or rec["stats"].get("rx_bytes")
            tx = tx or rec["stats"].get("tx") or rec["stats"].get("tx_bytes")
        out["rx_bytes"] = rx
        out["tx_bytes"] = tx

        since = rec.get("since") or rec.get("uptime") or rec.get("connected_since")
        out["since"] = since

        return out

    def get_vpn_tunnels(self) -> List[Dict[str, Any]]:
        """Retrieve VPN tunnel instances from the controller (best-effort)."""

        endpoints = (
            "internet/vpn/status",
            "internet/vpn/tunnels",
            "internet/vpn",
            "stat/vpn",
            "stat/s2s",
            "rest/vpn",
            "rest/vpnconf",
            "list/vpn",
            "stat/ipsec",
        )

        for endpoint in endpoints:
            try:
                payload, _ = self._call_vpn_endpoint("GET", endpoint)
            except Exception:
                continue

            records: List[Dict[str, Any]] = []
            if isinstance(payload, list):
                records = [item for item in payload if isinstance(item, dict)]
            elif isinstance(payload, dict):
                for key in ("tunnels", "connections", "items", "data", "records"):
                    value = payload.get(key)
                    if isinstance(value, list):
                        records = [item for item in value if isinstance(item, dict)]
                        break
                if not records:
                    # dict-of-dicts fallback
                    if all(isinstance(v, dict) for v in payload.values()):
                        records = [dict(v) for v in payload.values()]  # type: ignore[arg-type]

            if not records:
                continue

            normalized = [self._normalize_vpn_tunnel(rec) for rec in records]
            # keep only entries with at least a name or id
            normalized = [n for n in normalized if n.get("name") or n.get("id")]
            if normalized:
                return normalized

        return []

    # ---- Speedtest helpers (base-relative) ----
    def get_gateway_mac(self) -> Optional[str]:
        try:
            devs = self.get_devices()
        except Exception:
            devs = None
        for d in devs or []:
            t = (d.get("type") or "").lower()
            m = (d.get("model") or "").lower()
            if t in ("ugw", "udm") or m.startswith("udm") or "gateway" in (d.get("name") or "").lower():
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

    def _iter_speedtest_paths(self, endpoint: str) -> List[str]:
        """Return candidate API paths for a speedtest endpoint."""

        cleaned = str(endpoint or "").lstrip("/")
        site_id = self._ensure_site_id_sync()
        site_name = self._site_name

        candidates = [cleaned]
        candidates.append(self._site_path(cleaned))
        if site_id:
            candidates.append(self._site_path_for(site_id, cleaned))
            candidates.append(f"v2/api/site/{site_id}/{cleaned}")
        if site_name:
            candidates.append(f"v2/api/site/{site_name}/{cleaned}")

        paths: List[str] = []
        seen: set[str] = set()
        for path in candidates:
            normalized = str(path or "").lstrip("/")
            if not normalized or normalized in seen:
                continue
            seen.add(normalized)
            paths.append(normalized)
        return paths

    def _call_speedtest_endpoint(
        self,
        method: str,
        endpoint: str,
        *,
        payload: Any = None,
        timeout: Optional[int] = None,
    ) -> Tuple[Any, str]:
        """Invoke a speedtest endpoint trying multiple path variations."""

        last_error: Optional[Exception] = None
        for path in self._iter_speedtest_paths(endpoint):
            try:
                if method.upper() == "GET":
                    response = self._request_json("GET", path, timeout=timeout)
                else:
                    response = self._request_json(
                        method.upper(),
                        path,
                        json_payload=payload,
                        timeout=timeout,
                    )
                return response, path
            except APIError as err:
                last_error = err
                if err.status_code in (404, 405) or err.expected:
                    continue
                if err.status_code == 400 and method.upper() == "GET":
                    continue
                raise
            except ConnectivityError as err:
                last_error = err
                continue

        if last_error:
            raise last_error
        raise APIError(
            f"UniFi speedtest endpoint {endpoint} unavailable",
            expected=True,
        )

    def _enable_speedtest_flags(self, payload: Any) -> bool:
        """Ensure logging/monitoring flags are enabled within the payload."""

        changed = False
        if isinstance(payload, dict):
            for key, value in list(payload.items()):
                lower_key = key.lower()
                if any(term in lower_key for term in ("logging", "monitor")) and (
                    "enable" in lower_key or lower_key.endswith("enabled")
                ):
                    if isinstance(value, bool):
                        if not value:
                            payload[key] = True
                            changed = True
                    elif isinstance(value, (int, float)):
                        if not value:
                            payload[key] = 1
                            changed = True
                    elif isinstance(value, str):
                        if value.strip().lower() in {"0", "false", "disabled", "off"}:
                            payload[key] = True
                            changed = True
                if isinstance(value, (dict, list)):
                    if self._enable_speedtest_flags(value):
                        changed = True
        elif isinstance(payload, list):
            for item in payload:
                if self._enable_speedtest_flags(item):
                    changed = True
        return changed

    def ensure_speedtest_monitoring_enabled(self, cache_sec: int = 3600) -> None:
        """Make sure controller-side logging/monitoring toggles required for speedtest are on."""

        now = time.time()
        last_check = getattr(self, "_st_settings_check", 0.0)
        if now - last_check < cache_sec:
            return

        setattr(self, "_st_settings_check", now)

        try:
            settings_payload, path = self._call_speedtest_endpoint(
                "GET", "internet/speedtest/settings"
            )
        except Exception as err:
            LOGGER.debug("Unable to fetch speedtest settings: %s", err)
            return

        if not self._enable_speedtest_flags(settings_payload):
            return

        try:
            self._request_json("POST", path, json_payload=settings_payload)
            LOGGER.debug("Enabled UniFi speedtest logging/monitoring via %s", path)
        except Exception as err:
            LOGGER.debug("Failed to persist speedtest settings via %s: %s", path, err)

    def start_speedtest(self, mac: Optional[str] = None):
        if mac is None:
            mac = self.get_gateway_mac()
        payload = {"cmd": "speedtest"}
        if mac:
            payload["mac"] = mac
        try:
            result, _ = self._call_speedtest_endpoint("POST", "cmd/devmgr", payload=payload)
            # Record the trigger time to avoid immediate duplicate runs from other paths
            try:
                self._st_last_trigger = time.time()
            except Exception:
                pass
            return result
        except Exception:
            result, _ = self._call_speedtest_endpoint(
                "POST", "internet/speedtest/run", payload={}
            )
            try:
                self._st_last_trigger = time.time()
            except Exception:
                pass
            return result

    def get_speedtest_status(self, mac: Optional[str] = None):
        if mac is None:
            mac = self.get_gateway_mac()
        payload = {"cmd": "speedtest-status"}
        if mac:
            payload["mac"] = mac
        try:
            result, _ = self._call_speedtest_endpoint("POST", "cmd/devmgr", payload=payload)
            return result
        except Exception:
            pass

        for method in ("GET", "POST"):
            try:
                payload_arg = {} if method == "POST" else None
                result, _ = self._call_speedtest_endpoint(
                    method, "internet/speedtest/status", payload=payload_arg
                )
                return result
            except Exception:
                continue
        raise APIError("Unable to retrieve UniFi speedtest status", expected=True)

    def get_speedtest_history(self, start_ms: Optional[int] = None, end_ms: Optional[int] = None):
        if end_ms is None:
            end_ms = int(time.time() * 1000)
        if start_ms is None:
            start_ms = end_ms - 7 * 24 * 60 * 60 * 1000
        payload = {
            "attrs": [
                "xput_download",
                "xput_upload",
                "latency",
                "rundate",
                "server",
            ],
            "start": start_ms,
            "end": end_ms,
        }
        try:
            result, _ = self._call_speedtest_endpoint(
                "POST", "stat/report/archive.speedtest", payload=payload
            )
            if isinstance(result, list):
                return result
            return self._extract_list(result)
        except Exception:
            result, _ = self._call_speedtest_endpoint("GET", "internet/speedtest/results")
            if isinstance(result, list):
                return result
            return self._extract_list(result)

    @staticmethod
    def _coerce_float(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _coerce_nested_float(value: Any) -> Optional[float]:
        result = UniFiOSClient._coerce_float(value)
        if result is not None:
            return result
        if isinstance(value, dict):
            preferred_keys = (
                "bandwidth",
                "throughput",
                "speed",
                "rate",
                "latency",
                "jitter",
                "value",
                "avg",
                "average",
                "mean",
                "median",
                "current",
                "last",
            )
            for key in preferred_keys:
                if key in value:
                    nested = UniFiOSClient._coerce_nested_float(value.get(key))
                    if nested is not None:
                        return nested
            for nested_value in value.values():
                nested = UniFiOSClient._coerce_nested_float(nested_value)
                if nested is not None:
                    return nested
        if isinstance(value, (list, tuple, set)):
            for item in value:
                nested = UniFiOSClient._coerce_nested_float(item)
                if nested is not None:
                    return nested
        return None

    @staticmethod
    def _extract_speedtest_metric(
        rec: Dict[str, Any], candidates: Sequence[Tuple[str, float]]
    ) -> Optional[float]:
        for key, multiplier in candidates:
            if key not in rec:
                continue
            raw_value = rec.get(key)
            if isinstance(raw_value, dict):
                if "bandwidth" in raw_value:
                    bandwidth = UniFiOSClient._coerce_nested_float(
                        raw_value.get("bandwidth")
                    )
                    if bandwidth is not None:
                        return bandwidth * 8e-6
                if "latency" in raw_value and key in {"ping", "latency", "latency_ms"}:
                    latency = UniFiOSClient._coerce_nested_float(raw_value.get("latency"))
                    if latency is not None:
                        return latency
            value = UniFiOSClient._coerce_nested_float(raw_value)
            if value is None:
                continue
            return value * multiplier
        return None

    @staticmethod
    def _format_speedtest_rundate(value: Any) -> Optional[str]:
        if value is None or value == "":
            return None
        if isinstance(value, str):
            return value
        try:
            number = float(value)
        except (TypeError, ValueError):
            return str(value)
        if number > 1e11:
            number /= 1000.0
        try:
            dt = datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return str(value)
        return dt.isoformat()

    @staticmethod
    def _parse_speedtest_server_details(value: Any) -> Dict[str, Any]:
        if isinstance(value, dict):
            return dict(value)
        if isinstance(value, str):
            text = value.strip()
            if not text:
                return {}
            try:
                parsed = json.loads(text)
                if isinstance(parsed, dict):
                    return parsed
            except ValueError:
                pass
            details: Dict[str, Any] = {}
            parts = [segment.strip() for segment in text.split(",") if segment.strip()]
            for part in parts:
                if ":" in part:
                    key, val = part.split(":", 1)
                    details[key.strip()] = val.strip()
            if "name" not in details:
                details["name"] = text
            return details
        return {}

    def _normalize_speedtest_record(self, rec: Dict[str, Any]) -> Dict[str, Any]:
        out = {}
        download_candidates: Tuple[Tuple[str, float], ...] = (
            ("download_mbps", 1.0),
            ("download_Mbps", 1.0),
            ("download", 1.0),
            ("speedtest_download", 1.0),
            ("xput_download", 1.0),
            ("xput_download_mbps", 1.0),
            ("xput_down", 1.0),
            ("xput_down_mbps", 1.0),
            ("download_kbps", 1e-3),
            ("xput_download_kbps", 1e-3),
            ("xput_down_kbps", 1e-3),
            ("download_bps", 1e-6),
            ("xput_download_bps", 1e-6),
            ("xput_down_bps", 1e-6),
            ("download_bytes_per_second", 8e-6),
        )
        upload_candidates: Tuple[Tuple[str, float], ...] = (
            ("upload_mbps", 1.0),
            ("upload_Mbps", 1.0),
            ("upload", 1.0),
            ("speedtest_upload", 1.0),
            ("xput_upload", 1.0),
            ("xput_upload_mbps", 1.0),
            ("xput_up", 1.0),
            ("xput_up_mbps", 1.0),
            ("upload_kbps", 1e-3),
            ("xput_upload_kbps", 1e-3),
            ("xput_up_kbps", 1e-3),
            ("upload_bps", 1e-6),
            ("xput_upload_bps", 1e-6),
            ("xput_up_bps", 1e-6),
            ("upload_bytes_per_second", 8e-6),
        )
        latency_candidates: Tuple[Tuple[str, float], ...] = (
            ("latency_ms", 1.0),
            ("latency", 1.0),
            ("latency_avg", 1.0),
            ("latency_average", 1.0),
            ("latency_mean", 1.0),
            ("ping_ms", 1.0),
            ("ping", 1.0),
            ("speedtest_ping", 1.0),
            ("latency_us", 1e-3),
            ("ping_us", 1e-3),
            ("latency_ns", 1e-6),
        )

        dl = self._extract_speedtest_metric(rec, download_candidates)
        ul = self._extract_speedtest_metric(rec, upload_candidates)
        ping = self._extract_speedtest_metric(rec, latency_candidates)
        if dl is not None:
            out["download_mbps"] = float(dl)
        if ul is not None:
            out["upload_mbps"] = float(ul)
        if ping is not None:
            out["latency_ms"] = float(ping)
        if "rundate" in rec:
            formatted_rundate = self._format_speedtest_rundate(rec["rundate"])
            out["rundate"] = (
                formatted_rundate if formatted_rundate is not None else rec["rundate"]
            )
        else:
            for alt_key in ("timestamp", "time", "date", "start_time"):
                if alt_key not in rec:
                    continue
                formatted_rundate = self._format_speedtest_rundate(rec[alt_key])
                out["rundate"] = (
                    formatted_rundate if formatted_rundate is not None else rec[alt_key]
                )
                break
        if "server" in rec:
            server_raw = rec["server"]
            out["server"] = server_raw
            server_details = self._parse_speedtest_server_details(server_raw)

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

            _assign("server_id", ["id", "serverid", "server_id"])
            _assign("server_name", ["name", "server", "label"])
            _assign("server_city", ["city", "location"])
            if "server_city" not in out and "server_name" in out:
                out["server_city"] = out["server_name"]
            _assign("server_cc", ["cc", "country_code"])
            _assign("server_country", ["country"])
            _assign("server_lat", ["lat", "latitude"], converter=self._coerce_float)
            _assign("server_long", ["long", "lon", "lng"], converter=self._coerce_float)
            _assign("server_provider", ["provider", "sponsor"])
            _assign("server_provider_url", ["provider_url", "url"])
            _assign("server_host", ["host", "hostname", "fqdn"])
        if "status" in rec:
            status_value = rec["status"]
            if isinstance(status_value, dict):
                status_value = (
                    status_value.get("status")
                    or status_value.get("state")
                    or status_value.get("value")
                )
            out["status"] = status_value
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
                # Only trust status payloads that carry actual values or timestamps.
                has_values = any(
                    out.get(key) not in (None, "") for key in ("download_mbps", "upload_mbps", "latency_ms")
                )
                has_timestamp = out.get("rundate") not in (None, "")
                if has_values or has_timestamp:
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
            self.ensure_speedtest_monitoring_enabled(cache_sec=cooldown_sec)
        except Exception as err:
            LOGGER.debug("Unable to ensure speedtest settings prior to run: %s", err)
        try:
            self.start_speedtest(self.get_gateway_mac())
            self._st_last_trigger = now
        except Exception:
            return
