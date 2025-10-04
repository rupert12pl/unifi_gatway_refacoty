
from __future__ import annotations

import hashlib
import json
import logging
import re
import socket
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Mapping, Optional, Sequence, Tuple

from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover - for typing only
    import requests

from .const import DEFAULT_SITE


DEFAULT_ACTIVE_WINDOW_SEC = 120
UNAVAILABLE_ENDPOINT_RETRY_SEC = 1800
_VPN_NET_ID_KEYS = (
    "networkconf_id",
    "network_id",
    "listen_networkconf_id",
    "client_network_id",
    "vpn_network_id",
    "lan_network_id",
    "user_group_network_id",
)


_LOGGER = logging.getLogger(__name__)


class _RetryingLogFilter(logging.Filter):
    """Suppress noisy urllib3 retry warnings that we handle ourselves."""

    def filter(self, record: logging.LogRecord) -> bool:  # pragma: no cover - logging guard
        message = record.getMessage()
        return not (isinstance(message, str) and message.startswith("Retrying (Retry("))


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
    @staticmethod
    def _requests_module():
        import requests

        return requests

    @staticmethod
    def _configure_retry_logging() -> None:
        """Install retry log filters for both urllib3 and Requests vendored loggers."""

        for name in ("urllib3.connectionpool", "requests.packages.urllib3.connectionpool"):
            logger = logging.getLogger(name)
            for existing in logger.filters:
                if isinstance(existing, _RetryingLogFilter):
                    break
            else:
                logger.addFilter(_RetryingLogFilter())

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
        self._configure_retry_logging()
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

        requests = self._requests_module()
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry

        self._session = requests.Session()
        self._session.verify = ssl_verify
        if not ssl_verify:
            from urllib3 import disable_warnings
            from urllib3.exceptions import InsecureRequestWarning

            disable_warnings(InsecureRequestWarning)
            _LOGGER.debug(
                "SSL verification disabled for UniFi controller – suppressing InsecureRequestWarning"
            )
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

        self._csrf: Optional[str] = None
        if not self._username or not self._password:
            raise AuthError("Provide username and password for UniFi controller")

        preferred_ports: list[int] = [port]
        if port == 443:
            preferred_ports.append(8443)
        elif port == 8443:
            preferred_ports.append(443)

        attempted: set[int] = set()
        last_connectivity_error: ConnectivityError | None = None

        for candidate_port in preferred_ports:
            if candidate_port in attempted:
                continue
            attempted.add(candidate_port)
            self._port = candidate_port
            try:
                self._login(host, candidate_port, ssl_verify, timeout)
                self._ensure_connected()
            except AuthError:
                raise
            except ConnectivityError as err:
                last_connectivity_error = err
                _LOGGER.debug(
                    "Connectivity error connecting to UniFi controller %s:%s: %s",
                    host,
                    candidate_port,
                    err,
                )
                continue
            except APIError:
                # API errors indicate the controller responded, so bubbling up the
                # exception gives clearer feedback than silently retrying.
                raise
            else:
                if candidate_port != port:
                    _LOGGER.info(
                        "Connected to UniFi controller %s using fallback port %s after %s failed",
                        host,
                        candidate_port,
                        port,
                    )
                break
        else:
            if last_connectivity_error is not None:
                raise last_connectivity_error
            raise ConnectivityError(
                f"Unable to connect to UniFi controller on ports {preferred_ports}"
            )

        self._base = self._join(self._site_path())

        # Stable instance identifier – must NOT depend on autodetected _base so that
        # Home Assistant keeps existing entities when the controller path changes
        # between /proxy/network, /network and /v2 variants.
        basis = f"{self._net_base()}|{host}|{site_id}|{instance_hint or ''}"
        self._iid = hashlib.sha256(basis.encode()).hexdigest()[:12]

        self._active_window = DEFAULT_ACTIVE_WINDOW_SEC

        # caches used by advanced VPN discovery helpers
        self._leases_cache: Optional[Tuple[float, List[Dict[str, Any]]]] = None
        self._clients_v2_cache: Optional[Tuple[float, List[Dict[str, Any]]]] = None
        self._vpn_servers_cache: Optional[Tuple[float, List[Dict[str, Any]]]] = None
        self._vpn_sessions_cache: Optional[Tuple[float, Dict[str, Dict[str, int]]]] = None
        self._st_cache: Optional[tuple[float, Dict[str, Any] | None]] = None
        self._unavailable_paths: dict[str, float] = {}
        self._supports_stat_alert: Optional[bool] = None
        self._internet_api_supported: Optional[bool] = None

    def close(self) -> None:
        """Close the underlying HTTP session."""

        session = getattr(self, "_session", None)
        if session is not None:
            session.close()

    @property
    def port(self) -> int:
        """Return the port used for the active UniFi controller session."""

        return self._port

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
            cleaned = cleaned[len("proxy/network/"):]
        if cleaned.startswith("network/") and self._path_prefix.strip("/") == "network":
            cleaned = cleaned[len("network/"):]
        prefix = self._path_prefix.strip("/")
        if prefix and cleaned.startswith(f"{prefix}/"):
            cleaned = cleaned[len(prefix) + 1:]
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
            if self._is_path_unavailable(path):
                _LOGGER.debug("Skipping previously unavailable site-id path %s", path)
                continue
            try:
                resp, text = self._request("GET", path, timeout=6)
            except APIError as err:  # pragma: no cover - defensive network guard
                if err.expected:
                    self._mark_path_unavailable(path)
                _LOGGER.debug("Site-id probe %s failed: %s", path, err)
                continue
            except Exception as err:  # pragma: no cover - defensive network guard
                _LOGGER.debug("Site-id probe %s failed: %s", path, err)
                continue

            if resp.status_code >= 400:
                continue

            try:
                payload = json.loads(text) if text else {}
            except json.JSONDecodeError:  # pragma: no cover - defensive
                _LOGGER.debug("Invalid JSON while probing site id from %s", path)
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
                        _LOGGER.debug(
                            "Resolved site id %s for site %s", site_id, self._site_name
                        )
                        return self._site_id

        _LOGGER.debug("Falling back to site name for site-id lookups: %s", self._site_name)
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

    def _update_csrf_token(self, response: "requests.Response") -> None:
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
        requests = self._requests_module()

        for path in ("/api/auth/csrf", "/api/csrf"):
            url = f"{base_url}{path}"
            try:
                response = self._session.get(url, timeout=timeout, allow_redirects=False)
            except requests.exceptions.RequestException as err:  # pragma: no cover - network guard
                _LOGGER.debug("Fetching CSRF token from %s failed: %s", url, err)
                continue
            if response.status_code >= 400:
                _LOGGER.debug(
                    "CSRF probe %s returned HTTP %s", url, response.status_code
                )
                continue
            self._update_csrf_token(response)
            if self._csrf:
                _LOGGER.debug("CSRF token refreshed from %s", url)
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
    ) -> tuple["requests.Response", str]:
        url = self._join(path)
        req_timeout = timeout or self._timeout
        kwargs: Dict[str, Any] = {"timeout": req_timeout, "allow_redirects": False}
        if params:
            kwargs["params"] = params
        if json_payload is not None:
            kwargs["json"] = json_payload
        if data is not None:
            kwargs["data"] = data
        label = self._login_endpoint_label(url)
        _LOGGER.debug("UniFi request %s %s initiated", method, label)
        requests = self._requests_module()

        start = time.perf_counter()
        try:
            response = self._session.request(method, url, **kwargs)
        except requests.exceptions.SSLError as err:
            message = self._shorten(str(err))
            _LOGGER.error(
                "UniFi request %s %s failed during SSL negotiation: %s",
                method,
                label,
                message,
            )
            raise ConnectivityError(
                f"SSL error while connecting to {url}: {err}", url=url
            ) from err
        except requests.exceptions.ConnectTimeout as err:
            message = self._shorten(str(err))
            _LOGGER.error(
                "UniFi request %s %s timed out: %s",
                method,
                label,
                message,
            )
            raise ConnectivityError(
                f"Timeout while connecting to {url}: {err}", url=url
            ) from err
        except requests.exceptions.ConnectionError as err:
            message = self._shorten(str(err))
            _LOGGER.error(
                "UniFi request %s %s connection error: %s",
                method,
                label,
                message,
            )
            raise ConnectivityError(
                f"Connection error while reaching {url}: {err}", url=url
            ) from err
        except requests.exceptions.RequestException as err:
            message = self._shorten(str(err))
            _LOGGER.error(
                "UniFi request %s %s failed: %s",
                method,
                label,
                message,
            )
            raise ConnectivityError(
                f"Request {method} {url} failed: {err}", url=url
            ) from err

        self._update_csrf_token(response)

        status = response.status_code
        body_preview = self._shorten(response.text)
        duration_ms = int((time.perf_counter() - start) * 1000)
        if status in (401, 403):
            _LOGGER.error(
                "UniFi request %s %s failed (status=%s, duration_ms=%d, body=%s)",
                method,
                label,
                status,
                duration_ms,
                body_preview,
            )
            raise AuthError(
                "Authentication with UniFi controller failed",
                status_code=status,
                url=url,
                body=body_preview,
            )
        if status >= 400:
            is_expected = status == 404 or (
                status == 400
                and body_preview is not None
                and "api.err.Invalid" in body_preview
            )
            log_func = _LOGGER.debug if is_expected else _LOGGER.error
            log_func(
                "UniFi request %s %s failed (status=%s, duration_ms=%d, body=%s)",
                method,
                label,
                status,
                duration_ms,
                body_preview,
            )
            raise APIError(
                f"UniFi API call {method} {url} failed with HTTP {status}",
                status_code=status,
                url=url,
                expected=is_expected,
                body=body_preview,
            )
        _LOGGER.debug(
            "UniFi request %s %s succeeded (status=%s, duration_ms=%d)",
            method,
            label,
            status,
            duration_ms,
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

    @staticmethod
    def _normalize_path(path: str) -> str:
        return str(path or "").lstrip("/")

    @staticmethod
    def _strip_network_prefix(path: str) -> str:
        """Remove known network proxy prefixes from ``path``."""

        normalized = UniFiOSClient._normalize_path(path)
        for prefix in ("proxy/network/", "network/"):
            if normalized.startswith(prefix):
                normalized = normalized[len(prefix) :]
        return normalized

    def _is_path_unavailable(self, path: str) -> bool:
        normalized = self._normalize_path(path)
        if not normalized:
            return False
        expiry = self._unavailable_paths.get(normalized)
        if not expiry:
            return False
        if time.monotonic() < expiry:
            return True
        self._unavailable_paths.pop(normalized, None)
        return False

    def _mark_path_unavailable(self, path: str) -> None:
        normalized = self._normalize_path(path)
        if not normalized:
            return
        expiry = time.monotonic() + UNAVAILABLE_ENDPOINT_RETRY_SEC
        existing = self._unavailable_paths.get(normalized)
        if not existing or existing < expiry:
            self._unavailable_paths[normalized] = expiry
            _LOGGER.debug("Marking UniFi endpoint %s unavailable", normalized)

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
            label = self._login_endpoint_label(response.url)
            _LOGGER.debug(
                "UniFi request %s %s returned non-JSON payload: %s",
                method,
                label,
                self._shorten(text),
            )
            return text
        try:
            return self._process_payload(payload, response.url)
        except APIError as err:
            label = self._login_endpoint_label(response.url)
            log_func = _LOGGER.debug if err.expected else _LOGGER.error
            log_func(
                "UniFi request %s %s returned controller error: %s",
                method,
                label,
                err,
            )
            raise

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
        if self._is_path_unavailable(path):
            _LOGGER.debug("Skipping previously unavailable UniFi endpoint %s", path)
            return []
        try:
            payload = self._request_json("GET", path, timeout=timeout)
        except APIError as err:
            if err.expected:
                self._mark_path_unavailable(path)
                _LOGGER.debug("UniFi endpoint %s unavailable: %s", path, err)
                return []
            raise
        return self._extract_list(payload)

    def _post(self, path: str, payload: Dict[str, Any], *, timeout: Optional[int] = None) -> Any:
        return self._request_json("POST", path, json_payload=payload, timeout=timeout)

    def _get(self, path: str, *, timeout: Optional[int] = None) -> Any:
        return self._request_json("GET", path, timeout=timeout)

    def _login(self, host: str, port: int, ssl_verify: bool, timeout: int) -> None:
        requests = self._requests_module()

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
            # Do not log the resolved endpoint to avoid leaking credentials on misconfigured hosts
            _LOGGER.debug("Attempting UniFi login")
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
                _LOGGER.debug("UniFi login attempt failed: %s", err)
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
                _LOGGER.debug("UniFi login endpoint not found (HTTP 404)")
                last_error = APIError(
                    f"Login endpoint {url} not found",
                    status_code=status,
                    url=url,
                    expected=True,
                    body=body_preview,
                )
                continue
            if status >= 400:
                _LOGGER.debug("UniFi login attempt returned HTTP %s", status)
                last_error = APIError(
                    f"Login attempt failed with HTTP {status}",
                    status_code=status,
                    url=url,
                    body=body_preview,
                )
                continue

            _LOGGER.debug("UniFi login succeeded")
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
            _LOGGER.debug(
                "Probing UniFi Network API base %s using %s", candidate_base, probe_path
            )
            try:
                payload = self._request_json("GET", probe_path, timeout=6)
            except AuthError:
                raise
            except ConnectivityError as err:
                _LOGGER.debug("Connectivity error probing %s: %s", candidate_base, err)
                last_error = err
                continue
            except APIError as err:
                _LOGGER.debug("API error probing %s: %s", candidate_base, err)
                if err.status_code == 404 or err.expected:
                    last_error = err
                    continue
                raise

            if isinstance(payload, dict):
                payload = self._process_payload(payload, candidate_base)
            _LOGGER.debug("Selected UniFi Network API base %s", candidate_base)
            self._base = candidate_base
            return

        if last_error:
            raise last_error
        raise ConnectivityError("Unable to determine UniFi Network API base path")

    def get_healthinfo(self) -> List[Dict[str, Any]]:
        return self._get_list(self._site_path("stat/health"))

    def get_alerts(self) -> List[Dict[str, Any]]:
        """Return the active UniFi alerts, preferring modern endpoints."""

        modern_paths = ("list/alarm", "stat/alarm")
        for path in modern_paths:
            alerts = self._get_list(self._site_path(path))
            if alerts:
                return alerts

        stat_alert_path = self._site_path("stat/alert")
        if self._supports_stat_alert is False:
            return []

        if self._is_path_unavailable(stat_alert_path):
            if self._supports_stat_alert is None:
                self._supports_stat_alert = False
            _LOGGER.debug("Skipping unavailable legacy alerts endpoint %s", stat_alert_path)
            return []

        alerts = self._get_list(stat_alert_path)
        if alerts:
            self._supports_stat_alert = True
            return alerts

        if self._supports_stat_alert is None and self._is_path_unavailable(stat_alert_path):
            self._supports_stat_alert = False
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

    def get_active_clients_v2(self, cache_sec: int = 5) -> List[Dict[str, Any]]:
        """Return active client list from the UniFi Network v2 API if available."""

        now = time.time()
        if self._clients_v2_cache and (now - self._clients_v2_cache[0]) < cache_sec:
            return self._clients_v2_cache[1]

        query = "clients/active?includeTrafficUsage=true&includeUnifiDevices=true"
        clients: List[Dict[str, Any]] = []
        last_error: Optional[Exception] = None

        for path in self._iter_speedtest_paths(query):
            try:
                payload = self._request_json("GET", path, timeout=6)
            except APIError as err:
                last_error = err
                if err.status_code in (404, 405) or err.expected or err.status_code == 400:
                    continue
                raise
            except ConnectivityError as err:
                last_error = err
                continue

            if isinstance(payload, list):
                clients = [item for item in payload if isinstance(item, dict)]
                break
            if isinstance(payload, dict):
                data = payload.get("data")
                if isinstance(data, list):
                    clients = [item for item in data if isinstance(item, dict)]
                    break

        if not clients and last_error:
            _LOGGER.debug("Active clients v2 endpoint unavailable: %s", last_error)

        self._clients_v2_cache = (now, clients)
        return clients

    def _leases_fetch(self) -> List[Dict[str, Any]]:
        paths = (
            "stat/lease",
            "list/lease",
            "list/dhcpleases",
            "stat/dhcpleases",
            "rest/dhcpleases",
        )
        for path in paths:
            try:
                payload = self._request_json("GET", self._site_path(path))
            except APIError:
                continue
            except ConnectivityError:
                continue

            if isinstance(payload, list):
                return [item for item in payload if isinstance(item, dict)]
            if isinstance(payload, dict):
                for value in payload.values():
                    if isinstance(value, list):
                        return [item for item in value if isinstance(item, dict)]
        return []

    def get_dhcp_leases(self, cache_sec: int = 8) -> List[Dict[str, Any]]:
        """Return cached DHCP leases from the controller."""

        now = time.time()
        if self._leases_cache and (now - self._leases_cache[0]) < cache_sec:
            return self._leases_cache[1]

        leases = self._leases_fetch()
        self._leases_cache = (now, leases)
        return leases

    @staticmethod
    def _lease_is_active(lease: Dict[str, Any], now_ts: float) -> bool:
        if "expired" in lease:
            try:
                return not bool(lease.get("expired"))
            except Exception:  # pragma: no cover - defensive  # nosec B110
                pass
        if "is_active" in lease:
            try:
                return bool(lease.get("is_active"))
            except Exception:  # pragma: no cover - defensive  # nosec B110
                pass
        end = lease.get("end") or lease.get("expires") or lease.get("expire_time")
        if end is None:
            return True
        try:
            end_ts = float(end)
        except (TypeError, ValueError):
            return True
        if end_ts > 1e12:
            end_ts /= 1000.0
        return now_ts < end_ts

    def is_client_active(self, client: Dict[str, Any], now_ts: float) -> bool:
        """Determine if a client record should be considered active."""

        status = str(client.get("status") or client.get("state") or "").lower()
        if status in {"online", "connected", "up", "active", "authorized"}:
            return True

        if client.get("is_online") is True or client.get("connected") is True:
            return True

        try:
            uptime = int(client.get("uptime", 0))
        except (TypeError, ValueError):
            uptime = 0
        if uptime > 0:
            return True

        for key in ("rx_bytes-r", "tx_bytes-r", "rx_rate", "tx_rate"):
            try:
                if float(client.get(key, 0)) > 0:
                    return True
            except (TypeError, ValueError):
                continue

        for key in ("last_seen", "last_seen_ts"):
            ts = client.get(key)
            if ts is None:
                continue
            try:
                ts_value = float(ts)
            except (TypeError, ValueError):
                continue
            if ts_value > 1e12:
                ts_value /= 1000.0
            if (now_ts - ts_value) <= self._active_window:
                return True

        return False

    def _vpn_type_from(self, server: Dict[str, Any]) -> str:
        text = " ".join(
            str(server.get(key, "")).lower()
            for key in (
                "type",
                "vpn_type",
                "protocol",
                "proto",
                "impl",
                "implementation",
                "name",
                "display_name",
                "server_name",
                "mode",
            )
        )
        if "openvpn" in text:
            return "OpenVPN"
        if "wireguard" in text or "wg" in text:
            return "WireGuard"
        if "l2tp" in text and "ipsec" in text:
            return "L2TP/IPsec"
        if "ipsec" in text or "ikev2" in text:
            return "IPsec/IKEv2"
        if "l2tp" in text:
            return "L2TP"
        if "pptp" in text:
            return "PPTP"
        return "Unknown"

    def get_vpn_servers(
        self, cache_sec: int = 8, *, net_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Return VPN server definitions discovered on the controller."""

        now = time.time()
        if (
            net_id is None
            and self._vpn_servers_cache
            and (now - self._vpn_servers_cache[0]) < cache_sec
        ):
            return self._vpn_servers_cache[1]

        candidates: List[Dict[str, Any]] = []
        for endpoint in (
            "internet/vpn/servers",
            "internet/vpn",
            "stat/vpn",
            "list/vpn",
        ):
            try:
                payload, _ = self._call_vpn_endpoint("GET", endpoint)
            # Allow transient controller errors when probing VPN endpoints.
            except Exception:  # nosec B112
                continue

            records: List[Dict[str, Any]] = []
            if isinstance(payload, list):
                records = [item for item in payload if isinstance(item, dict)]
            elif isinstance(payload, dict):
                servers = payload.get("servers")
                if isinstance(servers, list):
                    records = [item for item in servers if isinstance(item, dict)]
                if not records:
                    for value in payload.values():
                        if isinstance(value, list):
                            records = [item for item in value if isinstance(item, dict)]
                            break

            if not records:
                continue

            for record in records:
                if not isinstance(record, dict):
                    continue
                if net_id:
                    linked = any(
                        str(record.get(key)) == str(net_id) for key in _VPN_NET_ID_KEYS
                    )
                    if not linked:
                        continue
                server = {
                    "id": record.get("_id")
                    or record.get("id")
                    or record.get("server_id")
                    or record.get("uuid"),
                    "name": record.get("name")
                    or record.get("display_name")
                    or record.get("server_name"),
                    "local_ip": record.get("local_ip")
                    or record.get("ip")
                    or record.get("wan_ip")
                    or record.get("listen_ip"),
                    "interface": record.get("interface")
                    or record.get("wan")
                    or record.get("ifname"),
                    "vpn_type": record.get("vpn_type") or self._vpn_type_from(record),
                    "active_clients": None,
                    "linked_network_id": next(
                        (record.get(key) for key in _VPN_NET_ID_KEYS if record.get(key)),
                        None,
                    ),
                    "_raw": record,
                }
                for key in (
                    "active_clients",
                    "online_clients",
                    "num_active",
                    "activePeersCount",
                    "num_peers_active",
                    "connected",
                    "connected_clients",
                ):
                    value = record.get(key)
                    if isinstance(value, list):
                        value = len(value)
                    if isinstance(value, int):
                        server["active_clients"] = value
                        break
                candidates.append(server)

        unique: Dict[str, Dict[str, Any]] = {}
        for candidate in candidates:
            key = candidate.get("id") or f"name:{candidate.get('name')}"
            unique[key] = candidate

        servers = list(unique.values())
        if net_id is None:
            self._vpn_servers_cache = (now, servers)
        return servers

    def get_vpn_active_sessions_map(
        self, cache_sec: int = 8
    ) -> Dict[str, Dict[str, int]]:
        """Return active VPN session counts indexed by server and network."""

        now = time.time()
        if (
            self._vpn_sessions_cache
            and (now - self._vpn_sessions_cache[0]) < cache_sec
        ):
            return self._vpn_sessions_cache[1]

        by_server: Dict[str, int] = {}
        by_network: Dict[str, int] = {}

        def _inc(target: Dict[str, int], key: Optional[str]) -> None:
            if not key:
                return
            target[key] = target.get(key, 0) + 1

        endpoints = (
            "internet/vpn/peers",
            "internet/vpn/users",
            "internet/vpn/sessions",
            "stat/remote-user",
            "stat/remoteuser",
        )

        for endpoint in endpoints:
            try:
                payload, _ = self._call_vpn_endpoint("GET", endpoint)
            # Allow controllers without remote-user endpoints to be skipped.
            except Exception:  # nosec B112
                continue

            if not isinstance(payload, list):
                continue

            for record in payload:
                if not isinstance(record, dict):
                    continue
                active = False
                status = str(
                    record.get("state")
                    or record.get("status")
                    or ""
                ).lower()
                if status in {"connected", "up", "established", "active", "online"}:
                    active = True
                if not active:
                    ts = record.get("last_seen_ts") or record.get("last_seen")
                    if ts is not None:
                        try:
                            ts_value = float(ts)
                            if ts_value > 1e12:
                                ts_value /= 1000.0
                            if (now - ts_value) <= self._active_window:
                                active = True
                        except (TypeError, ValueError):
                            pass
                if not active and (
                    record.get("connected") is True or record.get("is_online") is True
                ):
                    active = True
                if not active:
                    try:
                        uptime = int(record.get("uptime", 0))
                        if uptime > 0:
                            active = True
                    except (TypeError, ValueError):
                        pass
                if not active:
                    continue

                server_id = record.get("server_id") or record.get("vpn_server_id")
                if server_id is None:
                    server_id = record.get("id")
                network_id: Optional[str] = None
                for key in _VPN_NET_ID_KEYS:
                    if record.get(key):
                        network_id = str(record.get(key))
                        break

                if server_id is not None:
                    _inc(by_server, str(server_id))
                if network_id is not None:
                    _inc(by_network, network_id)

        result = {"by_server": by_server, "by_net": by_network}
        self._vpn_sessions_cache = (now, result)
        return result

    def get_wan_links(self) -> List[Dict[str, Any]]:
        primary_paths = ("stat/waninfo", "stat/wan")
        for path in primary_paths:
            links = self._get_list(self._site_path(path))
            if links:
                return links

        if self._internet_api_supported is False:
            return []

        attempted_internet = False
        internet_paths = ("internet/wan", "rest/internet")
        for path in internet_paths:
            if self._internet_api_supported is False:
                break
            attempted_internet = True
            try:
                links = self._get_list(self._site_path(path))
            except APIError as err:
                if err.status_code == 400:
                    _LOGGER.debug(
                        "UniFi endpoint %s unavailable (HTTP 400): %s", path, err
                    )
                    continue
                raise
            if links:
                self._internet_api_supported = True
                return links

        if attempted_internet and self._internet_api_supported is None:
            if all(
                self._is_path_unavailable(self._site_path(path)) for path in internet_paths
            ):
                self._internet_api_supported = False
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
            if self._is_path_unavailable(path):
                _LOGGER.debug("Skipping unavailable VPN endpoint %s", path)
                continue
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
                    self._mark_path_unavailable(path)
                    continue
                if err.status_code == 400 and method.upper() == "GET":
                    self._mark_path_unavailable(path)
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
        # Ignore unexpected payload shapes when deriving MAC information.
        except Exception:  # nosec B110
            pass
        return None

    def _iter_speedtest_paths(self, endpoint: str) -> List[str]:
        """Return candidate API paths for a speedtest endpoint."""

        cleaned = self._strip_network_prefix(endpoint)
        site_id = self._ensure_site_id_sync()
        configured_site = (self._site_name or DEFAULT_SITE).strip() or DEFAULT_SITE

        base_endpoint = cleaned
        origin_site: str | None = None
        if base_endpoint.startswith("v2/api/site/"):
            remainder = base_endpoint[len("v2/api/site/") :]
            origin_site, _, tail = remainder.partition("/")
            base_endpoint = tail
        elif base_endpoint.startswith("api/s/"):
            remainder = base_endpoint[len("api/s/") :]
            origin_site, _, tail = remainder.partition("/")
            base_endpoint = tail

        base_endpoint = base_endpoint.lstrip("/")

        site_candidates: List[str] = []
        for candidate in (origin_site, site_id, configured_site):
            candidate = (candidate or "").strip()
            if candidate and candidate not in site_candidates:
                site_candidates.append(candidate)

        paths: List[str] = []
        seen: set[str] = set()

        def _add(path: str) -> None:
            normalized = self._normalize_path(path)
            if not normalized or normalized in seen:
                return
            seen.add(normalized)
            paths.append(normalized)

        original = self._normalize_path(endpoint)
        cleaned_norm = self._normalize_path(cleaned)
        _add(original)
        if cleaned_norm != original:
            _add(cleaned_norm)
        if base_endpoint:
            _add(base_endpoint)

        suffix = f"/{base_endpoint}" if base_endpoint else ""
        for site in site_candidates:
            _add(f"api/s/{site}{suffix}")
            _add(f"v2/api/site/{site}{suffix}")

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
            if self._is_path_unavailable(path):
                _LOGGER.debug("Skipping unavailable speedtest endpoint %s", path)
                continue
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
                    self._mark_path_unavailable(path)
                    continue
                if err.status_code == 400 and method.upper() == "GET":
                    self._mark_path_unavailable(path)
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
            _LOGGER.debug("Unable to fetch speedtest settings: %s", err)
            return

        if not self._enable_speedtest_flags(settings_payload):
            return

        try:
            self._request_json("POST", path, json_payload=settings_payload)
            _LOGGER.debug("Enabled UniFi speedtest logging/monitoring via %s", path)
        except Exception as err:
            _LOGGER.debug("Failed to persist speedtest settings via %s: %s", path, err)

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
            except Exception:  # pragma: no cover - cache update is best-effort
                _LOGGER.debug("Failed to update speedtest trigger timestamp", exc_info=True)
            return result
        # Fallback to legacy endpoint when the preferred endpoint fails.
        except Exception:
            result, _ = self._call_speedtest_endpoint(
                "POST", "internet/speedtest/run", payload={}
            )
            try:
                self._st_last_trigger = time.time()
            except Exception:  # pragma: no cover - cache update is best-effort
                _LOGGER.debug("Failed to update speedtest trigger timestamp", exc_info=True)
            return result

    def restart_gateway(self, mac: Optional[str] = None):
        """Trigger a soft restart of the UniFi gateway device."""

        if mac is None:
            mac = self.get_gateway_mac()
        payload: Dict[str, Any] = {"cmd": "restart"}
        if mac:
            payload["mac"] = mac

        result, _ = self._call_speedtest_endpoint(
            "POST", "cmd/devmgr", payload=payload
        )
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
        # Fall back to legacy endpoints on controller errors.
        except Exception:  # nosec B110
            pass

        for method in ("GET", "POST"):
            try:
                payload_arg: Optional[Dict[str, Any]] = {} if method == "POST" else None
                result, _ = self._call_speedtest_endpoint(
                    method, "internet/speedtest/status", payload=payload_arg
                )
                return result
            # Some controllers implement only one of these endpoints.
            except Exception:  # nosec B112
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
        out: Dict[str, Any] = {}
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
        cache = getattr(self, "_st_cache", None)
        if cache is not None and (now - cache[0]) < cache_sec:
            return cache[1]
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
        # Cache population is best-effort; unexpected payloads are ignored.
        except Exception:  # nosec B110
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
        # Cache population is best-effort; unexpected payloads are ignored.
        except Exception:  # nosec B110
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
            _LOGGER.debug("Unable to ensure speedtest settings prior to run: %s", err)
        try:
            self.start_speedtest(self.get_gateway_mac())
            self._st_last_trigger = now
        except Exception:
            return

    def get_wan_ips_from_devices(self) -> tuple[str | None, str | None]:
        """Return WAN IPv4/IPv6 addresses discovered from the device inventory."""

        try:
            payload = self._get(self._site_path("stat/device"))
        except APIError as err:
            if getattr(err, "expected", False):
                return (None, None)
            raise

        devices = self._extract_list(payload)

        if not devices:
            return (None, None)

        ipv6_pattern = re.compile(r"\b([0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}\b", re.IGNORECASE)
        ipv4_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

        def pick_first_ipv4(obj: Mapping[str, Any]) -> str | None:
            for key in ("wan_ip", "ip_wan", "wan_ipaddr", "wan", "ip"):
                value = obj.get(key)
                if isinstance(value, str):
                    match = ipv4_pattern.search(value)
                    if match:
                        return match.group(0)
            dump = json.dumps(obj, ensure_ascii=False)
            match = ipv4_pattern.search(dump)
            return match.group(0) if match else None

        def pick_first_ipv6(obj: Mapping[str, Any]) -> str | None:
            for key in ("wan_ip6", "wan_ipv6", "ip6_wan", "ip_wan6", "ipv6", "ip6"):
                value = obj.get(key)
                if isinstance(value, str):
                    match = ipv6_pattern.search(value)
                    if match:
                        return match.group(0)

            for nested_key in ("uplink", "port_table", "network_table", "statistics"):
                nested_value = obj.get(nested_key)
                if isinstance(nested_value, Mapping):
                    hit = pick_first_ipv6(nested_value)
                    if hit:
                        return hit
                elif isinstance(nested_value, list):
                    for item in nested_value:
                        if isinstance(item, Mapping):
                            hit = pick_first_ipv6(item)
                            if hit:
                                return hit

            dump = json.dumps(obj, ensure_ascii=False)
            match = ipv6_pattern.search(dump)
            return match.group(0) if match else None

        for device in devices:
            if not isinstance(device, Mapping):
                continue
            model = str(device.get("type") or device.get("model") or "").lower()
            role = str(device.get("role") or device.get("device_role") or "").lower()
            if any(token in model for token in ("ugw", "udm")) or role in {
                "gw",
                "gateway",
                "router",
            }:
                ipv4 = pick_first_ipv4(device)
                ipv6 = pick_first_ipv6(device)
                return (ipv4, ipv6)

        return (None, None)
