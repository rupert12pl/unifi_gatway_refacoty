
from __future__ import annotations

import hashlib
import json
import logging
import socket
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

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
            links = self._get_list(self._site_path(path))
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

    @staticmethod
    def _coerce_float(value: Any) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
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
            formatted_rundate = self._format_speedtest_rundate(rec["rundate"])
            out["rundate"] = (
                formatted_rundate if formatted_rundate is not None else rec["rundate"]
            )
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

            _assign("server_cc", ["cc"])
            _assign("server_city", ["city", "name"])
            _assign("server_country", ["country"])
            _assign("server_lat", ["lat", "latitude"], converter=self._coerce_float)
            _assign("server_long", ["long", "lon", "lng"], converter=self._coerce_float)
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
