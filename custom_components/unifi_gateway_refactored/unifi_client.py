"""Asynchronous UniFi Network API client."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

from aiohttp import ClientError, ClientResponse, ClientSession, ClientTimeout

from .const import (
    CLIENT_CONNECT_TIMEOUT,
    CLIENT_MAX_ATTEMPTS,
    CLIENT_SOCK_READ_TIMEOUT,
    DEFAULT_SITE,
    ERROR_CODE_5XX,
    ERROR_CODE_AUTH,
    ERROR_CODE_CLIENT,
    ERROR_CODE_TIMEOUT,
    LOG_ERROR_RATE_LIMIT,
)

LOGGER = logging.getLogger(__package__)

_LOGIN_ENDPOINTS: tuple[tuple[str, dict[str, Any], bool], ...] = (
    (
        "/api/auth/login",
        {"username": "{username}", "password": "{password}", "rememberMe": True},
        True,
    ),
    (
        "/api/login",
        {"username": "{username}", "password": "{password}", "remember": True},
        True,
    ),
    ("/login", {"username": "{username}", "password": "{password}"}, False),
)

RETRYABLE_HTTP_STATUS = {500, 502, 503, 504}


def _shorten(text: str, limit: int = 160) -> str:
    if len(text) <= limit:
        return text
    return text[: limit - 3] + "..."


@dataclass
class _RateLimiter:
    cooldown: float
    last_ts: float = 0.0

    def allow(self) -> bool:
        now = time.monotonic()
        if now - self.last_ts >= self.cooldown:
            self.last_ts = now
            return True
        return False


class UniFiClientError(Exception):
    """Base exception for UniFi client errors."""

    def __init__(
        self,
        message: str,
        *,
        code: str | None = None,
        status: int | None = None,
        endpoint: str | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.status = status
        self.endpoint = endpoint


class UniFiAuthError(UniFiClientError):
    """Raised when authentication fails."""


class UniFiRequestError(UniFiClientError):
    """Raised when an HTTP request fails."""


class UniFiApiClient:
    """Asynchronous UniFi Network API client."""

    def __init__(
        self,
        *,
        session: ClientSession,
        host: str,
        username: str,
        password: str,
        port: int = 443,
        site_id: str = DEFAULT_SITE,
        verify_ssl: bool = False,
        use_proxy_prefix: bool = True,
        request_timeout: int = 10,
        instance_hint: str | None = None,
    ) -> None:
        self._session = session
        self._session.headers.update({"Accept": "application/json"})
        self._timeout = ClientTimeout(
            total=request_timeout if request_timeout > 0 else None,
            connect=CLIENT_CONNECT_TIMEOUT,
            sock_read=CLIENT_SOCK_READ_TIMEOUT,
        )
        self._host = host
        self._username = username
        self._password = password
        self._port = port
        self._site = site_id or DEFAULT_SITE
        self._verify_ssl = verify_ssl
        self._use_proxy_prefix = use_proxy_prefix
        self._csrf: str | None = None
        self._base_prefix = "/proxy/network" if use_proxy_prefix else ""
        basis = f"{host}:{port}:{self._site}:{instance_hint or ''}"
        self._iid = hashlib.sha1(basis.encode()).hexdigest()[:12]
        self._etag_cache: dict[str, tuple[str, Any]] = {}
        self._error_limiter = _RateLimiter(LOG_ERROR_RATE_LIMIT)

    # Public helpers -----------------------------------------------------------------
    def instance_key(self) -> str:
        return self._iid

    def get_controller_url(self) -> str:
        return f"https://{self._host}:{self._port}"

    def get_site(self) -> str:
        return self._site

    def get_controller_api_url(self) -> str:
        return (
            f"{self.get_controller_url()}{self._base_prefix or ''}/api/s/{self._site}"
        )

    # Internal helpers ----------------------------------------------------------------
    def _url(self, path: str) -> str:
        base = self.get_controller_url().rstrip("/")
        prefix = self._base_prefix.rstrip("/")
        cleaned = str(path or "").lstrip("/")
        if prefix:
            return f"{base}/{prefix}/{cleaned}" if cleaned else f"{base}/{prefix}"
        return f"{base}/{cleaned}" if cleaned else base

    def _site_path(self, path: str = "") -> str:
        cleaned = str(path or "").lstrip("/")
        if cleaned:
            return f"api/s/{self._site}/{cleaned}"
        return f"api/s/{self._site}"

    async def async_login(self, *, trace_id: str = "login") -> None:
        """Authenticate against UniFi OS."""

        last_error: Exception | None = None
        base = self.get_controller_url()
        for endpoint, payload_template, is_json in _LOGIN_ENDPOINTS:
            payload = {
                key: (
                    value.format(username=self._username, password=self._password)
                    if isinstance(value, str)
                    else value
                )
                for key, value in payload_template.items()
            }
            url = f"{base}{endpoint}"
            LOGGER.debug(
                "Attempting UniFi login",
                extra={
                    "event": "login",
                    "status": "attempt",
                    "endpoint": endpoint,
                    "trace_id": trace_id,
                },
            )
            try:
                async with self._session.post(
                    url,
                    json=payload if is_json else None,
                    data=None if is_json else payload,
                    ssl=self._verify_ssl,
                    timeout=self._timeout,
                ) as response:
                    await self._process_login_response(response, endpoint, trace_id)
                    return
            except UniFiClientError as err:
                last_error = err
                if isinstance(err, UniFiAuthError):
                    raise
            except (asyncio.TimeoutError, ClientError) as err:
                last_error = UniFiRequestError(
                    f"Error connecting to {endpoint}: {err}",
                    code=ERROR_CODE_TIMEOUT,
                    endpoint=endpoint,
                )
        if isinstance(last_error, Exception):
            raise last_error
        raise UniFiRequestError(
            "Unable to authenticate with UniFi controller", endpoint="login"
        )

    async def _process_login_response(
        self, response: ClientResponse, endpoint: str, trace_id: str
    ) -> None:
        status = response.status
        body_preview = _shorten(await response.text())
        self._update_csrf(response)
        if status in (401, 403):
            raise UniFiAuthError(
                "Invalid UniFi credentials",
                code=ERROR_CODE_AUTH,
                status=status,
                endpoint=endpoint,
            )
        if status == 404:
            raise UniFiRequestError(
                "Login endpoint not found",
                code=ERROR_CODE_CLIENT,
                status=status,
                endpoint=endpoint,
            )
        if status >= 400:
            raise UniFiRequestError(
                f"Login failed with HTTP {status}",
                code=ERROR_CODE_CLIENT,
                status=status,
                endpoint=endpoint,
            )
        LOGGER.info(
            "UniFi login successful",
            extra={
                "event": "login",
                "status": "ok",
                "endpoint": endpoint,
                "http_status": status,
                "trace_id": trace_id,
            },
        )
        LOGGER.debug("Login response preview: %s", body_preview)

    async def async_probe(self) -> None:
        """Determine the working API prefix by probing health endpoint."""

        prefixes: list[str] = []
        if self._use_proxy_prefix:
            prefixes.append("/proxy/network")
        prefixes.extend(["/network", ""])

        last_error: Exception | None = None
        for prefix in prefixes:
            self._base_prefix = prefix
            try:
                await self._request_json(
                    "GET",
                    self._site_path("stat/health"),
                    trace_id="probe",
                    use_cache=False,
                )
            except UniFiAuthError:
                raise
            except UniFiClientError as err:
                last_error = err
                continue
            else:
                return
        if isinstance(last_error, Exception):
            raise last_error
        raise UniFiRequestError(
            "Unable to determine UniFi API base", code=ERROR_CODE_CLIENT
        )

    async def async_request_sites(self, *, trace_id: str) -> list[dict[str, Any]]:
        return await self._get_with_candidates(
            ("api/self/sites", "api/stat/sites"), trace_id=trace_id
        )

    async def async_request_health(self, *, trace_id: str) -> list[dict[str, Any]]:
        return await self._request_json(
            "GET", self._site_path("stat/health"), trace_id=trace_id
        )

    async def async_request_alerts(self, *, trace_id: str) -> list[dict[str, Any]]:
        return await self._get_with_candidates(
            (
                self._site_path("stat/alert"),
                self._site_path("list/alarm"),
                self._site_path("stat/alarm"),
            ),
            trace_id=trace_id,
        )

    async def async_request_devices(self, *, trace_id: str) -> list[dict[str, Any]]:
        return await self._get_with_candidates(
            (
                self._site_path("stat/device"),
                self._site_path("stat/device-basic"),
            ),
            trace_id=trace_id,
        )

    async def _get_with_candidates(
        self, paths: Iterable[str], *, trace_id: str
    ) -> list[dict[str, Any]]:
        for path in paths:
            try:
                data = await self._request_json("GET", path, trace_id=trace_id)
            except UniFiRequestError as err:
                if err.status == 404:
                    continue
                raise
            if isinstance(data, list):
                return data
        return []

    async def _request_json(
        self,
        method: str,
        path: str,
        *,
        trace_id: str,
        use_cache: bool = True,
        params: Optional[dict[str, Any]] = None,
        json_payload: Optional[dict[str, Any]] = None,
    ) -> Any:
        endpoint = "/" + path.lstrip("/")
        url = self._url(path)
        etag_headers: dict[str, str] = {}
        cache_entry = self._etag_cache.get(endpoint)
        if use_cache and cache_entry:
            etag_headers["If-None-Match"] = cache_entry[0]

        headers = {}
        if self._csrf:
            headers["X-CSRF-Token"] = self._csrf

        backoff = 0.5
        for attempt in range(1, CLIENT_MAX_ATTEMPTS + 1):
            started = time.perf_counter()
            try:
                async with self._session.request(
                    method,
                    url,
                    json=json_payload,
                    params=params,
                    headers=headers | etag_headers,
                    ssl=self._verify_ssl,
                    timeout=self._timeout,
                ) as response:
                    elapsed_ms = int((time.perf_counter() - started) * 1000)
                    payload = await self._consume_response(
                        response,
                        endpoint=endpoint,
                        trace_id=trace_id,
                        elapsed_ms=elapsed_ms,
                        cache_entry=cache_entry,
                    )
                    if response.status == 304 and cache_entry:
                        return cache_entry[1]
                    etag = response.headers.get("ETag")
                    if etag:
                        self._etag_cache[endpoint] = (etag, payload)
                    return payload
            except UniFiClientError:
                raise
            except asyncio.TimeoutError as err:
                self._log_warning(
                    "Request timeout",
                    endpoint,
                    trace_id,
                    status=None,
                    code=ERROR_CODE_TIMEOUT,
                )
                if attempt >= CLIENT_MAX_ATTEMPTS:
                    self._log_error(
                        "Request timed out after retries",
                        endpoint,
                        trace_id,
                        status=None,
                        code=ERROR_CODE_TIMEOUT,
                    )
                    raise UniFiRequestError(
                        f"Timeout requesting {endpoint}",
                        code=ERROR_CODE_TIMEOUT,
                        endpoint=endpoint,
                    ) from err
                await asyncio.sleep(backoff)
            except ClientError as err:
                if attempt >= CLIENT_MAX_ATTEMPTS:
                    self._log_error(
                        "Request failed after retries",
                        endpoint,
                        trace_id,
                        status=None,
                        code=ERROR_CODE_CLIENT,
                    )
                    raise UniFiRequestError(
                        f"HTTP error calling {endpoint}: {err}",
                        code=ERROR_CODE_CLIENT,
                        endpoint=endpoint,
                    ) from err
                await asyncio.sleep(backoff)
            backoff *= 2
        raise UniFiRequestError("Unexpected request failure", endpoint=endpoint)

    async def _consume_response(
        self,
        response: ClientResponse,
        *,
        endpoint: str,
        trace_id: str,
        elapsed_ms: int,
        cache_entry: Optional[tuple[str, Any]],
    ) -> Any:
        self._update_csrf(response)
        status = response.status
        if status == 304 and cache_entry:
            self._log_debug("Received 304 Not Modified", endpoint, trace_id, status)
            return cache_entry[1]
        if status in (401, 403):
            raise UniFiAuthError(
                "UniFi authorization failure",
                code=ERROR_CODE_AUTH,
                status=status,
                endpoint=endpoint,
            )
        if status >= 400:
            text = await response.text()
            if status in RETRYABLE_HTTP_STATUS:
                self._log_warning(
                    "Server returned error", endpoint, trace_id, status, ERROR_CODE_5XX
                )
                raise UniFiRequestError(
                    f"Server error {status} for {endpoint}",
                    code=ERROR_CODE_5XX,
                    status=status,
                    endpoint=endpoint,
                )
            raise UniFiRequestError(
                f"Unexpected HTTP {status} for {endpoint}: {_shorten(text)}",
                code=ERROR_CODE_CLIENT,
                status=status,
                endpoint=endpoint,
            )

        text = await response.text()
        if not text:
            self._log_debug("Empty response", endpoint, trace_id, status, elapsed_ms)
            return None
        try:
            payload = json.loads(text)
        except json.JSONDecodeError as err:
            raise UniFiRequestError(
                f"Invalid JSON payload for {endpoint}",
                code=ERROR_CODE_CLIENT,
                status=status,
                endpoint=endpoint,
            ) from err

        if (
            isinstance(payload, dict)
            and "data" in payload
            and isinstance(payload["data"], list)
        ):
            payload = payload["data"]
        self._log_debug("Request successful", endpoint, trace_id, status, elapsed_ms)
        return payload

    def _log_debug(
        self,
        message: str,
        endpoint: str,
        trace_id: str,
        status: Optional[int],
        elapsed_ms: Optional[int] = None,
    ) -> None:
        LOGGER.debug(
            message,
            extra={
                "event": "request",
                "status": "debug",
                "endpoint": endpoint,
                "http_status": status,
                "elapsed_ms": elapsed_ms,
                "trace_id": trace_id,
            },
        )

    def _log_warning(
        self,
        message: str,
        endpoint: str,
        trace_id: str,
        status: Optional[int],
        code: str,
    ) -> None:
        LOGGER.warning(
            message,
            extra={
                "event": "request",
                "status": code,
                "endpoint": endpoint,
                "http_status": status,
                "trace_id": trace_id,
            },
        )

    def _log_error(
        self,
        message: str,
        endpoint: str,
        trace_id: str,
        status: Optional[int],
        code: str,
    ) -> None:
        if self._error_limiter.allow():
            LOGGER.error(
                message,
                extra={
                    "event": "request",
                    "status": code,
                    "endpoint": endpoint,
                    "http_status": status,
                    "trace_id": trace_id,
                },
            )

    def _update_csrf(self, response: ClientResponse) -> None:
        token = response.headers.get("X-CSRF-Token")
        if token:
            self._csrf = token

    async def async_close(self) -> None:
        """Compatibility helper for older code paths."""
        return
