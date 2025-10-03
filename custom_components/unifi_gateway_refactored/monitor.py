from __future__ import annotations

import asyncio
import logging
from time import monotonic
import uuid
from typing import Any, Protocol, Sequence

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from .const import (
    ATTR_DURATION_MS,
    ATTR_ENTITY_IDS,
    ATTR_ERROR,
    ATTR_REASON,
    ATTR_TRACE_ID,
    EVT_RUN_END,
    EVT_RUN_ERROR,
    EVT_RUN_START,
)
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)



class ResultCallback(Protocol):
    async def __call__(
        self, *, success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        ...

DEFAULT_MAX_WAIT_S = 600
DEFAULT_POLL_INTERVAL = 5.0


class SpeedtestRunner:
    """Execute UniFi speedtests via the controller API and report results."""

    def __init__(
        self,
        hass: HomeAssistant,
        entity_ids: Sequence[str],
        on_result_cb: ResultCallback,
        client: UniFiOSClient,
        coordinator: UniFiGatewayDataUpdateCoordinator,
    ) -> None:
        self.hass = hass
        self.entity_ids = self._normalize_entity_ids(entity_ids)
        self._on_result_cb = on_result_cb
        self._client = client
        self._coordinator = coordinator
        self._lock = asyncio.Lock()

    @staticmethod
    def _normalize_entity_ids(entity_ids: Sequence[str]) -> list[str]:
        """Return entity IDs stripped of blanks and duplicates while preserving order."""

        normalized: dict[str, None] = {}
        for candidate in entity_ids:
            if not candidate:
                continue
            text = str(candidate).strip()
            if text and text not in normalized:
                normalized[text] = None
        return list(normalized)

    @staticmethod
    def _record_marker(record: dict[str, Any] | None) -> tuple[Any, ...] | None:
        if not record:
            return None
        return (
            record.get("rundate"),
            record.get("download_mbps"),
            record.get("upload_mbps"),
            record.get("latency_ms"),
        )

    @staticmethod
    def _status_text(payload: Any) -> str | None:
        if payload is None:
            return None
        if isinstance(payload, str):
            payload = payload.strip()
            return payload or None
        if isinstance(payload, dict):
            candidates: list[str | None] = []
            status = payload.get("status")
            if isinstance(status, dict):
                candidates.append(SpeedtestRunner._status_text(status))
            elif isinstance(status, str):
                candidates.append(status)
            for key in ("state", "value", "error", "message"):
                value = payload.get(key)
                if isinstance(value, str):
                    candidates.append(value)
            for candidate in candidates:
                if candidate and candidate.strip():
                    return candidate.strip()
            return None
        if isinstance(payload, list):
            for item in payload:
                text = SpeedtestRunner._status_text(item)
                if text:
                    return text
            return None
        return None

    @staticmethod
    def _status_indicates_failure(status: str | None) -> bool:
        if not status:
            return False
        lowered = status.lower()
        return any(term in lowered for term in ("fail", "error", "timeout", "abort"))

    async def _async_get_last_speedtest(self, cache_sec: int = 0) -> dict[str, Any] | None:
        def _call() -> dict[str, Any] | None:
            try:
                return self._client.get_last_speedtest(cache_sec=cache_sec)
            except APIError as err:
                _LOGGER.debug("Failed to fetch last speedtest: %s", err)
                return None
            except Exception:
                _LOGGER.exception("Unexpected error while fetching last speedtest")
                return None

        return await self.hass.async_add_executor_job(_call)

    async def _async_get_speedtest_status(self) -> Any:
        def _call() -> Any:
            try:
                return self._client.get_speedtest_status()
            except APIError as err:
                _LOGGER.debug("Failed to fetch speedtest status: %s", err)
                return None
            except Exception:
                _LOGGER.exception("Unexpected error while fetching speedtest status")
                return None

        return await self.hass.async_add_executor_job(_call)

    async def _async_start_speedtest(self, trace_id: str) -> None:
        def _call() -> None:
            try:
                ensure = getattr(self._client, "ensure_speedtest_monitoring_enabled", None)
                if callable(ensure):
                    ensure(cache_sec=60)
                self._client.start_speedtest()
            except APIError as err:
                raise HomeAssistantError(f"Failed to start UniFi speedtest: {err}") from err
            except Exception as err:  # pragma: no cover - defensive
                raise HomeAssistantError("Unexpected error starting UniFi speedtest") from err

        await self.hass.async_add_executor_job(_call)

    async def _async_wait_for_result(
        self,
        trace_id: str,
        previous_marker: tuple[Any, ...] | None,
        *,
        max_wait_s: int = DEFAULT_MAX_WAIT_S,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        last_status: str | None = None
        attempt = 0

        async def _poll() -> dict[str, Any]:
            nonlocal attempt, last_status
            while True:
                attempt += 1

                record = await self._async_get_last_speedtest(cache_sec=0)
                record_status = self._status_text(record)
                if self._status_indicates_failure(record_status):
                    raise RuntimeError(
                        f"Speedtest completed with failure status: {record_status}"
                    )

                marker = self._record_marker(record)
                if record and (previous_marker is None or marker != previous_marker):
                    return record

                status_payload = await self._async_get_speedtest_status()
                status_text = self._status_text(status_payload)
                if status_text and status_text != last_status:
                    _LOGGER.debug(
                        "[%s] Speedtest status update -> %s (attempt %d)",
                        trace_id,
                        status_text,
                        attempt,
                    )
                    last_status = status_text
                if self._status_indicates_failure(status_text):
                    raise RuntimeError(
                        f"Speedtest reported failure status: {status_text}"
                    )

                await asyncio.sleep(poll_interval)

        try:
            async with asyncio.timeout(max_wait_s):
                return await _poll()
        except asyncio.TimeoutError as err:
            raise TimeoutError(
                f"Speedtest result not available within {max_wait_s}s (trace={trace_id})"
            ) from err

    async def _async_refresh_entities(self) -> None:
        try:
            await self._coordinator.async_request_refresh()
        except Exception:  # pragma: no cover - defensive logging
            _LOGGER.exception(
                "UniFi Gateway speedtest: failed to refresh entities after run"
            )

    async def _dispatch_result(
        self, *, success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        try:
            await self._on_result_cb(
                success=success,
                duration_ms=duration_ms,
                error=error,
                trace_id=trace_id,
            )
        except Exception:  # pragma: no cover - defensive logging
            _LOGGER.exception(
                "UniFi Gateway speedtest: result callback raised for %s",
                trace_id,
            )

    async def async_trigger(self, reason: str) -> None:
        """Trigger a speedtest update."""
        if self._lock.locked():
            _LOGGER.debug("Speedtest already running, ignoring trigger: %s", reason)
            return

        async with self._lock:
            trace_id = str(uuid.uuid4())
            start = monotonic()
            error: str | None = None

            _LOGGER.info(
                "[%s] Speedtest run started (reason=%s, entities=%s)",
                trace_id,
                reason,
                ", ".join(self.entity_ids),
            )

            self.hass.bus.async_fire(
                EVT_RUN_START,
                {
                    ATTR_TRACE_ID: trace_id,
                    ATTR_REASON: reason,
                    ATTR_ENTITY_IDS: self.entity_ids,
                },
            )

            try:
                previous_record = await self._async_get_last_speedtest(cache_sec=0)
                previous_marker = self._record_marker(previous_record)

                await self._async_start_speedtest(trace_id)
                result = await self._async_wait_for_result(
                    trace_id,
                    previous_marker,
                    max_wait_s=DEFAULT_MAX_WAIT_S,
                    poll_interval=DEFAULT_POLL_INTERVAL,
                )

                if result:
                    _LOGGER.info(
                        "[%s] Speedtest completed: %s/%s Mbps, %s ms",
                        trace_id,
                        result.get("download_mbps"),
                        result.get("upload_mbps"),
                        result.get("latency_ms"),
                    )
                    await self._async_refresh_entities()

                duration_ms = int((monotonic() - start) * 1000)
                self.hass.bus.async_fire(
                    EVT_RUN_END,
                    {
                        ATTR_TRACE_ID: trace_id,
                        ATTR_REASON: reason,
                        ATTR_ENTITY_IDS: self.entity_ids,
                        ATTR_DURATION_MS: duration_ms,
                    },
                )
                await self._dispatch_result(
                    success=True,
                    duration_ms=duration_ms,
                    error=None,
                    trace_id=trace_id,
                )
            except Exception as err:
                duration_ms = int((monotonic() - start) * 1000)
                error = f"{type(err).__name__}: {err}"
                _LOGGER.error(
                    "[%s] Speedtest failed after %dms: %s",
                    trace_id,
                    duration_ms,
                    error,
                )
                self.hass.bus.async_fire(
                    EVT_RUN_ERROR,
                    {
                        ATTR_TRACE_ID: trace_id,
                        ATTR_REASON: reason,
                        ATTR_ENTITY_IDS: self.entity_ids,
                        ATTR_DURATION_MS: duration_ms,
                        ATTR_ERROR: error,
                    },
                )
                await self._dispatch_result(
                    success=False,
                    duration_ms=duration_ms,
                    error=error,
                    trace_id=trace_id,
                )


__all__ = [
    "SpeedtestRunner",
    "ResultCallback",
    "DEFAULT_MAX_WAIT_S",
    "DEFAULT_POLL_INTERVAL",
]
