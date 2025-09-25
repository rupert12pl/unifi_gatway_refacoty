from __future__ import annotations

import asyncio
import logging
import time
import uuid
from typing import Any, Awaitable, Callable, Sequence

from homeassistant.core import HomeAssistant
from homeassistant.components import persistent_notification as pn
from homeassistant.exceptions import HomeAssistantError
from homeassistant.helpers.issue_registry import IssueSeverity, async_create_issue

from .const import (
    ATTR_DURATION_MS,
    ATTR_ENTITY_IDS,
    ATTR_ERROR,
    ATTR_REASON,
    ATTR_TRACE_ID,
    DATA_RUNNER,
    DOMAIN,
    EVT_RUN_END,
    EVT_RUN_ERROR,
    EVT_RUN_START,
)
from .coordinator import UniFiGatewayDataUpdateCoordinator
from .unifi_client import APIError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)

ResultCallback = Callable[[bool, int, str | None, str], Awaitable[None]]

DEFAULT_MAX_WAIT_S = 600
DEFAULT_POLL_INTERVAL = 5.0
RETRY_DELAY_S = 5


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
        """Initialize the speedtest runner."""
        _LOGGER.debug("Initializing SpeedtestRunner with entities: %s", entity_ids)
        self.hass = hass
        self.entity_ids = [entity_id for entity_id in entity_ids if entity_id]
        self._on_result_cb = on_result_cb
        self._client = client
        self._coordinator = coordinator
        self._lock = asyncio.Lock()
        _LOGGER.debug("SpeedtestRunner initialized successfully")

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
        """Extract a textual status from a UniFi speedtest payload."""

        if payload is None:
            return None
        if isinstance(payload, list):
            for item in payload:
                text = SpeedtestRunner._status_text(item)
                if text:
                    return text
            return None
        if isinstance(payload, dict):
            candidates = []
            value = payload.get("status")
            if isinstance(value, dict):
                candidates.append(SpeedtestRunner._status_text(value))
            elif isinstance(value, str):
                candidates.append(value)
            for key in ("state", "value"):
                aux = payload.get(key)
                if isinstance(aux, str):
                    candidates.append(aux)
            for candidate in candidates:
                if candidate and candidate.strip():
                    return candidate.strip()
            return None
        if isinstance(payload, str) and payload.strip():
            return payload.strip()
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
                self._client.ensure_speedtest_monitoring_enabled(cache_sec=60)
            except Exception as err:  # pragma: no cover - defensive
                _LOGGER.debug(
                    "[%s] Unable to ensure speedtest monitoring flags: %s",
                    trace_id,
                    err,
                )
            self._client.start_speedtest()

        await self.hass.async_add_executor_job(_call)

    async def _async_wait_for_result(
        self,
        trace_id: str,
        previous_marker: tuple[Any, ...] | None,
        max_wait_s: int = DEFAULT_MAX_WAIT_S,
        poll_interval: float = DEFAULT_POLL_INTERVAL,
    ) -> dict[str, Any]:
        """Wait for speedtest results with improved error handling and logging."""
        end = time.monotonic() + max_wait_s
        last_status: str | None = None
        attempt_count = 0
        start_time = time.monotonic()

        while time.monotonic() < end:
            attempt_count += 1
            remaining_time = int(end - time.monotonic())
            elapsed_time = int(time.monotonic() - start_time)

            _LOGGER.debug(
                "[%s] Speedtest check attempt %d (elapsed: %ds, remaining: %ds)",
                trace_id,
                attempt_count,
                elapsed_time,
                remaining_time,
            )

            try:
                record = await self._async_get_last_speedtest(cache_sec=0)
                status_payload = await self._async_get_speedtest_status()
            except Exception as err:
                _LOGGER.warning(
                    "[%s] Failed to fetch speedtest data: %s",
                    trace_id,
                    err,
                )
                await asyncio.sleep(poll_interval)
                continue

            marker = self._record_marker(record)
            if record and (previous_marker is None or marker != previous_marker):
                status = record.get("status") if isinstance(record, dict) else None
                status_text = status if isinstance(status, str) else self._status_text(status)
                if self._status_indicates_failure(status_text):
                    raise RuntimeError(f"Speedtest completed with failure status: {status_text}")
                _LOGGER.debug("[%s] Speedtest completed successfully after %d attempts", trace_id, attempt_count)
                return record

            status_text = self._status_text(status_payload)
            if status_text and status_text != last_status:
                _LOGGER.debug("[%s] Speedtest status -> %s (attempt %d)", trace_id, status_text, attempt_count)
                last_status = status_text
            if self._status_indicates_failure(status_text):
                raise RuntimeError(f"Speedtest reported failure status: {status_text}")
            await asyncio.sleep(poll_interval)

        _LOGGER.warning(
            "[%s] Speedtest timed out after %d attempts (%ds elapsed)",
            trace_id,
            attempt_count,
            int(time.monotonic() - start_time),
        )
        raise TimeoutError(
            f"Speedtest result not available within {max_wait_s}s "
            f"(trace={trace_id}, attempts={attempt_count})"
        )

    async def _async_refresh_entities(self, trace_id: str) -> None:
        try:
            await self._coordinator.async_request_refresh()
        except Exception as err:  # pragma: no cover - defensive
            _LOGGER.debug(
                "[%s] Coordinator refresh failed after speedtest completion: %s",
                trace_id,
                err,
            )

    async def _dispatch_result(
        self, success: bool, duration_ms: int, error: str | None, trace_id: str
    ) -> None:
        try:
            await self._on_result_cb(success, duration_ms, error, trace_id)
        except Exception:  # pragma: no cover - defensive logging
            _LOGGER.exception("[%s] Result callback raised", trace_id)

    async def async_trigger(self, reason: str) -> None:
        """Trigger a speedtest update."""
        if self._lock.locked():
            _LOGGER.debug("Speedtest already running, ignoring trigger: %s", reason)
            return

        async with self._lock:
            trace_id = str(uuid.uuid4())
            start = time.monotonic()
            _LOGGER.info("Starting speedtest (reason=%s, trace=%s)", reason, trace_id)

            try:
                previous_record = await self._async_get_last_speedtest(cache_sec=0)
                previous_marker = self._record_marker(previous_record)

                await self._async_start_speedtest(trace_id)
                result = await self._async_wait_for_result(
                    trace_id,
                    previous_marker,
                    max_wait_s=DEFAULT_MAX_WAIT_S,
                )

                if result:
                    _LOGGER.info(
                        "Speedtest completed successfully: %s/%s Mbps, %s ms",
                        result.get("download_mbps"),
                        result.get("upload_mbps"),
                        result.get("latency_ms"),
                    )
                    await self._async_refresh_entities(trace_id)

                duration_ms = int((time.monotonic() - start) * 1000)
                await self._dispatch_result(True, duration_ms, None, trace_id)

            except Exception as err:
                duration_ms = int((time.monotonic() - start) * 1000)
                error_msg = f"{type(err).__name__}: {str(err)}"
                _LOGGER.error(
                    "Speedtest failed after %dms: %s (trace=%s)",
                    duration_ms,
                    error_msg,
                    trace_id,
                    exc_info=True,
                )
                await self._dispatch_result(False, duration_ms, error_msg, trace_id)


__all__ = ["SpeedtestRunner", "ResultCallback", DATA_RUNNER"]
                    await self._async_refresh_entities(trace_id)
                    break
                except Exception as exc:
                    if attempt == 0:
                        _LOGGER.warning(
                            "[%s] First attempt failed: %s",
                            trace_id,
                            exc,
                            exc_info=True,
                        )
                        continue

                    if isinstance(exc, (asyncio.TimeoutError, TimeoutError)):
                        error = (
                            f"TimeoutError: Speedtest result not available within "
                            f"{DEFAULT_MAX_WAIT_S}s (trace={trace_id})"
                        )
                    else:
                        error = f"{type(exc).__name__}: {exc}"

                    _LOGGER.error(
                        "[%s] Speedtest failed: %s",
                        trace_id,
                        error,
                        exc_info=True,
                    )

            duration_ms = int((time.monotonic() - start) * 1000)

            if error:
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
                async_create_issue(
                    self.hass,
                    DOMAIN,
                    f"speedtest_run_failed_{trace_id}",
                    is_fixable=False,
                    severity=IssueSeverity.ERROR,
                    translation_key="speedtest_run_failed",
                    translation_placeholders={
                        "error": error,
                        "reason": reason,
                        "trace_id": trace_id,
                    },
                    data={
                        "error": error,
                        "entities": self.entity_ids,
                        "reason": reason,
                        "trace_id": trace_id,
                    },
                )
                maybe_coro = pn.async_create(
                    self.hass,
                    (
                        f"Speedtest failed ({reason}). Error: **{error}**\n"
                        f"Trace: `{trace_id}`"
                    ),
                    title="UniFi Gateway Refactored • Speedtest",
                    notification_id=f"{DOMAIN}_speedtest_error",
                )
                if isawaitable(maybe_coro):
                    await maybe_coro
                _LOGGER.error(
                    "[%s] Speedtest run ERROR after %sms -> %s",
                    trace_id,
                    duration_ms,
                    error,
                )
                await self._dispatch_result(False, duration_ms, error, trace_id)
                return

            self.hass.bus.async_fire(
                EVT_RUN_END,
                {
                    ATTR_TRACE_ID: trace_id,
                    ATTR_REASON: reason,
                    ATTR_ENTITY_IDS: self.entity_ids,
                    ATTR_DURATION_MS: duration_ms,
                },
            )
            maybe_coro = pn.async_dismiss(self.hass, f"{DOMAIN}_speedtest_error")
            if isawaitable(maybe_coro):
                await maybe_coro
            _LOGGER.info("[%s] Speedtest run END in %sms", trace_id, duration_ms)
            await self._dispatch_result(True, duration_ms, None, trace_id)


__all__ = ["SpeedtestRunner", "ResultCallback", DATA_RUNNER"]
