from __future__ import annotations

import asyncio
import logging
import time
import uuid
from inspect import isawaitable
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
        self.entity_ids = [entity_id for entity_id in entity_ids if entity_id]
        self._on_result_cb = on_result_cb
        self._client = client
        self._coordinator = coordinator
        self._lock = asyncio.Lock()

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
        max_wait_s: int = 240,
        poll_interval: float = 5.0,
    ) -> dict[str, Any]:
        end = time.monotonic() + max_wait_s
        last_status: str | None = None
        while time.monotonic() < end:
            record = await self._async_get_last_speedtest(cache_sec=0)
            marker = self._record_marker(record)
            if record and (previous_marker is None or marker != previous_marker):
                status = record.get("status") if isinstance(record, dict) else None
                status_text = status if isinstance(status, str) else self._status_text(status)
                if self._status_indicates_failure(status_text):
                    raise RuntimeError(f"Speedtest completed with failure status: {status_text}")
                return record

            status_payload = await self._async_get_speedtest_status()
            status_text = self._status_text(status_payload)
            if status_text and status_text != last_status:
                _LOGGER.debug("[%s] Speedtest status -> %s", trace_id, status_text)
                last_status = status_text
            if self._status_indicates_failure(status_text):
                raise RuntimeError(f"Speedtest reported failure status: {status_text}")
            await asyncio.sleep(poll_interval)
        raise TimeoutError(
            f"Speedtest result not available within {max_wait_s}s (trace={trace_id})"
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
        """Trigger a speedtest update with full observability."""
        # Prevent overlapping runs that can confuse the controller and timeout
        if self._lock.locked():
            _LOGGER.debug("Speedtest trigger ignored because a run is already in progress (%s)", reason)
            return
        async with self._lock:
        trace_id = str(uuid.uuid4())
        start = time.monotonic()

        self.hass.bus.async_fire(
            EVT_RUN_START,
            {
                ATTR_TRACE_ID: trace_id,
                ATTR_REASON: reason,
                ATTR_ENTITY_IDS: self.entity_ids,
            },
        )
        _LOGGER.info(
            "[%s] Speedtest run START (reason=%s, entities=%s)",
            trace_id,
            reason,
            self.entity_ids,
        )

        previous_record = await self._async_get_last_speedtest(cache_sec=0)
        previous_marker = self._record_marker(previous_record)
        error: str | None = None

        try:
            await self._async_start_speedtest(trace_id)
            await self._async_wait_for_result(trace_id, previous_marker)
            await self._async_refresh_entities(trace_id)
        except (asyncio.TimeoutError, TimeoutError, HomeAssistantError, Exception) as exc:
            _LOGGER.warning(
                "[%s] First attempt failed: %s. Retrying once...",
                trace_id,
                exc,
                exc_info=True,
            )
            await asyncio.sleep(5)
            try:
                await self._async_start_speedtest(trace_id)
                await self._async_wait_for_result(trace_id, previous_marker)
                await self._async_refresh_entities(trace_id)
            except Exception as retry_exc:  # pragma: no cover - error path
                error = f"{type(retry_exc).__name__}: {retry_exc}"

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
                translation_key=None,
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

    async def _async_run_speed_test_and_get_results(self) -> dict:
        """Run speed test and get results."""
        trace = uuid.uuid4()
        _LOGGER.debug(
            "[%s] Speedtest run START",
            trace,
        )
        start_time = time.monotonic()
        await self._gateway.run_speed_test()
        try:
            await asyncio.wait_for(
                self._gateway.wait_for_speed_test_result(), timeout=600
            )
        except TimeoutError as err:
            end_time = time.monotonic()
            _LOGGER.error(
                "[%s] Speedtest run ERROR after %sms -> TimeoutError: Speedtest result not available within 240s (trace=%s)",
                trace,
                (end_time - start_time) * 1000,
                trace,
            )
            raise TimeoutError(
                "Speedtest result not available within 240s"
            ) from err

        end_time = time.monotonic()
        _LOGGER.debug(
            "[%s] Speedtest run END in %sms",
            trace,
            (end_time - start_time) * 1000,
        )
        return await self._gateway.get_speed_test_results()


__all__ = ["SpeedtestRunner", "ResultCallback", DATA_RUNNER]
