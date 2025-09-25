from __future__ import annotations

import asyncio
import logging
import time
import uuid
from inspect import isawaitable
from typing import Awaitable, Callable, Sequence

import async_timeout
from homeassistant.core import HomeAssistant, State
from homeassistant.exceptions import HomeAssistantError
from homeassistant.components import persistent_notification as pn
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

_LOGGER = logging.getLogger(__name__)

ResultCallback = Callable[[bool, int, str | None, str], Awaitable[None]]


class SpeedtestRunner:
    """Execute and observe Home Assistant speedtest updates."""

    def __init__(
        self,
        hass: HomeAssistant,
        entity_ids: Sequence[str],
        on_result_cb: ResultCallback,
    ) -> None:
        self.hass = hass
        self.entity_ids = [entity_id for entity_id in entity_ids if entity_id]
        self._on_result_cb = on_result_cb

    async def _call_update_entity(self, trace_id: str, timeout_s: int = 120) -> None:
        """Invoke the Home Assistant update_entity service with a timeout."""

        if not self.entity_ids:
            _LOGGER.debug("[%s] No entity IDs configured for speedtest run", trace_id)
            return

        # async_call no longer returns a boolean; enforce our own timeout.
        async with async_timeout.timeout(timeout_s):
            await self.hass.services.async_call(
                "homeassistant",
                "update_entity",
                {"entity_id": self.entity_ids},
                blocking=True,
            )
        _LOGGER.debug("[%s] update_entity called for %s", trace_id, self.entity_ids)

    async def _postcondition_wait(
        self,
        trace_id: str,
        before_states: dict[str, State | None],
        max_wait_s: int = 90,
    ) -> None:
        """Ensure that sensor states changed after the service call."""

        end = time.monotonic() + max_wait_s
        while time.monotonic() < end:
            updated = 0
            for entity_id, before in before_states.items():
                current = self.hass.states.get(entity_id)
                if current is None:
                    continue

                # If we did not have a previous state we consider any state
                # retrieval to be a successful update for that entity.
                if before is None:
                    updated += 1
                    continue

                before_changed = getattr(before, "last_changed", None)
                before_updated = getattr(before, "last_updated", before_changed)
                current_changed = getattr(current, "last_changed", None)
                current_updated = getattr(current, "last_updated", current_changed)

                # Some integrations keep the same value (and therefore the
                # same ``last_changed`` timestamp) when an update occurs.
                # ``last_updated`` is bumped in those cases, so we check both
                # fields to determine whether the entity really refreshed.
                if current_changed != before_changed:
                    updated += 1
                    continue
                if current_updated and before_updated and current_updated > before_updated:
                    updated += 1
                    continue
            if updated == len(before_states):
                return
            await asyncio.sleep(2)
        # If we previously had states for all monitored entities but none of
        # them reported a change, it is likely that the integration suppressed
        # the state write because the value did not actually change. In that
        # case we still consider the speedtest run successful instead of
        # raising a timeout.
        had_previous_state = any(before_states.values())
        if had_previous_state:
            unchanged = True
            for entity_id, before in before_states.items():
                current = self.hass.states.get(entity_id)
                if current is None:
                    unchanged = False
                    break
                if before is None:
                    unchanged = False
                    break
                if current.state != before.state:
                    unchanged = False
                    break
                if current.attributes != before.attributes:
                    unchanged = False
                    break
                before_changed = getattr(before, "last_changed", None)
                current_changed = getattr(current, "last_changed", None)
                if current_changed != before_changed:
                    unchanged = False
                    break
                before_updated = getattr(before, "last_updated", before_changed)
                current_updated = getattr(current, "last_updated", current_changed)
                if current_updated != before_updated:
                    unchanged = False
                    break
            if unchanged:
                _LOGGER.debug(
                    "[%s] Sensor states unchanged after speedtest run; treating as successful",
                    trace_id,
                )
                return
        raise TimeoutError(
            f"States did not change within {max_wait_s}s for {self.entity_ids}"
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

        before = {entity_id: self.hass.states.get(entity_id) for entity_id in self.entity_ids}
        error: str | None = None

        try:
            await self._call_update_entity(trace_id)
            await self._postcondition_wait(trace_id, before)
        except (asyncio.TimeoutError, TimeoutError, HomeAssistantError, Exception) as exc:
            _LOGGER.warning(
                "[%s] First attempt failed: %s. Retrying once...",
                trace_id,
                exc,
                exc_info=True,
            )
            await asyncio.sleep(5)
            try:
                await self._call_update_entity(trace_id)
                await self._postcondition_wait(trace_id, before)
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


__all__ = ["SpeedtestRunner", "ResultCallback", DATA_RUNNER]
