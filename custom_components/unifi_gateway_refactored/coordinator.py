"""Data coordinator for the UniFi Gateway Dashboard Analyzer."""

from __future__ import annotations

import asyncio
import logging
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator
from homeassistant.util import dt as dt_util

from .const import (
    CIRCUIT_TIMEOUT_THRESHOLD,
    DOMAIN,
    ERROR_CODE_5XX,
    ERROR_CODE_CLIENT,
    ERROR_CODE_TIMEOUT,
    TRACE_ID_BYTES,
    UPDATE_INTERVAL_BACKOFF,
    UPDATE_INTERVAL_OK,
)
from .unifi_client import UniFiApiClient, UniFiAuthError, UniFiClientError

LOGGER = logging.getLogger(__name__)


@dataclass
class UniFiGatewayData:
    """Structured data returned by the coordinator."""

    trace_id: str
    status: str
    controller: dict[str, Any]
    health: list[dict[str, Any]]
    alerts: list[dict[str, Any]]
    devices: list[dict[str, Any]]
    errors: list[dict[str, Any]]
    last_updated: datetime
    available: bool


def _derive_status(records: Iterable[dict[str, Any]]) -> str:
    state = "unknown"
    for record in records:
        value = str(record.get("status") or record.get("state") or "").lower()
        if not value:
            continue
        if value in {"down", "disconnected", "critical"}:
            return "critical"
        if value in {"warn", "warning", "degraded"}:
            state = "degraded"
        elif state == "unknown" and value in {"ok", "healthy", "up"}:
            state = "ok"
    return state


class UniFiGatewayDataUpdateCoordinator(DataUpdateCoordinator[UniFiGatewayData]):
    """Coordinate UniFi Gateway data retrieval."""

    def __init__(
        self,
        hass: HomeAssistant,
        *,
        client: UniFiApiClient,
        error_buffer: list[dict[str, Any]] | None = None,
    ) -> None:
        super().__init__(
            hass,
            LOGGER,
            name=f"{DOMAIN} coordinator",
            update_interval=UPDATE_INTERVAL_OK,
        )
        self._client = client
        self._timeout_streak = 0
        self._available = True
        self._error_buffer = error_buffer if error_buffer is not None else []

    @property
    def available(self) -> bool:  # type: ignore[override]
        return self._available

    async def _async_update_data(self) -> UniFiGatewayData:
        trace_id = secrets.token_hex(TRACE_ID_BYTES)
        tasks = {
            "health": self._client.async_request_health(trace_id=trace_id),
            "alerts": self._client.async_request_alerts(trace_id=trace_id),
            "devices": self._client.async_request_devices(trace_id=trace_id),
        }

        results = await asyncio.gather(*tasks.values(), return_exceptions=True)
        errors: list[dict[str, Any]] = []
        data: dict[str, Any] = {}

        for key, result in zip(tasks.keys(), results):
            if isinstance(result, UniFiAuthError):
                raise result
            if isinstance(result, UniFiClientError):
                error_entry = {
                    "endpoint": key,
                    "code": result.code or ERROR_CODE_CLIENT,
                    "message": str(result),
                    "trace_id": trace_id,
                    "timestamp": dt_util.utcnow().isoformat(),
                }
                errors.append(error_entry)
                self._error_buffer.append(error_entry)
                del self._error_buffer[:-20]
                level = logging.WARNING
                if result.code == ERROR_CODE_TIMEOUT:
                    self._timeout_streak += 1
                else:
                    self._timeout_streak = 0
                if result.code in {ERROR_CODE_5XX, ERROR_CODE_TIMEOUT}:
                    level = logging.WARNING
                elif result.code == ERROR_CODE_CLIENT:
                    level = logging.ERROR
                LOGGER.log(
                    level,
                    "Coordinator request failed",
                    extra={
                        "event": "coordinator",
                        "status": result.code,
                        "endpoint": key,
                        "trace_id": trace_id,
                    },
                )
                continue
            if isinstance(result, Exception):
                errors.append(
                    {
                        "endpoint": key,
                        "code": ERROR_CODE_CLIENT,
                        "message": str(result),
                        "trace_id": trace_id,
                        "timestamp": dt_util.utcnow().isoformat(),
                    }
                )
                self._error_buffer.append(errors[-1])
                del self._error_buffer[:-20]
                LOGGER.error(
                    "Coordinator unexpected error",
                    extra={
                        "event": "coordinator",
                        "status": ERROR_CODE_CLIENT,
                        "endpoint": key,
                        "trace_id": trace_id,
                    },
                )
                continue
            data[key] = result

        if not errors:
            self._timeout_streak = 0

        if self._timeout_streak >= CIRCUIT_TIMEOUT_THRESHOLD:
            self._available = False
            self.update_interval = UPDATE_INTERVAL_BACKOFF
        else:
            self._available = True
            self.update_interval = UPDATE_INTERVAL_OK

        controller_info = {
            "url": self._client.get_controller_url(),
            "api": self._client.get_controller_api_url(),
            "site": self._client.get_site(),
        }
        health = data.get("health", []) or []
        alerts = data.get("alerts", []) or []
        devices = data.get("devices", []) or []
        status = _derive_status(health)
        LOGGER.info(
            "Coordinator cycle completed",
            extra={
                "event": "coordinator",
                "status": "ok" if not errors else "partial",
                "endpoint": "cycle",
                "trace_id": trace_id,
            },
        )
        return UniFiGatewayData(
            trace_id=trace_id,
            status=status,
            controller=controller_info,
            health=health,
            alerts=alerts,
            devices=devices,
            errors=errors,
            last_updated=dt_util.utcnow(),
            available=self._available,
        )
