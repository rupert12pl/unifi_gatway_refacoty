"""UniFi Gateway Speedtest handling utilities."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any, Dict, Optional

from homeassistant.util import dt as dt_util
from .unifi_client import APIError, UniFiOSClient

_LOGGER = logging.getLogger(__name__)

class SpeedtestHandler:
    """Handle UniFi Gateway speedtest operations."""

    def __init__(self, client: UniFiOSClient, interval: int | None = None) -> None:
        """Initialize the speedtest handler."""
        self._client = client
        self._interval = self._sanitize_interval(interval)

    @staticmethod
    def _sanitize_interval(value: int | None) -> int:
        """Sanitize the speedtest interval value."""
        try:
            interval = int(value) if value is not None else 0
        except (TypeError, ValueError):
            return 0
        return max(0, interval)

    @staticmethod
    def _get_last_timestamp(record: Optional[Dict[str, Any]]) -> Optional[float]:
        """Extract the timestamp from a speedtest record."""
        if not isinstance(record, dict):
            return None
        
        for key in ("rundate", "timestamp", "time", "date", "start_time"):
            if key not in record:
                continue
                
            value = record.get(key)
            if value in (None, ""):
                continue
                
            if isinstance(value, (int, float)):
                number = float(value)
                if number > 1e11:
                    number /= 1000.0
                if number > 0:
                    return number
                continue
                
            dt_value: Optional[datetime] = None
            if isinstance(value, str):
                text = value.strip()
                if not text:
                    continue
                try:
                    number = float(text)
                except (TypeError, ValueError):
                    dt_value = dt_util.parse_datetime(text)
                else:
                    if number > 1e11:
                        number /= 1000.0
                    if number > 0:
                        return number
                    continue
            elif isinstance(value, datetime):
                dt_value = value
                
            if dt_value is None:
                continue
                
            dt_utc = dt_util.as_utc(dt_value)
            return dt_utc.timestamp()
        return None

    def get_speedtest(self) -> Optional[Dict[str, Any]]:
        """Get the latest speedtest result."""
        try:
            speedtest = self._client.get_last_speedtest(cache_sec=5)
            if speedtest:
                has_values = any(
                    isinstance(speedtest.get(key), (int, float)) and speedtest[key] > 0
                    for key in ("download_mbps", "upload_mbps", "latency_ms")
                )
                if not has_values:
                    _LOGGER.debug("Cached speedtest result has no valid measurements")
                    return None
                
                _LOGGER.debug(
                    "Valid speedtest result: %0.1f/%0.1f Mbps, %0.1f ms",
                    speedtest.get("download_mbps", 0),
                    speedtest.get("upload_mbps", 0),
                    speedtest.get("latency_ms", 0)
                )
                return speedtest
        except APIError as err:
            _LOGGER.warning("Failed to fetch speedtest results: %s", err)
        return None

    def check_and_trigger(self, now_ts: float) -> None:
        """Check if speedtest should be triggered and do so if needed."""
        if self._interval <= 0:
            return

        speedtest = self.get_speedtest()
        last_ts = self._get_last_timestamp(speedtest)
        
        should_trigger = False
        reason = None
        
        if not speedtest:
            should_trigger = True
            reason = "missing"
        elif last_ts and (now_ts - last_ts) >= self._interval:
            should_trigger = True
            reason = f"stale ({int(now_ts - last_ts)}s old)"
            
        if should_trigger:
            cooldown = max(self._interval, 60)
            try:
                self._client.maybe_start_speedtest(cooldown_sec=cooldown)
                _LOGGER.info(
                    "Triggered speedtest (reason=%s, interval=%ss, cooldown=%ss)",
                    reason,
                    self._interval,
                    cooldown
                )
            except APIError as err:
                _LOGGER.warning("Failed to trigger speedtest: %s", err)