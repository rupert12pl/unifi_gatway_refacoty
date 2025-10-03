"""Tests for UniFi Gateway monitor module."""
from __future__ import annotations

import asyncio
from contextlib import ExitStack
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from homeassistant.core import HomeAssistant

from custom_components.unifi_gateway_refactored.monitor import SpeedtestRunner


@pytest.fixture
def mock_client():
    """Create mock UniFi client."""
    client = MagicMock()
    client.get_last_speedtest.return_value = None
    client.get_speedtest_status.return_value = None
    return client

@pytest.fixture
def mock_coordinator():
    """Create mock coordinator."""
    coordinator = MagicMock()
    coordinator.async_request_refresh = AsyncMock()
    return coordinator

@pytest.fixture
def mock_callback():
    """Create mock callback."""
    return AsyncMock()


async def run_test(
    coro,
    *,
    patch_sleep: bool = True,
    max_wait: float = 0.05,
    poll_interval: float = 0.01,
) -> None:
    """Execute coroutine with patched monitor timing constants."""

    with ExitStack() as stack:
        stack.enter_context(
            patch(
                "custom_components.unifi_gateway_refactored.monitor.DEFAULT_MAX_WAIT_S",
                max_wait,
            )
        )
        stack.enter_context(
            patch(
                "custom_components.unifi_gateway_refactored.monitor.DEFAULT_POLL_INTERVAL",
                poll_interval,
            )
        )
        if patch_sleep:
            stack.enter_context(
                patch("asyncio.sleep", new=AsyncMock(return_value=None))
            )
        await coro

async def test_speedtest_success(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test successful speedtest run."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Simulate a successful speed test
    mock_client.get_last_speedtest.side_effect = [
        None,  # First call - no results
        {  # Second call - new results
            "rundate": datetime.now().timestamp(),
            "download_mbps": 100,
            "upload_mbps": 50,
            "latency_ms": 10,
        },
    ]
    mock_client.get_speedtest_status.return_value = {"status": "completed"}

    await run_test(runner.async_trigger("test"))

    # Check that callback was called with success
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is True
    assert args["error"] is None

async def test_speedtest_timeout(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test speedtest timeout scenario."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Simulate timeout - always return no results
    mock_client.get_last_speedtest.return_value = None
    mock_client.get_speedtest_status.return_value = {"status": "running"}

    with patch.object(
        SpeedtestRunner,
        "_async_wait_for_result",
        new_callable=AsyncMock,
        side_effect=TimeoutError("Speedtest timed out"),
    ):
        await run_test(runner.async_trigger("test"))

    # Check that callback was called with error
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is False
    assert "TimeoutError" in args["error"]

async def test_speedtest_failure_status(
    hass: HomeAssistant, mock_client, mock_coordinator, mock_callback
):
    """Test speedtest failure status handling."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Simulate speed test error
    mock_client.get_last_speedtest.return_value = {
        "status": "error",
        "error": "Test failed"
    }

    await run_test(runner.async_trigger("test"))

    # Check that callback was called with error
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is False
    assert "failure status" in args["error"]

async def test_concurrent_runs(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test prevention of concurrent speedtest runs."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    async def fake_wait(*args: Any, **kwargs: Any) -> dict[str, Any]:
        await asyncio.sleep(0.05)
        return {
            "rundate": datetime.now().timestamp(),
            "download_mbps": 0,
            "upload_mbps": 0,
            "latency_ms": 0,
        }

    wait_mock = AsyncMock(side_effect=fake_wait)
    entered_wait = asyncio.Event()
    release_wait = asyncio.Event()

    async def _fake_wait(*args: Any, **kwargs: Any) -> dict[str, Any]:
        entered_wait.set()
        await release_wait.wait()
        return await wait_mock(*args, **kwargs)

    async def _run_concurrent() -> None:
        with patch.object(SpeedtestRunner, "_async_wait_for_result", _fake_wait):
            first = asyncio.create_task(runner.async_trigger("test1"))
            await entered_wait.wait()
            second = asyncio.create_task(runner.async_trigger("test2"))
            await asyncio.sleep(0)
            release_wait.set()
            await asyncio.gather(first, second)

    await run_test(_run_concurrent(), patch_sleep=False, max_wait=1)

    # Check that only one test was executed
    assert mock_callback.call_count == 1
    wait_mock.assert_awaited_once()

async def test_retry_mechanism(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test speedtest retry mechanism."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Simulate failure in first attempt and success in second
    mock_client.get_last_speedtest.side_effect = [
        Exception("First attempt failed"),  # First attempt
        None,  # Second attempt - start
        {  # Second attempt - success
            "rundate": datetime.now().timestamp(),
            "download_mbps": 100,
            "upload_mbps": 50,
            "latency_ms": 10,
        },
    ]

    await run_test(runner.async_trigger("test"))

    # Check that test succeeded after retry
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is True
    assert args["error"] is None
