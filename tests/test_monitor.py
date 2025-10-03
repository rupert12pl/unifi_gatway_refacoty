"""Tests for UniFi Gateway monitor module."""
from __future__ import annotations

import asyncio
import threading
from datetime import datetime
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


async def run_test(coro) -> None:
    """Execute coroutine with patched asyncio.sleep for fast tests.

    Args:
        coro: The coroutine to execute.

    Returns:
        None

    """
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_MAX_WAIT_S", 1
    ), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_POLL_INTERVAL",
        0.01,
    ):
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

    await runner.async_trigger("test")

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

    await runner.async_trigger("test")

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

    # Simulate a long-running test
    def slow_status():
        # Simulate a blocking controller poll without using time.sleep
        threading.Event().wait(0.1)
        return {"status": "running"}

    mock_client.get_speedtest_status.side_effect = slow_status

    # Try to run two tests simultaneously
    async def _run_concurrent() -> None:
        task1 = asyncio.create_task(runner.async_trigger("test1"))
        task2 = asyncio.create_task(runner.async_trigger("test2"))
        await asyncio.gather(task1, task2)

    await run_test(_run_concurrent())

    # Check that only one test was executed
    assert mock_callback.call_count == 1

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
