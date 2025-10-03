"""Tests for UniFi Gateway monitor module."""
from __future__ import annotations

import asyncio
from datetime import datetime
import threading
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


def run(coro) -> None:
    """Execute coroutine with patched asyncio.sleep for fast tests."""
    with patch("asyncio.sleep", new=AsyncMock(return_value=None)), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_MAX_WAIT_S", 1
    ), patch(
        "custom_components.unifi_gateway_refactored.monitor.DEFAULT_POLL_INTERVAL",
        0.01,
    ):
        asyncio.run(coro)

def test_speedtest_success(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test successful speedtest run."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Symuluj udany test prędkości
    mock_client.get_last_speedtest.side_effect = [
        None,  # Pierwsze wywołanie - brak wyników
        {  # Drugie wywołanie - nowe wyniki
            "rundate": datetime.now().timestamp(),
            "download_mbps": 100,
            "upload_mbps": 50,
            "latency_ms": 10,
        },
    ]
    mock_client.get_speedtest_status.return_value = {"status": "completed"}

    run(runner.async_trigger("test"))

    # Sprawdź czy callback został wywołany z sukcesem
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is True
    assert args["error"] is None

def test_speedtest_timeout(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test speedtest timeout scenario."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Symuluj timeout - zawsze zwracaj brak wyników
    mock_client.get_last_speedtest.return_value = None
    mock_client.get_speedtest_status.return_value = {"status": "running"}

    run(runner.async_trigger("test"))

    # Sprawdź czy callback został wywołany z błędem
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is False
    assert "TimeoutError" in args["error"]

def test_speedtest_failure_status(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test speedtest failure status handling."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Symuluj błąd w teście prędkości
    mock_client.get_last_speedtest.return_value = {
        "status": "error",
        "error": "Test failed"
    }

    run(runner.async_trigger("test"))

    # Sprawdź czy callback został wywołany z błędem
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is False
    assert "failure status" in args["error"]

def test_concurrent_runs(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test prevention of concurrent speedtest runs."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Symuluj długo trwający test
    def slow_status():
        # Simulate a blocking controller poll without using time.sleep.
        threading.Event().wait(0.1)
        return {"status": "running"}

    mock_client.get_speedtest_status.side_effect = slow_status

    # Spróbuj uruchomić dwa testy jednocześnie
    async def _run_concurrent() -> None:
        task1 = asyncio.create_task(runner.async_trigger("test1"))
        task2 = asyncio.create_task(runner.async_trigger("test2"))
        await asyncio.gather(task1, task2)

    run(_run_concurrent())

    # Sprawdź czy tylko jeden test został wykonany
    assert mock_callback.call_count == 1

def test_retry_mechanism(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
    """Test speedtest retry mechanism."""
    runner = SpeedtestRunner(
        hass,
        ["sensor.speedtest"],
        mock_callback,
        mock_client,
        mock_coordinator,
    )

    # Symuluj błąd w pierwszej próbie i sukces w drugiej
    mock_client.get_last_speedtest.side_effect = [
        Exception("First attempt failed"),  # Pierwsza próba
        None,  # Druga próba - start
        {  # Druga próba - sukces
            "rundate": datetime.now().timestamp(),
            "download_mbps": 100,
            "upload_mbps": 50,
            "latency_ms": 10,
        },
    ]

    run(runner.async_trigger("test"))

    # Sprawdź czy test zakończył się sukcesem po ponownej próbie
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is True
    assert args["error"] is None
