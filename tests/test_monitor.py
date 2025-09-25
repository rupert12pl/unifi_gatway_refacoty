"""Tests for UniFi Gateway monitor module."""
from __future__ import annotations

import asyncio
from datetime import datetime
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from custom_components.unifi_gateway_refactored.monitor import (
    SpeedtestRunner,
    DEFAULT_MAX_WAIT_S,
    DEFAULT_POLL_INTERVAL,
)

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

async def test_speedtest_success(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
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

    await runner.async_trigger("test")

    # Sprawdź czy callback został wywołany z sukcesem
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

    # Symuluj timeout - zawsze zwracaj brak wyników
    mock_client.get_last_speedtest.return_value = None
    mock_client.get_speedtest_status.return_value = {"status": "running"}

    await runner.async_trigger("test")

    # Sprawdź czy callback został wywołany z błędem
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is False
    assert "TimeoutError" in args["error"]

async def test_speedtest_failure_status(hass: HomeAssistant, mock_client, mock_coordinator, mock_callback):
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

    await runner.async_trigger("test")

    # Sprawdź czy callback został wywołany z błędem
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

    # Symuluj długo trwający test
    async def slow_status():
        await asyncio.sleep(0.1)
        return {"status": "running"}
    
    mock_client.get_speedtest_status.side_effect = slow_status

    # Spróbuj uruchomić dwa testy jednocześnie
    task1 = asyncio.create_task(runner.async_trigger("test1"))
    task2 = asyncio.create_task(runner.async_trigger("test2"))
    
    await asyncio.gather(task1, task2)

    # Sprawdź czy tylko jeden test został wykonany
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

    await runner.async_trigger("test")

    # Sprawdź czy test zakończył się sukcesem po ponownej próbie
    assert mock_callback.call_count == 1
    args = mock_callback.call_args[1]
    assert args["success"] is True
    assert args["error"] is None
