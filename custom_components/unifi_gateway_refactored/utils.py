"""Utility helpers for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations


def build_speedtest_button_unique_id(entry_id: str) -> str:
    """Return a stable unique ID for the Run Speedtest button entity."""

    return f"{entry_id}_run_speedtest"


__all__ = ["build_speedtest_button_unique_id"]
