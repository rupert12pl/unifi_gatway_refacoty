"""Diagnostics support for UniFi Gateway Refactory."""
from __future__ import annotations

import hashlib
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant

from .const import DOMAIN
from .coordinator import UniFiGatewayDataUpdateCoordinator, UniFiGatewayMetrics


def _anonymize(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:12]


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant, entry: ConfigEntry
) -> dict[str, Any]:
    """Return anonymized diagnostics for a config entry."""

    stored = hass.data.get(DOMAIN, {}).get(entry.entry_id)
    coordinator: UniFiGatewayDataUpdateCoordinator | None = None
    if stored:
        coordinator = stored.get("coordinator")

    diagnostics: dict[str, Any] = {
        "entry": {
            "title": entry.title,
            "site": entry.data.get("site"),
            "host_hash": _anonymize(entry.data.get("host", "")),
            "verify_ssl": entry.options.get("verify_ssl", entry.data.get("verify_ssl", True)),
        }
    }

    if coordinator and coordinator.data:
        metrics: UniFiGatewayMetrics = coordinator.data
        diagnostics["last_fetch"] = metrics.last_fetch.isoformat()
        ipv6_info = metrics.wan.get("ipv6", {}) if isinstance(metrics.wan, dict) else {}
        diagnostics["wan"] = {
            "status": metrics.wan.get("status"),
            "latency_ms": metrics.wan.get("latency_ms"),
            "packet_loss_pct": metrics.wan.get("packet_loss_pct"),
            "throughput_mbps": metrics.wan.get("throughput_mbps"),
            "ipv6": {
                "source": ipv6_info.get("ipv6_source"),
                "has_ipv6_connectivity": ipv6_info.get("has_ipv6_connectivity"),
                "wan_ipv6_global_hash": _maybe_anonymize(ipv6_info.get("wan_ipv6_global")),
                "wan_ipv6_link_local_hash": _maybe_anonymize(
                    ipv6_info.get("wan_ipv6_link_local")
                ),
                "delegated_prefix_hash": _maybe_anonymize(
                    ipv6_info.get("delegated_prefix")
                ),
            },
        }
        diagnostics["vpn"] = {
            "active_tunnels": metrics.vpn.get("active_tunnels"),
            "clients_sample": metrics.vpn.get("clients", [])[:5],
        }
        diagnostics["clients"] = metrics.clients
    else:
        diagnostics["last_fetch"] = None

    return diagnostics


def _maybe_anonymize(value: Any) -> str | None:
    if not value:
        return None
    if not isinstance(value, str):
        return None
    return _anonymize(value)
