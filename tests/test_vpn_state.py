from custom_components.unifi_gateway_refactored.coordinator import UniFiGatewayData
from custom_components.unifi_gateway_refactored.unifi_client import (
    VpnAttempt,
    VpnState,
    _redact_text,
)


def test_vpn_state_mapping_preserves_payload() -> None:
    state = VpnState(
        remote_users=[{"id": "ru1", "name": "Alice"}],
        site_to_site_peers=[{"id": "peer1", "name": "HQ"}],
        teleport_servers=[{"id": "srv1", "name": "TeleportServer"}],
        teleport_clients=[{"id": "cl1", "name": "TeleportClient"}],
        attempts=[
            VpnAttempt(
                path="gateway/health/overview", status=200, ok=True, snippet="{}"
            )
        ],
        errors={"remote_users": "not available"},
    )

    data = UniFiGatewayData(controller={}, vpn_state=state)

    assert data.vpn_state is state
    assert data.vpn_state.remote_users[0]["name"] == "Alice"
    assert data.vpn_state.attempts[0].path == "gateway/health/overview"
    assert data.vpn_state.errors["remote_users"] == "not available"


def test_redact_text_masks_sensitive_tokens() -> None:
    sample = '{"token": "abc123", "password": "secret", "cookie": "crumb"}'
    redacted = _redact_text(sample)

    assert "abc123" not in redacted
    assert "secret" not in redacted
    assert "crumb" not in redacted
    assert redacted.count("***") >= 3
