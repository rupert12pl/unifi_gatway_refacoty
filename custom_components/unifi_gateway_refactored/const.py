from typing import Any

from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactored"
PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SITE_ID = "site_id"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_PROXY_PREFIX = "use_proxy_prefix"
CONF_TIMEOUT = "timeout"
CONF_SPEEDTEST_INTERVAL = "speedtest_interval"
CONF_SPEEDTEST_INTERVAL_MIN = "speedtest_interval_minutes"
CONF_SPEEDTEST_ENTITIES = "speedtest_entities"

DEFAULT_PORT = 443
DEFAULT_SITE = "default"
DEFAULT_VERIFY_SSL = False
DEFAULT_USE_PROXY_PREFIX = True
DEFAULT_TIMEOUT = 10
DEFAULT_SPEEDTEST_INTERVAL = 3600
DEFAULT_SPEEDTEST_INTERVAL_MIN = 60
DEFAULT_SPEEDTEST_ENTITIES = (
    "sensor.speedtest_download,sensor.speedtest_upload,sensor.speedtest_ping"
)

# Monitoring keys
DATA_RUNNER = "runner"
DATA_UNDO_TIMER = "undo_timer"

EVT_RUN_START = f"{DOMAIN}.speedtest.start"
EVT_RUN_END = f"{DOMAIN}.speedtest.end"
EVT_RUN_ERROR = f"{DOMAIN}.speedtest.error"

ATTR_TRACE_ID = "trace_id"
ATTR_REASON = "reason"
ATTR_ENTITY_IDS = "entity_ids"
ATTR_DURATION_MS = "duration_ms"
ATTR_ERROR = "error"

# Speedtest configuration
SPEEDTEST_DEFAULT_TIMEOUT = 600  # 10 minutes
SPEEDTEST_RETRY_DELAY = 5  # seconds
SPEEDTEST_POLL_INTERVAL = 5.0  # seconds

# Speedtest status
SPEEDTEST_STATUS_PENDING = "pending"
SPEEDTEST_STATUS_RUNNING = "running"
SPEEDTEST_STATUS_SUCCESS = "success"
SPEEDTEST_STATUS_ERROR = "error"
SPEEDTEST_STATUS_UNKNOWN = "unknown"

# VPN configuration
VPN_REFRESH_INTERVAL = 30  # seconds
VPN_CONNECTION_TIMEOUT = 60  # seconds

# VPN types (enhanced)
VPN_TYPES_MAP = {
    "client": {
        "name": "Client",
        "icon": "mdi:account-network",
        "aliases": ["client", "remote_user", "roadwarrior"],
    },
    "server": {
        "name": "Server",
        "icon": "mdi:server-network",
        "aliases": ["server"],
    },
    "s2s": {
        "name": "Site-to-Site",
        "icon": "mdi:wan",
        "aliases": ["s2s", "site-to-site", "ipsec"],
    },
    "teleport": {
        "name": "Teleport",
        "icon": "mdi:transit-connection-variant",
        "aliases": ["teleport"],
    },
}

# VPN status
VPN_STATUS_CONNECTED = "connected"
VPN_STATUS_DISCONNECTED = "disconnected"
VPN_STATUS_ERROR = "error"
VPN_STATUS_UNKNOWN = "unknown"

# VPN attributes
VPN_ATTR_TYPE = "type"
VPN_ATTR_NAME = "name"
VPN_ATTR_STATUS = "status"
VPN_ATTR_REMOTE = "remote"
VPN_ATTR_LOCAL = "local"
VPN_ATTR_INTERFACE = "interface"
VPN_ATTR_CLIENTS = "clients"
VPN_ATTR_PEERS = "peers"
VPN_ATTR_NETWORKS = "networks"
VPN_ATTR_ESTABLISHED = "established"
VPN_ATTR_LAST_SEEN = "last_seen"

# Existing code...


def normalize_vpn_type(value: Any) -> str:
    """Normalize various VPN type labels to canonical keys."""

    text = str(value or "").strip().lower()
    if not text:
        return "vpn"

    normalized = text.replace("-", "_")

    for canonical, meta in VPN_TYPES_MAP.items():
        if normalized == canonical:
            return canonical

        for alias in meta.get("aliases", []):
            alias_normalized = str(alias).strip().lower().replace("-", "_")
            if not alias_normalized:
                continue
            if normalized == alias_normalized or alias_normalized in normalized:
                return canonical

    if "site" in normalized and "teleport" not in normalized:
        return "s2s"
    if "client" in normalized:
        return "client"
    if "server" in normalized:
        return "server"
    if "teleport" in normalized:
        return "teleport"

    return "vpn"
