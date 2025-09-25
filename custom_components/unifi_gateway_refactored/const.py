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

# VPN types
VPN_TYPE_CLIENT = "client"
VPN_TYPE_SERVER = "server"
VPN_TYPE_S2S = "s2s"
VPN_TYPE_TELEPORT = "teleport"

VPN_TYPES = [VPN_TYPE_CLIENT, VPN_TYPE_SERVER, VPN_TYPE_S2S, VPN_TYPE_TELEPORT]
