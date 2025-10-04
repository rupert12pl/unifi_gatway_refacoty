from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactored"
PLATFORMS = [Platform.SENSOR, Platform.BUTTON]

CONF_USERNAME = "username"
# Placeholder configuration keys for UI forms.
CONF_PASSWORD = "password"  # nosec B105
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SITE_ID = "site_id"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_PROXY_PREFIX = "use_proxy_prefix"
CONF_TIMEOUT = "timeout"
CONF_SPEEDTEST_INTERVAL = "speedtest_interval"
# Legacy option key kept for backwards compatibility with pre-0.6.1 releases
LEGACY_CONF_SPEEDTEST_INTERVAL_MIN = "speedtest_interval_minutes"
CONF_SPEEDTEST_ENTITIES = "speedtest_entities"
CONF_WIFI_GUEST = "wifi_guest"
CONF_WIFI_IOT = "wifi_iot"
CONF_API_KEY = "api_key"
# Backwards compatibility alias for legacy option name
CONF_UI_API_KEY = CONF_API_KEY
CONF_GW_MAC = "gw_mac"

DEFAULT_PORT = 443
DEFAULT_SITE = "default"
DEFAULT_VERIFY_SSL = True
DEFAULT_USE_PROXY_PREFIX = True
DEFAULT_TIMEOUT = 10
DEFAULT_SPEEDTEST_INTERVAL = 3600  # seconds
DEFAULT_SPEEDTEST_INTERVAL_MINUTES = 60
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
ATTR_GW_MAC = "gw_mac"
ATTR_REASON = "reason"
ATTR_ENTITY_IDS = "entity_ids"
ATTR_DURATION_MS = "duration_ms"
ATTR_ERROR = "error"

API_CLOUD_HOSTS_URL = "https://api.ui.com/v1/hosts"
