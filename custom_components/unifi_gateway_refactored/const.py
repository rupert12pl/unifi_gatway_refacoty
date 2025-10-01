"""Constants for the UniFi Gateway Dashboard Analyzer integration."""

from __future__ import annotations

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactored"
PLATFORMS: list[Platform] = [Platform.SENSOR]

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SITE_ID = "site_id"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_PROXY_PREFIX = "use_proxy_prefix"
CONF_TIMEOUT = "timeout"
CONF_SPEEDTEST_INTERVAL = "speedtest_interval"
LEGACY_CONF_SPEEDTEST_INTERVAL_MIN = "speedtest_interval_minutes"
CONF_SPEEDTEST_ENTITIES = "speedtest_entities"
CONF_WIFI_GUEST = "wifi_guest"
CONF_WIFI_IOT = "wifi_iot"

DEFAULT_PORT = 443
DEFAULT_SITE = "default"
DEFAULT_VERIFY_SSL = False
DEFAULT_USE_PROXY_PREFIX = True
DEFAULT_TIMEOUT = 10
DEFAULT_SPEEDTEST_INTERVAL = 3600  # seconds
DEFAULT_SPEEDTEST_INTERVAL_MINUTES = 60
DEFAULT_SPEEDTEST_ENTITIES = (
    "sensor.speedtest_download,sensor.speedtest_upload,sensor.speedtest_ping",
)

DATA_CLIENT = "client"
DATA_COORDINATOR = "coordinator"
DATA_SESSION = "session"
DATA_ERRORS = "errors"

UPDATE_INTERVAL_OK = timedelta(seconds=30)
UPDATE_INTERVAL_BACKOFF = timedelta(seconds=90)
CIRCUIT_TIMEOUT_THRESHOLD = 3

CLIENT_TOTAL_TIMEOUT = 12
CLIENT_CONNECT_TIMEOUT = 4
CLIENT_SOCK_READ_TIMEOUT = 8
CLIENT_MAX_ATTEMPTS = 3
LOG_ERROR_RATE_LIMIT = 30.0

ERROR_CODE_TIMEOUT = "UGDA_TIMEOUT"
ERROR_CODE_5XX = "UGDA_5XX"
ERROR_CODE_CLIENT = "UGDA_CLIENT"
ERROR_CODE_AUTH = "UGDA_AUTH"

DIAGNOSTICS_MAX_PAYLOAD_BYTES = 1024
SENSITIVE_DIAGNOSTIC_KEYS = {"password", "token", "cookie", "authorization", "secret"}

TRACE_ID_BYTES = 4
