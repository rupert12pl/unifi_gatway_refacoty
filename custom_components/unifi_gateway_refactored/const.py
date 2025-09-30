"""Constants for the UniFi Gateway Refactored integration."""
from __future__ import annotations

from datetime import timedelta

from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactored"

CONF_SITE = "site"
CONF_VERIFY_SSL = "verify_ssl"
CONF_SCAN_INTERVAL = "scan_interval"

DEFAULT_SITE = "default"
DEFAULT_VERIFY_SSL = True
DEFAULT_SCAN_INTERVAL = 30
MIN_SCAN_INTERVAL = 30
MAX_SCAN_INTERVAL = 300

PLATFORMS: list[Platform] = [Platform.SENSOR, Platform.BINARY_SENSOR]

LEGACY_DOMAIN = "unifigateway"

REQUEST_TIMEOUT = 30
MAX_RETRIES = 4
BACKOFF_BASE = 2
INITIAL_BACKOFF = 1.0
MAX_BACKOFF = 30.0
RATE_LIMIT = 3

DATA_COORDINATOR = "coordinator"
DATA_API = "api"
DATA_OPTIONS = "options"
DATA_SSL_WARNING_EMITTED = "ssl_warning_emitted"

UPDATE_INTERVAL = timedelta(seconds=DEFAULT_SCAN_INTERVAL)
