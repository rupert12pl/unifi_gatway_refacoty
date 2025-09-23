
from homeassistant.const import Platform

DOMAIN = "unifi_gateway_refactored"
PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR]

CONF_USERNAME = "username"
CONF_PASSWORD = "password"
CONF_HOST = "host"
CONF_PORT = "port"
CONF_SITE_ID = "site_id"
CONF_VERIFY_SSL = "verify_ssl"
CONF_USE_PROXY_PREFIX = "use_proxy_prefix"
CONF_TIMEOUT = "timeout"

DEFAULT_PORT = 443
DEFAULT_SITE = "default"
DEFAULT_VERIFY_SSL = False
DEFAULT_USE_PROXY_PREFIX = True
DEFAULT_TIMEOUT = 10
