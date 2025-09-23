# Changelog

## Unreleased

- Removed the broken VPN endpoint probing logic in favour of gateway overview stats.
- Added the aggregate VPN diagnostics entity sourced from LAN/WAN-style gateway stats.
- Deduplicated LAN/WAN/WLAN sensors by stabilising unique IDs and refreshing on setup.
- Hardened the HTTP client with consistent timeouts, SSL handling, retries, and debug logs.
