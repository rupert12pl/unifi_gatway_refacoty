
# UniFi Gateway (Refactored) — UI Config Flow + Options + Diagnostics

- **UI-based setup** (no YAML): Add Integration → UniFi Gateway (Refactored).
- **Live validation on save**: during setup we log in and read `/stat/health` and `/self/sites`.
- **Options Flow**: you can change host/credentials/site/etc. later from the integration's Options.
- **Diagnostics**: menu "Download diagnostics" dumps controller URL, current site, health, sites.

Uwierzytelnianie: lokalny **username/password** (jak w sirkirby/unifi-network-rules).

