
# UniFi Gateway Dashboard Analyzer

Custom integration for Home Assistant that exposes UniFi Gateway metrics with a
fully UI-driven configuration flow.

## Features

- **UI-based setup** (no YAML): Add Integration → UniFi Gateway Dashboard Analyzer.
- **Live validation on save**: during setup we log in and read `/stat/health` and `/self/sites`.
- **Options Flow**: you can change host/credentials/site/etc. later from the integration's Options.
- **Diagnostics**: menu "Download diagnostics" dumps controller URL, current site, health, sites.

Authentication uses a local **username/password** (the same approach as in
[`sirkirby/unifi-network-rules`](https://github.com/sirkirby/unifi-network-rules)).

## Repository layout required by HACS

HACS expects the following files in a custom integration repository:

- `hacs.json` in the repository root.
- `README.md` (or `info.md`) in the repository root for documentation rendering.
- `custom_components/<domain>/manifest.json` inside the integration directory.

This repository already follows that layout with the integration stored in
`custom_components/unifi_gateway_refactored/`.

## Publishing releases for HACS

HACS requires release tags that follow the `MAJOR.MINOR.PATCH` semantic version
pattern. The workflow is:

1. Update `custom_components/unifi_gateway_refactored/manifest.json` with the new
   version number and any code changes for the release.
2. Commit the change and push it to the `main` branch.
3. GitHub Actions (`.github/workflows/release.yml`) validates the semantic version
   and, if a tag with that name does not yet exist, automatically creates a tag
   and GitHub Release with the same version number.

The generated release contains the complete repository (including the
`custom_components` directory) as required by the
[HACS publishing guide](https://hacs.xyz/docs/publish/).

## Enable verbose logging

To collect detailed diagnostics, add the following snippet to your Home Assistant
`configuration.yaml` and reload the logger integration:

```yaml
logger:
  default: warning
  logs:
    custom_components.unifi_gateway_refactored: debug
    custom_components.unifi_gateway_refactored.unifi_client: debug
    custom_components.unifi_gateway_refactored.coordinator: debug
```

When debug logging is enabled the integration records each UniFi Network HTTP request
and, for non-2xx responses, includes a sanitized preview of the response body (first 1 kB)
to simplify troubleshooting endpoint discovery issues.

