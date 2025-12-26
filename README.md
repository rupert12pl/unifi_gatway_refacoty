
# UniFi Gateway Dashboard Analyzer

This Home Assistant custom integration surfaces key metrics from your UniFi
gateway in a simple, aggregated fashion. It exposes high‑level health
indicators for your WAN, LAN, WLAN and internet connectivity as well as
firmware status, outstanding alerts and the results of built‑in speed tests.

Unlike some UniFi integrations that enumerate every network, SSID or VPN
tunnel as a separate entity, **UniFi Gateway Dashboard Analyzer deliberately
avoids creating per‑network or per‑client entities**. In UniFi OS 10.0.162 the
controller API can report thousands of pseudo‑networks, which previously led
to Home Assistant flooding your entity registry with entries like
`sensor.lan_vlan_none_182`, `sensor.lan_default_3` and similar. In this
refactored version dynamic discovery has been disabled so that only the
meaningful, high‑level entities described below are created.

## Available entities

After you set up the integration you will find the following entities in
Home Assistant.  The entity IDs will be prefixed with the name of your UniFi
gateway or site.

| Domain  | Entity ID suffix            | Description                                         |
|--------|-----------------------------|-----------------------------------------------------|
| sensor | `alerts`                    | Number of active alerts reported by the controller. |
| sensor | `firmware_upgradable`       | Number of devices with available firmware upgrades. |
| sensor | `lan`                       | Health status of the gateway’s LAN subsystem.       |
| sensor | `wan`                       | Health status of the gateway’s WAN subsystem.       |
| sensor | `wlan`                      | Health status of the gateway’s WLAN subsystem.      |
| sensor | `www`                       | Health status of internet reachability.             |
| sensor | `speedtest_download`        | Most recent speed test download throughput (Mbps).  |
| sensor | `speedtest_upload`          | Most recent speed test upload throughput (Mbps).    |
| sensor | `speedtest_ping`            | Most recent speed test ping time (ms).              |
| sensor | `speedtest_last_duration`   | How long the last speed test took (ms).            |
| sensor | `speedtest_last_error`      | Error message from the last speed test, if any.    |
| sensor | `speedtest_last_run`        | Timestamp when the last speed test finished.        |
| sensor | `speedtest_last_run_ok`     | Whether the last speed test completed successfully. |
| button | `run_speedtest`             | Manually trigger a speed test on the gateway.       |
| button | `refresh_network_status`    | Request an immediate health status refresh.         |
| button | `reset_gateway`             | Issue a software reboot of the gateway.             |

These entities provide a concise overview of your network health.  For
example you can pin the `wan`, `lan`, `wlan` and `www` sensors to a card on
your dashboard to monitor connectivity status at a glance.  The speedtest
entities enable automations based on throughput or latency changes, and the
buttons let you run on‑demand diagnostics or reboot the gateway from within
Home Assistant.


## Integration guide (English)

### What this integration does for you

- Presents the health status of your UniFi Gateway’s WAN, LAN, WLAN and internet
  (WWW) subsystems so you can monitor uptime, latency and alerts directly from
  the Home Assistant dashboard.
- Tracks firmware status for UniFi devices and highlights upgrades directly in
  Home Assistant.
- Exposes built‑in speed test results (download, upload, ping, last run and
  duration) and provides a button to run a new speed test on demand.
- Provides buttons to refresh the gateway’s network status and to perform a
  soft reboot of the gateway.
- Offers live diagnostic data (controller URLs, current site, last fetched
  payloads) that can be shared with support teams when something stops working.

### How to get started

1. In Home Assistant navigate to **Settings → Devices & Services → Add
   Integration** and search for **UniFi Gateway Dashboard Analyzer**.
2. Enter the controller address, site and credentials (local UniFi OS username
   and password). The form validates everything before saving.
3. After the initial setup you can revisit the entry and use **Configure** to
   adjust connection details without deleting the integration.

### Daily use tips

- Pin the `wan`, `lan`, `wlan` and `www` sensors to a dashboard card to keep
  an eye on connectivity and alert status.
- Set up automations based on the speed test entities.  For example you can
  notify yourself if the download throughput drops below a threshold or if
  latency spikes.
- Use the **Run Speedtest** button to initiate a speed test from within
  Home Assistant whenever you notice slowdowns.
- Use the **Refresh Network Status** and **Reset Gateway** buttons from the
  entities list or dashboard to troubleshoot connectivity issues.
- Download **Diagnostics** from the integration's menu whenever you need a
  snapshot of controller data for troubleshooting.

### Cloud WAN IPv6

- Configure your UniFi **UI API Key** in the integration options to enable
  fetching WAN IPv6 data from the UniFi Cloud `v1/hosts` endpoint. The key is
  stored in the config entry options, so you can safely keep it in
  `secrets.yaml`.
- The **WAN Last IP (IPv6)** sensor now relies solely on the cloud payload. The
  sensor exposes the resolved gateway MAC address as the `gw_mac` attribute and
  reports the reason (`reason` attribute) whenever the IPv6 address is missing
  or the cloud request fails.
- IPv6 values retrieved from the cloud are cached and automatically propagated
  to the WAN link attributes so that other dashboards continue to show the most
  recent address.

## Przewodnik integracji (Polski)

### Co daje ta integracja

- Udostępnia w Home Assistant zagregowane wskaźniki zdrowia dla WAN, LAN, WLAN
  oraz połączenia z internetem (WWW) bramy UniFi, aby w prosty sposób
  monitorować dostępność łącza, opóźnienia i alarmy.
- Śledzi wersje oprogramowania urządzeń UniFi i wskazuje dostępne aktualizacje
  bezpośrednio w Home Assistant.
- Eksponuje wyniki wbudowanego testu prędkości (pobieranie, wysyłanie, ping,
  czas trwania i czas ostatniego uruchomienia) oraz udostępnia przycisk do
  ręcznego uruchomienia testu.
- Udostępnia przyciski do odświeżenia stanu sieci bramy oraz do jej miękkiego
  restartu.
- Umożliwia pobranie diagnostyki (adresy kontrolera, aktualna witryna, ostatnie
  dane) do przekazania zespołowi wsparcia.

### Jak zacząć

1. W Home Assistant przejdź do **Ustawienia → Urządzenia i usługi → Dodaj
   integrację** i wyszukaj **UniFi Gateway Dashboard Analyzer**.
2. Podaj adres kontrolera, witrynę oraz dane logowania (lokalny użytkownik i
   hasło UniFi OS). Formularz sprawdza poprawność przed zapisaniem.
3. Po instalacji możesz wybrać **Konfiguruj** przy wpisie integracji, aby w
   każdej chwili zmienić parametry połączenia.

### Wskazówki do codziennego użycia

- Dodaj sensory `wan`, `lan`, `wlan` i `www` na dashboard, aby mieć stale
  podgląd opóźnień i stanu alarmów.
- Konfiguruj automatyzacje w oparciu o sensory z testu prędkości – np.
  powiadomienie gdy prędkość pobierania spadnie poniżej ustalonego progu lub
  gdy ping wzrośnie.
- Używaj przycisku **Uruchom test prędkości** z poziomu Home Assistant,
  gdy zauważysz spowolnienia łącza.
- Skorzystaj z przycisków **Odśwież status sieci** i **Zrestartuj bramę**
  dostępnych w encjach, aby szybko rozwiązać problemy z łącznością.
- W menu integracji wybierz **Pobierz diagnostykę**, aby zebrać migawkę danych
  do rozwiązywania problemów.

### Chmura WAN IPv6

- W opcjach integracji podaj **UI API Key**, aby umożliwić pobieranie adresu
  IPv6 WAN z końcówki UniFi Cloud `v1/hosts`. Klucz zapisywany jest w opcjach
  wpisu konfiguracyjnego, dzięki czemu można go przechowywać w `secrets.yaml`.
- Sensor **WAN Last IP (IPv6)** bazuje wyłącznie na danych z chmury. W atrybucie
  `gw_mac` prezentowany jest MAC interfejsu WAN, a w `reason` znajdziesz powód
  braku adresu IPv6 lub błędu komunikacji z chmurą.
- Otrzymane adresy IPv6 są buforowane i synchronizowane z atrybutami łącza WAN,
  aby inne pulpity wciąż widziały ostatni znany adres.

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

