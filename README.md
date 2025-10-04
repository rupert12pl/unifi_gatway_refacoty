
# UniFi Gateway Dashboard Analyzer

Custom integration for Home Assistant that exposes UniFi Gateway metrics with a
fully UI-driven configuration flow.

## Integration guide (English)

### What this integration does for you

- Presents WAN, LAN, WLAN and internet health metrics from your UniFi Gateway so
  you can monitor uptime, throughput and alerts from the Home Assistant
  dashboard.
- Tracks firmware status for UniFi devices and highlights upgrades directly in
  Home Assistant.
- Creates dedicated VPN server sensors that count active sessions and expose a
  **Connected Clients** attribute listing each user as
  `Name ~ Source IP | Internal IP | Source Country | Source City | Source ISP`.
  No other entity includes that attribute, so you immediately know which card
  to open when reviewing VPN activity.
- Provides live diagnostic data (controller URLs, current site, last fetched
  payloads) that can be shared with support teams when something stops working.

### How to get started

1. In Home Assistant navigate to **Settings → Devices & Services → Add
   Integration** and search for **UniFi Gateway Dashboard Analyzer**.
2. Enter the controller address, site and credentials (local UniFi OS username
   and password). The form validates everything before saving.
3. After the initial setup you can revisit the entry and use **Configure** to
   adjust connection details without deleting the integration.

### Daily use tips

- Pin the WAN/LAN/WLAN sensors to a dashboard card to keep latency and alert
  status in view.
- Use the VPN server sensor state to trigger automations (for example notify
  when more than five remote workers are connected).
- Expand the **Connected Clients** attribute on a VPN sensor to see the device
  name, public IP origin and geolocation details for every active tunnel.
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

- Udostępnia w Home Assistant wskaźniki WAN, LAN, WLAN i stanu internetu z
  bramy UniFi, aby łatwo kontrolować dostępność łącza, przepustowość i alarmy.
- Śledzi wersje oprogramowania urządzeń UniFi i wskazuje dostępne aktualizacje
  bezpośrednio w Home Assistant.
- Tworzy osobne sensory serwerów VPN zliczające aktywne sesje oraz dodające
  atrybut **Connected Clients** w formacie
  `Nazwa ~ IP źródłowe | IP wewnętrzne | Kraj | Miasto | ISP`. Żadna inna encja
  nie pokazuje tego atrybutu, więc przeglądanie aktywności VPN jest proste i
  szybkie.
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

- Dodaj sensory WAN/LAN/WLAN na dashboard, aby mieć stale podgląd opóźnień i
  stanu alarmów.
- Wykorzystaj stan sensora serwera VPN w automatyzacjach (np. wyślij powiadomienie,
  gdy liczba zdalnych użytkowników przekroczy pięć).
- Rozwiń atrybut **Connected Clients** na sensorze VPN, aby zobaczyć nazwę
  urządzenia, adres publiczny oraz geolokalizację każdego tunelu.
- W menu integracji wybierz **Pobierz diagnostykę**, aby zebrać migawkę danych do
  rozwiązywania problemów.

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

