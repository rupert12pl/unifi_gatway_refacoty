
# UniFi Gateway Dashboard Analyzer

Custom integration for Home Assistant that exposes UniFi Gateway metrics with a
fully UI-driven configuration flow.

## Integration guide (English)

### What this integration does for you

- Uses a fully asynchronous data coordinator to poll UniFi OS health and WLAN
  endpoints without blocking Home Assistant.
- Provides a complete Config Flow and Options Flow that let you adjust
  connection settings directly from the UI.
- Protects the controller with automatic retry logic, exponential backoff with
  jitter and a semaphore-based rate limiter so bursts never overload the UniFi
  Gateway.
- Surfaces WAN, VPN and client metrics as dedicated sensors and binary sensors
  with defensive parsing so malformed payloads do not break the integration.
- Generates anonymised diagnostics that can be safely shared with support.
- Detects legacy `unifigateway` installations and raises a Repair issue with
  instructions for migration.
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

- The integration applies a small semaphore-based rate limit to outbound API
  calls. When multiple refreshes are queued they are serialized automatically
  to protect the controller.
- Pin the WAN/LAN/WLAN sensors to a dashboard card to keep latency and alert
  status in view.
- Use the VPN server sensor state to trigger automations (for example notify
  when more than five remote workers are connected).
- Expand the **Connected Clients** attribute on a VPN sensor to see the device
  name, public IP origin and geolocation details for every active tunnel.
- Download **Diagnostics** from the integration's menu whenever you need a
  snapshot of controller data for troubleshooting.
- On UniFi Dream Machine models that obtain IPv6 connectivity via DHCPv6 Prefix
  Delegation, the WAN interface may not expose a global IPv6 address. The WAN
  IPv6 sensor therefore reports the delegated prefix so you still know which
  network is routable from the internet.

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

- Integracja wykorzystuje limitowanie żądań oparte na semaforze, dzięki czemu
  kontroler UniFi nie jest przeciążany nawet przy częstych odświeżeniach.
- Dodaj sensory WAN/LAN/WLAN na dashboard, aby mieć stale podgląd opóźnień i
  stanu alarmów.
- Wykorzystaj stan sensora serwera VPN w automatyzacjach (np. wyślij powiadomienie,
  gdy liczba zdalnych użytkowników przekroczy pięć).
- Rozwiń atrybut **Connected Clients** na sensorze VPN, aby zobaczyć nazwę
  urządzenia, adres publiczny oraz geolokalizację każdego tunelu.
- W menu integracji wybierz **Pobierz diagnostykę**, aby zebrać migawkę danych do
  rozwiązywania problemów.
- Na urządzeniach UniFi Dream Machine korzystających z DHCPv6 PD interfejs WAN
  może nie mieć publicznego adresu IPv6. Sensor WAN IPv6 wyświetla wówczas
  delegowany prefiks, aby łatwo sprawdzić sieć dostępną z internetu.

## Repository layout required by HACS

HACS expects the following files in a custom integration repository:

- `hacs.json` in the repository root.
- `README.md` (or `info.md`) in the repository root for documentation rendering.
- `custom_components/<domain>/manifest.json` inside the integration directory.

This repository already follows that layout with the integration stored in
`custom_components/unifi_gateway_refactory/`.

## Publishing releases for HACS

HACS requires release tags that follow the `MAJOR.MINOR.PATCH` semantic version
pattern. The workflow is:

1. Update `custom_components/unifi_gateway_refactory/manifest.json` with the new
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
    custom_components.unifi_gateway_refactory: debug
    custom_components.unifi_gateway_refactory.coordinator: debug
```

When debug logging is enabled the integration records each UniFi Network HTTP request
and, for non-2xx responses, includes a sanitized preview of the response body (first 1 kB)
to simplify troubleshooting endpoint discovery issues.

