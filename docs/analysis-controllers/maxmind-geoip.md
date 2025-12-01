# MaxMind GeoIP

The `maxmind-geoip` analysis controller performs IP-to-location lookups to identify geographic information.

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this controller.
:::

## Configuration

```yaml
analysisControllers:
  - name: geoip
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb
```

## Upstream Headers Injected
- `X-GeoIP-City` — City name
- `X-GeoIP-PostalCode` — Postal/ZIP code
- `X-GeoIP-Region` — State/province name
- `X-GeoIP-Country` — Country name
- `X-GeoIP-CountryISO` — ISO country code (e.g., `US`)
- `X-GeoIP-Continent` — Continent name
- `X-GeoIP-TimeZone` — IANA timezone
- `X-GeoIP-Latitude` — Decimal latitude
- `X-GeoIP-Longitude` — Decimal longitude

## Caching & Errors
- In-memory cache prevents repeated database hits; cache hits are logged at debug level.
- If the IP is not present in the database or a read error occurs, the controller logs a warning and returns a report with a `nil` lookup result (headers are omitted).

## Use Cases
- Geographic access restrictions
- Content localization
- Analytics and reporting
- Compliance requirements (e.g., GDPR, data residency)

## Requirements
- [MaxMind GeoLite2 City Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Weekly database updates recommended
