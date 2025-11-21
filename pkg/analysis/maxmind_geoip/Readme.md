# MaxMind GeoIP Analysis Controller `maxmind-geoip`

## Overview

The MaxMind GeoIP analysis controller enriches incoming requests with geographic location data by querying the MaxMind City database. 

This controller operates during the **analysis phase**, providing detailed geolocation metadata that can inform authorization decisions and/or be provided upstream.

## Purpose

This controller performs IP-to-location lookups to identify:
- City, region, and country information
- Postal codes and time zones
- Geographic coordinates (latitude/longitude)
- Continent names

This information enables:
- Geographic access control and geo-fencing
- Compliance with regional data regulations
- Location-based service customization
- Fraud detection and security monitoring
- Analytics and traffic analysis

## Configuration

| Setting | Type | Description |
|---|---|---|
| `databasePath` | string (required) | Absolute or relative path to the MaxMind City .mmdb database file |

### Example

```yaml
analysisControllers:
  - name: geoip-detect
    type: maxmind-geoip
    settings:
      databasePath: config/GeoLite2-City.mmdb
```

## Output

### HTTP Headers

The controller injects the following headers into upstream requests (if the request is ultimately proxied):

| Header | Description | Example |
|---|---|---|
| `X-GeoIP-City` | City name | `Mountain View` |
| `X-GeoIP-PostalCode` | Postal/ZIP code | `94043` |
| `X-GeoIP-Region` | State/province/region | `California` |
| `X-GeoIP-Country` | Full country name | `United States` |
| `X-GeoIP-CountryISO` | ISO 3166-1 alpha-2 country code | `US` |
| `X-GeoIP-Continent` | Continent name | `North America` |
| `X-GeoIP-TimeZone` | IANA time zone identifier | `America/Los_Angeles` |
| `X-GeoIP-Latitude` | Geographic latitude | `37.419200` |
| `X-GeoIP-Longitude` | Geographic longitude | `-122.057404` |

## Caching

The controller implements an in-memory cache to minimize database lookups.

Cache hits are logged at debug level for observability.

## Error Handling

- If the IP address cannot be found in the database, the controller logs a warning and returns a report with `nil` lookup result
- Database read errors are logged and result in a `nil` lookup result

## Dependencies

A **[MaxMind City Database](https://dev.maxmind.com/geoip/docs/databases/city-and-country/)**.

It's recommended to update it weekly.

## See Also

- [MaxMind ASN Analysis Controller](../maxmind_asn)
