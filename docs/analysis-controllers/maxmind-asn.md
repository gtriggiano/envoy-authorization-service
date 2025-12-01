# MaxMind ASN

The `maxmind-asn` analysis controller performs IP-to-ASN lookups to identify the Autonomous System Number and organization.

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this controller.
:::

## Configuration

```yaml
analysisControllers:
  - name: asn
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb
```

## Upstream Headers Injected
- `X-ASN-Number` — Autonomous system number (e.g., `15169`)
- `X-ASN-Organization` — Organization name (e.g., `GOOGLE`)

## Caching & Errors
- In-memory cache avoids repeated lookups; cache hits are logged at debug level.
- If the IP is missing from the database or the database can’t be read, the controller logs a warning and returns a report with a `nil` lookup result (headers are omitted).

## Use Cases
- ASN-based authorization
- Tracking requests by network provider
- Security analysis and threat intelligence
- Providing network context to upstream services

## Requirements
- [MaxMind GeoLite2 ASN Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Weekly database updates recommended

## Pairing with Authorization
- Works with `asn-match` or `asn-match-database` to allow/deny by origin network.
- Example policy: `authorizationPolicy: "!asn-blocklist"` where `asn-blocklist` is a match controller fed by this analysis controller.
