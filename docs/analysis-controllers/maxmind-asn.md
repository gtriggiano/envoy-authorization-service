# MaxMind ASN Lookup

The `maxmind-asn` analysis controller performs IP-to-ASN lookups to identify the Autonomous System Number and organization.

::: warning Note
You need [MaxMind databases](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) to run this controller.
:::

## Configuration

```yaml
analysisControllers:
  - name: asn-detect
    type: maxmind-asn
    settings:
      databasePath: config/GeoLite2-ASN.mmdb
```

## Upstream Headers Injected
- `X-ASN-Number` — Autonomous system number (e.g., `15169`)
- `X-ASN-Organization` — Organization name (e.g., `GOOGLE`)

## Use Cases
- ASN-based authorization
- Tracking requests by network provider
- Security analysis and threat intelligence
- Providing network context to upstream services

## Requirements
- [MaxMind GeoLite2 ASN Database](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)
- Weekly database updates recommended
